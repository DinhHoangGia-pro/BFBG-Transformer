#!/usr/bin/env python
"""Cham v3 (holdout benign cuoi) MOT LAN theo docs/v3_eval_config.json.
AN TOAN:
  - Mac dinh KHONG lam gi. `--selftest` test plumbing (du lieu gia). `--subtest` chay TOAN duong tren
    test_indist (tap thay the, KHONG cham v3, KHONG lock). `--run` moi cham THAT v3 (co lock chay-mot-lan).
  - File khoa ~/bfbg_benign_work/eval_v3.lock chua CONFIG_HASH: da ton tai -> TU CHOI chay lan hai.
  - Kiem CONFIG_HASH khop sha256(docs/v3_eval_config.json) truoc khi chay.
  - TU TRICH dac trung (meta/graph/token) tu raw PE + feature JSON (KHONG phu thuoc cache v1/v2) nen dung cho v3.
QUY TAC: loi giua chung khi cham v3 -> DUNG, bao nguoi dung, KHONG sua roi chay lai (main xu ly).
"""
import os, sys, json, hashlib, argparse, warnings, math
warnings.filterwarnings("ignore")
REPO = "/home/dhgia/Work/Defi/BFBG-Transformer"
CONFIG = os.path.join(REPO, "docs", "v3_eval_config.json")
CONFIG_HASH = "55ace0a9cafa08489446ca818b45a9701d3ffa703dfe1957ec00815028d3a58e"  # ban 2 (165 benign; loai 06d84a2e)
LOCK = os.path.expanduser("~/bfbg_benign_work/eval_v3.lock")
BINS = ["MSVC<=10", "MSVC 11-12", "MSVC 14", "GNU/MinGW", "Go", "Delphi", "khac"]
IMPV3 = os.path.expanduser("~/bfbg_benign_work/import_v3")
V3FEAT = os.path.expanduser("~/bfbg_benign_work/v3_features")
FEAT_STD = os.path.join(REPO, "data/features_graph")

# ---------- metric helpers (selftest kiem) ----------
def wilson_ci(k, n, z=1.96):
    if n == 0: return (float("nan"), float("nan"))
    p = k/n; d = 1 + z*z/n
    c = (p + z*z/(2*n))/d; half = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n))/d
    return (max(0, c-half), min(1, c+half))
def tpr95_threshold(pos_scores):
    import numpy as np
    return float(np.percentile(np.asarray(pos_scores, float), 5))
def fpr_at(neg_scores, thr):
    import numpy as np
    neg = np.asarray(neg_scores, float); return float((neg >= thr).mean()) if len(neg) else float("nan")
def fpr_by_bin(neg_scores, neg_bins, thr):
    import numpy as np
    out = {}; neg = np.asarray(neg_scores, float); nb = np.asarray(neg_bins, object)
    for b in BINS:
        m = nb == b; n = int(m.sum())
        if n == 0: continue
        k = int((neg[m] >= thr).sum()); lo, hi = wilson_ci(k, n); out[b] = {"n": n, "fpr": k/n, "wilson": [lo, hi]}
    return out
def auc_score(y, s):
    from sklearn.metrics import roc_auc_score
    return float(roc_auc_score(y, s)) if len(set(y)) > 1 else float("nan")
def cluster_bootstrap_auc(y, s, cl, n=2000, seed=20261008):
    import numpy as np
    from sklearn.metrics import roc_auc_score
    y = np.asarray(y); s = np.asarray(s, float); cl = np.asarray(cl, object)
    uc = np.unique(cl); rng = np.random.RandomState(seed); idx = {c: np.where(cl == c)[0] for c in uc}; v = []
    for _ in range(n):
        ii = np.concatenate([idx[c] for c in rng.choice(uc, len(uc), replace=True)])
        if len(set(y[ii])) > 1: v.append(roc_auc_score(y[ii], s[ii]))
    v = np.array(v)
    return (float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))) if len(v) else (float("nan"), float("nan"))

def verify_config():
    h = hashlib.sha256(open(CONFIG, "rb").read()).hexdigest()
    if h != CONFIG_HASH: raise SystemExit(f"CONFIG_HASH khong khop! file={h} expect={CONFIG_HASH}")
    return json.load(open(CONFIG))
def check_lock():
    if os.path.exists(LOCK):
        raise SystemExit(f"DA CHAM v3 (lock {LOCK}): {open(LOCK).read().strip()}\n-> TU CHOI chay lan hai.")
    if os.path.exists(os.path.expanduser("~/bfbg_benign_work/eval_v3.FAILED")):
        raise SystemExit("Co eval_v3.FAILED (lan truoc loi). Xu ly loi + xoa file do + co lenh 'chay' moi thu lai.")
def write_lock(result_hash):
    import datetime
    with open(LOCK, "w") as f:
        f.write(json.dumps({"config_hash": CONFIG_HASH, "result_hash": result_hash, "at": datetime.datetime.now().isoformat()}) + "\n")

# ---------- TU TRICH dac trung (khong phu thuoc cache) ----------
import pefile, datetime as _dt
SECDIR = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
STD = {'.text','.data','.rdata','.rsrc','.reloc','.bss','.idata','.edata','.pdata','.tls','.gfids','.didat','.crt','.xdata','.rodata'}
def raw_path(sha, label, is_v3):
    if is_v3: return os.path.join(IMPV3, sha)
    return os.path.join(REPO, "data/raw", "malicious" if label == 1 else "benign", sha)
def feat_path(sha, is_v3):
    return os.path.join(V3FEAT if is_v3 else FEAT_STD, f"{sha}_static.json")
def extract(sha, label, is_v3, MF=150, MAXTOK=512):
    rp = raw_path(sha, label, is_v3); jp = feat_path(sha, is_v3)
    if not (os.path.exists(rp) and os.path.exists(jp)): return None
    from collections import Counter
    pe = pefile.PE(rp)
    try:
        oh, fh = pe.OPTIONAL_HEADER, pe.FILE_HEADER; dd = oh.DATA_DIRECTORY
        has_sig = 1 if (SECDIR < len(dd) and dd[SECDIR].Size > 0) else 0
        linker = oh.MajorLinkerVersion + oh.MinorLinkerVersion/100.0
        ts = fh.TimeDateStamp; year = 0
        if 0 < ts < 2**31:
            try: year = _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).year
            except Exception: year = 0
        has_rich = 1 if getattr(pe, 'RICH_HEADER', None) else 0
        secs = [s.Name.rstrip(b'\x00').decode('latin1','ignore') for s in pe.sections]
        nsec = len(secs); nonstd = sum(1 for s in secs if s.lower() not in STD)
        try: max_ent = max((s.get_entropy() for s in pe.sections), default=0.0)
        except Exception: max_ent = 0.0
        lk = int(linker); imps = set()
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for e in pe.DIRECTORY_ENTRY_IMPORT:
                if e.dll: imps.add(e.dll.decode('latin1','ignore').lower())
        fsize = os.path.getsize(rp)
    finally: pe.close()
    sset = set(secs); si = " ".join(imps)
    if '.buildid' in sset or '.symtab' in sset: tb = "Go"
    elif 'CODE' in sset or 'DATA' in sset or '.itext' in sset: tb = "Delphi"
    elif '.eh_fram' in sset or any(d in si for d in ('libgcc','mingw','msys-')): tb = "GNU/MinGW"
    elif has_rich or any(d in si for d in ('ucrtbase','vcruntime','api-ms-win-crt')) or ('msvcrt.dll' in imps and lk>=6):
        tb = "MSVC<=10" if lk<=10 else ("MSVC 11-12" if lk in (11,12) else "MSVC 14")
    else: tb = "khac"
    d = json.load(open(jp)); si2 = d.get('structural_indicators', {})
    ipg = d.get('intra_procedural_graphs', {})
    tn = sum(len(g.get('nodes', [])) for g in ipg.values())
    meta = [has_sig, linker, year, has_rich, nsec, nonstd, max_ent, math.log10(max(fsize,1))]
    graph = [d.get('num_functions',0), d.get('num_api_calls',0), d.get('num_imports',0), fsize,
             si2.get('max_section_entropy',0.0), 1 if si2.get('is_likely_packed') else 0, tn]
    tokc = Counter()
    for fi, g in enumerate(list(ipg.values())[:MF]):
        for n in g.get('nodes', [])[:MAXTOK]:
            t = n.get('token')
            if t: tokc[t] += 1
    return {"meta": meta, "graph": graph, "tokc": dict(tokc), "tbin": tb}

def selftest():
    import numpy as np, tempfile
    print("[selftest] kiem metric + lock tren du lieu gia (KHONG cham v3)...")
    rng = np.random.RandomState(0)
    pos = rng.normal(0.8, 0.1, 200).clip(0, 1); thr = tpr95_threshold(pos)
    neg = rng.normal(0.3, 0.2, 166).clip(0, 1); negbins = rng.choice(BINS, 166)
    fpr = fpr_at(neg, thr); bb = fpr_by_bin(neg, negbins, thr); assert 0 <= fpr <= 1
    y = np.r_[np.ones(262), np.zeros(166)]; s = np.r_[rng.normal(0.7,0.2,262), rng.normal(0.4,0.2,166)].clip(0,1)
    cl = np.r_[np.arange(262), np.arange(166)+1000]; a = auc_score(y, s); lo, hi = cluster_bootstrap_auc(y, s, cl, n=200)
    assert 0 <= a <= 1 and lo <= hi; wlo, whi = wilson_ci(3, 20); assert 0 <= wlo <= whi <= 1
    global LOCK; real = LOCK; LOCK = os.path.join(tempfile.mkdtemp(), "eval_v3.lock")
    try:
        check_lock(); write_lock("dummy")
        try: check_lock(); raise AssertionError("lock phai chan lan hai")
        except SystemExit: pass
        print(f"[selftest] thr={thr:.3f} fpr={fpr:.3f} bins={len(bb)} auc={a:.3f} ci[{lo:.3f},{hi:.3f}] lock=OK")
    finally: LOCK = real
    print("[selftest] PASS (plumbing OK, chua cham v3).")

def _iso_capped_trainpool(man, by_split, group_key, random):
    """v2 train_pool, ISO cap 113 (seed 20261008), roi carve §17 cluster-validation 15% (seed 20261008)."""
    from collections import defaultdict
    tp = by_split(man)["train_pool"]
    iso = [r for r in tp if r.get("source") == "windows11-eval-iso"]
    rnd = random.Random(20261008); rnd.shuffle(iso); keep = set(r["sha256"] for r in iso[:113])
    tp = [r for r in tp if r.get("source") != "windows11-eval-iso" or r["sha256"] in keep]
    groups = defaultdict(list)
    for r in tp: groups[group_key(r)].append(r)
    gl = list(groups.items()); random.Random(20261008).shuffle(gl)
    val = []; nval = 0; target = int(0.15 * len(tp))
    for g, recs in gl:
        if nval < target: val += recs; nval += len(recs)
    valset = set(r["sha256"] for r in val)
    train = [r for r in tp if r["sha256"] not in valset]
    return train, val

def run_real(neg_set="v3"):
    import numpy as np
    cfg = verify_config()
    if neg_set == "v3":
        check_lock(); write_lock("STARTED")   # tao lock NGAY khi bat dau (chan chay lan hai/crash giua chung)
    sys.path.insert(0, REPO); os.chdir(REPO)
    import torch, random
    from src.training.splits import by_split, group_key, group_kfold
    from src.training.bfbg_dataset import BFBGDataset, collate
    from src.models.bfbg_transformer import BFBGTransformer
    from torch.utils.data import DataLoader
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    man2 = [json.loads(l) for l in open(os.path.join(REPO, "docs/dataset_v2_manifest.jsonl"))]
    by2 = {r["sha256"]: r for r in man2}
    train, val = _iso_capped_trainpool(man2, by_split, group_key, random)
    bb = by_split(man2)["holdout_family_bumblebee"]
    if neg_set == "v3":
        negs = [json.loads(l) for l in open(os.path.join(REPO, "docs/dataset_v3_manifest.jsonl"))]; NEG_V3 = True
    elif neg_set == "test_indist":
        negs = [r for r in man2 if r["split"] == "test_indist" and r["label"] == 0]; NEG_V3 = False
    else: raise SystemExit("neg_set khong hop le")
    print(f"[{neg_set}] train={len(train)} val={len(val)} bb={len(bb)} negs={len(negs)}", flush=True)
    # ---- trich dac trung (tu raw+json) ----
    def is_v3(r): return NEG_V3 and (r in negs)
    FEAT = {}  # sha -> extracted
    def ext(r, v3):
        sha = r["sha256"]
        if sha not in FEAT: FEAT[sha] = extract(sha, r.get("label", 0), v3)
        return FEAT[sha]
    for r in train: ext(r, False)
    for r in val: ext(r, False)
    for r in bb: ext(r, False)
    for r in negs: ext(r, NEG_V3)
    def present(recs, v3): return [r for r in recs if ext(r, v3) is not None]
    train_p = present(train, False); bb_p = present(bb, False); negs_p = present(negs, NEG_V3)
    ytr = np.array([r["label"] for r in train_p])
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    stoi = json.load(open(os.path.join(REPO, "data/insn_vocab_v2.json")))
    if isinstance(stoi, list): stoi = {t: i for i, t in enumerate(stoi)}
    def elements(c):
        o = []
        for k, v in c.items(): o.extend([k]*v)
        return o
    def Xmat(recs, which, vec=None):
        if which in ("meta", "graph"): return np.array([FEAT[r["sha256"]][which] for r in recs], float)
        return vec.transform([FEAT[r["sha256"]]["tokc"] for r in recs])
    results = {"neg_set": neg_set, "config_hash": CONFIG_HASH, "models": {}, "per_sample": {},
               "samples": {}}
    for r in negs_p: results["samples"][r["sha256"]] = {"set": "neg", "label": 0, "bin": (r["tbin"] if NEG_V3 else FEAT[r["sha256"]]["tbin"])}
    for r in bb_p: results["samples"][r["sha256"]] = {"set": "pos_bumblebee", "label": 1, "bin": FEAT[r["sha256"]]["tbin"]}
    # ---------- PROBES ----------
    for which in ("meta", "graph", "bag_of_tokens"):
        vec = None
        if which == "bag_of_tokens":
            vec = TfidfVectorizer(analyzer=lambda c: elements(c), min_df=3).fit([FEAT[r["sha256"]]["tokc"] for r in train_p])
        Xtr = Xmat(train_p, which, vec)
        # OOF threshold (group-kfold k=5, TPR95 tren OOF positives)
        folds = group_kfold(train_p, k=5); oof = np.full(len(train_p), np.nan)
        for fv in folds:
            tri = [i for i, r in enumerate(train_p) if r["sha256"] not in fv]; vai = [i for i, r in enumerate(train_p) if r["sha256"] in fv]
            if not vai or len(set(ytr[tri])) < 2: continue
            clf = RandomForestClassifier(300, random_state=42, n_jobs=-1, class_weight="balanced").fit(Xtr[tri], ytr[tri])
            oof[vai] = clf.predict_proba(Xtr[vai])[:, 1]
        thr = tpr95_threshold(oof[(ytr == 1) & np.isfinite(oof)])
        clf = RandomForestClassifier(300, random_state=42, n_jobs=-1, class_weight="balanced").fit(Xtr, ytr)
        sn = clf.predict_proba(Xmat(negs_p, which, vec))[:, 1]; sp = clf.predict_proba(Xmat(bb_p, which, vec))[:, 1]
        nb = [(r["tbin"] if NEG_V3 else FEAT[r["sha256"]]["tbin"]) for r in negs_p]
        y = np.r_[np.ones(len(bb_p)), np.zeros(len(negs_p))]; s = np.r_[sp, sn]
        cl = np.array([group_key(r) for r in bb_p] + [r["sha256"] for r in negs_p])
        k = int((sn >= thr).sum()); wl, wh = wilson_ci(k, len(sn)); lo, hi = cluster_bootstrap_auc(y, s, cl)
        results["models"][which] = {"thr": thr, "fpr": fpr_at(sn, thr), "fpr_wilson": [wl, wh],
                                    "fpr_by_bin": fpr_by_bin(sn, nb, thr), "auc": auc_score(y, s), "auc_ci": [lo, hi],
                                    "n_neg": len(sn), "n_pos": len(sp)}
        results["per_sample"][which] = {**{negs_p[i]["sha256"]: float(sn[i]) for i in range(len(negs_p))},
                                        **{bb_p[i]["sha256"]: float(sp[i]) for i in range(len(bb_p))}}
        print(f"  [{which}] thr={thr:.3f} FPR={results['models'][which]['fpr']:.3f} AUC={results['models'][which]['auc']:.3f} [{lo:.3f},{hi:.3f}]", flush=True)
    # ---------- BFBG ensembles ----------
    @torch.no_grad()
    def bfbg(ckpts, recs, feat_dir, select):
        acc = {}
        for cp in ckpts:
            m = BFBGTransformer.from_config(len(stoi), num_global_features=0).to(dev)
            m.load_state_dict(torch.load(os.path.expanduser("~/bfbg_benign_work/"+cp), map_location=dev)); m.eval()
            dl = DataLoader(BFBGDataset(recs, stoi, max_funcs=150, feat_dir=feat_dir, select=select), batch_size=1, shuffle=False, num_workers=0, collate_fn=collate)
            i = 0
            for batch in dl:
                sha = recs[i]["sha256"]
                if batch is None: acc.setdefault(sha, []).append(np.nan); i += 1; continue
                try: p = float(torch.softmax(m(batch, train_sem_predictor=False)[0], 1)[0, 1])
                except Exception:
                    if dev == "cuda": torch.cuda.empty_cache()
                    p = np.nan
                acc.setdefault(sha, []).append(p); i += 1
            del m
            if dev == "cuda": torch.cuda.empty_cache()
        return {s: float(np.nanmean(v)) for s, v in acc.items()}
    NEGFEAT = V3FEAT if NEG_V3 else FEAT_STD
    for name, ckpts, select in [("bfbg_first150", ["ckpt_v2es101.pt","ckpt_v2es202.pt","ckpt_v2es303.pt","ckpt_v2es404.pt"], "first"),
                                 ("bfbg_apidensity", ["ckpt_v2api101.pt","ckpt_v2api202.pt","ckpt_v2api303.pt","ckpt_v2api404.pt"], "apidensity")]:
        sval = bfbg(ckpts, val, FEAT_STD, select); vy = {r["sha256"]: r["label"] for r in val}
        valpos = [sval[s] for s in sval if vy.get(s) == 1 and sval[s] == sval[s]]
        thr = tpr95_threshold(valpos)
        sn = bfbg(ckpts, negs_p, NEGFEAT, select); sp = bfbg(ckpts, bb_p, FEAT_STD, select)
        snv = np.array([sn[r["sha256"]] for r in negs_p if sn.get(r["sha256"]) == sn.get(r["sha256"])])
        nbv = [(r["tbin"] if NEG_V3 else FEAT[r["sha256"]]["tbin"]) for r in negs_p if sn.get(r["sha256"]) == sn.get(r["sha256"])]
        spv = np.array([sp[r["sha256"]] for r in bb_p if sp.get(r["sha256"]) == sp.get(r["sha256"])])
        y = np.r_[np.ones(len(spv)), np.zeros(len(snv))]; s = np.r_[spv, snv]
        cl = np.array([group_key(by2[r["sha256"]]) for r in bb_p if sp.get(r["sha256"]) == sp.get(r["sha256"])] + [f"n{i}" for i in range(len(snv))])
        k = int((snv >= thr).sum()); wl, wh = wilson_ci(k, len(snv)); lo, hi = cluster_bootstrap_auc(y, s, cl)
        results["models"][name] = {"thr": thr, "fpr": fpr_at(snv, thr), "fpr_wilson": [wl, wh],
                                   "fpr_by_bin": fpr_by_bin(snv, nbv, thr), "auc": auc_score(y, s), "auc_ci": [lo, hi],
                                   "n_neg": int(len(snv)), "n_pos": int(len(spv))}
        results["per_sample"][name] = {**{k: (None if v != v else float(v)) for k, v in sn.items()},
                                       **{k: (None if v != v else float(v)) for k, v in sp.items()}}
        print(f"  [{name}] thr={thr:.3f} FPR={results['models'][name]['fpr']:.3f} AUC={results['models'][name]['auc']:.3f} [{lo:.3f},{hi:.3f}]", flush=True)
    out = os.path.expanduser(f"~/bfbg_benign_work/eval_{neg_set}_result.json")
    json.dump(results, open(out, "w"), indent=2)
    rh = hashlib.sha256(open(out, "rb").read()).hexdigest()
    print(f"RESULT {out} sha256={rh}", flush=True)
    if neg_set == "v3": write_lock(rh); print(f"[LOCK] da ghi {LOCK}", flush=True)
    return results

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--subtest", action="store_true", help="chay TOAN duong tren test_indist (KHONG cham v3/lock)")
    ap.add_argument("--run", action="store_true", help="CHAM THAT v3 (chi khi nguoi dung noi 'chay')")
    A = ap.parse_args()
    if A.selftest: selftest(); return
    if A.subtest: run_real("test_indist"); return
    if A.run:
        try: run_real("v3")
        except SystemExit: raise
        except Exception as e:
            import traceback
            fp = os.path.expanduser("~/bfbg_benign_work/eval_v3.FAILED")
            open(fp, "w").write(f"{_dt.datetime.now().isoformat()}\n{type(e).__name__}: {e}\n{traceback.format_exc()}\n")
            print(f"[LOI GIUA CHUNG] {type(e).__name__}: {e}\n-> DUNG. Ghi {fp}. KHONG tu sua/chay lai; BAO nguoi dung.", flush=True)
            sys.exit(2)
        return
    print("eval_v3.py: KHONG lam gi mac dinh. --selftest (gia) | --subtest (test_indist) | --run (cham that, chi khi 'chay').")
    print(f"  CONFIG_HASH={CONFIG_HASH}  lock={LOCK} (ton tai={os.path.exists(LOCK)})")

if __name__ == "__main__":
    main()
