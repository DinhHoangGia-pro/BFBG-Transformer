#!/usr/bin/env python
# CPU-only (no BFBG training). #1 within-MSVC14 + LOFO-5-family, #2 call/API-only tokens,
# #3 seed-evidence after 150-func / 512-token cut, #4 size-overlap probe.
import json, os, warnings, pickle, numpy as np
warnings.filterwarnings("ignore")
os.chdir("/home/dhgia/Work/Defi/BFBG-Transformer")
from collections import Counter, defaultdict
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import roc_auc_score
from src.training.splits import by_split, group_key

MF, MAXTOK = 150, 512
man = [json.loads(l) for l in open("docs/dataset_v2_manifest.jsonl")]
sp = by_split(man)
by_sha = {r["sha256"]: r for r in man}
fc = {json.loads(l)["sha256"]: json.loads(l) for l in open(os.path.expanduser("~/bfbg_benign_work/feat_cache.jsonl"))}
tp = sp["train_pool"]; bb = sp["holdout_family_bumblebee"]; ch = sp["holdout_source_chocolatey"]
FEAT = "data/features_graph"
FAMS = ["TrickBot", "Dridex", "IcedID", "Emotet", "BumbleBee"]
def auc(s, y): return roc_auc_score(y, s) if len(set(y)) > 1 else float("nan")
def cboot(sc, y, cl, n=1000):
    cl = np.asarray(cl); uc = np.unique(cl); rng = np.random.RandomState(20261008); idx = {c: np.where(cl == c)[0] for c in uc}; v = []
    for _ in range(n):
        ii = np.concatenate([idx[c] for c in rng.choice(uc, len(uc), replace=True)])
        try:
            if len(set(y[ii])) > 1: v.append(roc_auc_score(y[ii], sc[ii]))
        except Exception: pass
    v = np.array(v); return (float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))) if len(v) else (float("nan"), float("nan"))

# ---- read JSONs once (union: all malicious + train benign + choco), cache ----
need = {}
for r in man:
    if r["label"] == 1 or r in tp or r in ch: need[r["sha256"]] = r
for r in tp + ch: need[r["sha256"]] = r
CACHE = os.path.expanduser("~/bfbg_benign_work/bin_parse.pkl")
if os.path.exists(CACHE):
    P = pickle.load(open(CACHE, "rb")); print(f"loaded parse cache n={len(P)}", flush=True)
else:
    P = {}
    for i, (sha, r) in enumerate(need.items()):
        fp = os.path.join(FEAT, f"{sha}_static.json")
        if not os.path.exists(fp): continue
        d = json.load(open(fp)); ipg = list(d.get("intra_procedural_graphs", {}).values())
        tokc = Counter(); caic = Counter(); apic = Counter()  # compact: counters, capped to MODEL view
        sd_tot = 0; sd_drop_func = 0; sd_drop_tok = 0
        for fi, g in enumerate(ipg):
            nodes = g.get("nodes", [])
            if fi < MF:                       # tokens only from first MF funcs, <=MAXTOK nodes (model view)
                for n in nodes[:MAXTOK]:
                    t = n.get("token"); a = n.get("api"); mn = (n.get("mnemonic") or "")
                    if t: tokc[t] += 1
                    if a: apic[a] += 1
                    if mn == "call" or a: caic[a or t or "call"] += 1
            for se in (g.get("seed_edges") or []):   # seed stats over ALL funcs/positions (for #3)
                sd_tot += 1
                if fi >= MF: sd_drop_func += 1
                else:
                    si, di = se.get("src_idx", 0), se.get("dst_idx", 0)
                    if (si is not None and si >= MAXTOK) or (di is not None and di >= MAXTOK): sd_drop_tok += 1
        P[sha] = dict(tokc=dict(tokc), caic=dict(caic), apic=dict(apic), nf=len(ipg),
                      sd_tot=sd_tot, sd_drop_func=sd_drop_func, sd_drop_tok=sd_drop_tok)
        if (i + 1) % 400 == 0: print(f"  ...parsed {i+1}/{len(need)}", flush=True)
    pickle.dump(P, open(CACHE, "wb")); print(f"parsed+cached n={len(P)}", flush=True)

def _elements(cnt):   # multiset -> token list (transient, one sample at a time)
    out = []
    for k, v in cnt.items(): out.extend([k] * v)
    return out

def tbin(sha): return fc.get(sha, {}).get("tbin")
def g7(sha): return fc[sha]["graph"]
def meta8(sha): return fc[sha]["meta"]
_agg = Counter()
for s in P:
    _agg.update(P[s]["apic"])
topapi_global = [a for a, _ in _agg.most_common(50)]
def apivec(sha): h = P.get(sha, {}).get("apic", {}); return [h.get(a, 0) for a in topapi_global]

# feature builders returning (fit_on_train_fn). We train per experiment.
def build_RF_scores(train_recs, test_recs, mode):
    needP = mode in ("tokens", "callapi")
    tr = [r for r in train_recs if r["sha256"] in fc and (not needP or r["sha256"] in P)]
    ytr = np.array([r["label"] for r in tr])
    te = [r for r in test_recs if r["sha256"] in fc and (not needP or r["sha256"] in P)]
    if mode in ("tokens", "callapi"):
        key = "tokc" if mode == "tokens" else "caic"
        vec = TfidfVectorizer(analyzer=lambda c: _elements(c), min_df=(3 if mode == "tokens" else 2))
        Xtr = vec.fit_transform([P[r["sha256"]][key] for r in tr])
        clf = RandomForestClassifier(300, random_state=42, n_jobs=-1, class_weight="balanced").fit(Xtr, ytr)
        Xte = vec.transform([P[r["sha256"]][key] for r in te]); s = clf.predict_proba(Xte)[:, 1]
    else:
        fb = {"meta": meta8, "graph": g7, "gapi": lambda sha: g7(sha) + apivec(sha)}[mode]
        Xtr = np.array([fb(r["sha256"]) for r in tr], float)
        clf = RandomForestClassifier(300, random_state=42, n_jobs=-1, class_weight="balanced").fit(Xtr, ytr)
        Xte = np.array([fb(r["sha256"]) for r in te], float); s = clf.predict_proba(Xte)[:, 1]
    yte = np.array([r["label"] for r in te]); cl = [group_key(r) for r in te]
    return s, yte, cl, te

# BFBG 4-seed mean scores on bb+choco (existing; trained cross-bin)
bfbg = defaultdict(list)
for t in ("v2es101","v2es202","v2es303","v2es404"):
    for p in json.load(open(os.path.expanduser(f"~/bfbg_benign_work/foldrun_{t}.json")))["per_sample"]:
        if p["score"] is not None: bfbg[p["sha"]].append(p["score"])
bfbg = {k: np.mean(v) for k, v in bfbg.items()}

MODELS = ["meta","graph","gapi","tokens"]
NAME = {"meta":"metadata","graph":"graph","gapi":"graph+API","tokens":"bag-of-tokens"}

print("="*70); print("#1a WITHIN-MSVC14 (train trong bin; eval MSVC14 mal vs MSVC14 choco)"); print("="*70)
tr14 = [r for r in tp if tbin(r["sha256"]) == "MSVC 14"]
pos14 = [r for r in bb if tbin(r["sha256"]) == "MSVC 14"]
neg14 = [r for r in ch if tbin(r["sha256"]) == "MSVC 14"]
test14 = pos14 + neg14
print(f"  train MSVC14 n={len(tr14)} (ben={sum(1 for r in tr14 if r['label']==0)}); eval mal={len(pos14)} choco={len(neg14)}")
for m in MODELS:
    s, y, cl, te = build_RF_scores(tr14, test14, m)
    lo, hi = cboot(s, y, cl); print(f"  {NAME[m]:14s} AUC={auc(s,y):.3f} [{lo:.3f},{hi:.3f}]")
# BFBG existing scores subset to MSVC14 eval (trained cross-bin)
bs = np.array([bfbg[r["sha256"]] for r in test14 if r["sha256"] in bfbg]); by = np.array([r["label"] for r in test14 if r["sha256"] in bfbg]); bcl = [group_key(r) for r in test14 if r["sha256"] in bfbg]
lo, hi = cboot(bs, by, bcl); print(f"  BFBG(4seed, train TOÀN bin) AUC={auc(bs,by):.3f} [{lo:.3f},{hi:.3f}]  (eval-subset MSVC14, không train-in-bin)")

print("="*70); print("#1b LOFO 5-family (test = family-held-out mal vs choco; train = 4 family khác + benign train)"); print("="*70)
allmal = [r for r in man if r["label"] == 1 and r.get("source") in FAMS]
benign_tr = [r for r in tp if r["label"] == 0]
res = {m: [] for m in MODELS}
for F in FAMS:
    tr = [r for r in allmal if r.get("source") != F] + benign_tr
    test = [r for r in allmal if r.get("source") == F] + ch
    line = f"  {F:10s} (mal={sum(1 for r in test if r['label']==1)} vs choco={sum(1 for r in test if r['label']==0)}): "
    for m in MODELS:
        s, y, cl, te = build_RF_scores(tr, test, m); a = auc(s, y); res[m].append(a); line += f"{NAME[m]}={a:.3f} "
    print(line, flush=True)
print("  --- LOFO mean±std ---")
for m in MODELS:
    a = np.array(res[m]); print(f"  {NAME[m]:14s} mean={a.mean():.3f} ± {a.std(ddof=1):.3f}")

print("="*70); print("#2 bag-of-tokens CHỈ call/API (bỏ idiom compiler) — eval bb vs choco"); print("="*70)
evic = [r for r in bb + ch if by_sha[r["sha256"]].get("num_functions",0) and r["sha256"] in P]
for m in ("tokens","callapi"):
    s, y, cl, te = build_RF_scores(tp, bb + ch, m); lo, hi = cboot(s, y, cl)
    print(f"  {('tokens(full)' if m=='tokens' else 'call/API-only'):16s} AUC={auc(s,y):.3f} [{lo:.3f},{hi:.3f}]")

print("="*70); print("#3 seed-evidence sau điểm cắt (150 hàm / 512 token), theo nhãn & family"); print("="*70)
def sd_stats(recs):
    tot = sum(P[r["sha256"]]["sd_tot"] for r in recs if r["sha256"] in P)
    df = sum(P[r["sha256"]]["sd_drop_func"] for r in recs if r["sha256"] in P)
    dt = sum(P[r["sha256"]]["sd_drop_tok"] for r in recs if r["sha256"] in P)
    return tot, df, dt
for lab, recs in [("benign(train+choco)", [r for r in tp+ch if r["label"]==0]), ("malicious(all)", [r for r in man if r["label"]==1])]:
    tot, df, dt = sd_stats([r for r in recs if r["sha256"] in P])
    print(f"  {lab:22s} seed_tot={tot} drop_by_funcs>150={df}({100*df/max(tot,1):.1f}%) drop_by_tok>512={dt}({100*dt/max(tot,1):.1f}%)")
for F in FAMS:
    recs = [r for r in man if r.get("source")==F and r["sha256"] in P]
    tot, df, dt = sd_stats(recs); print(f"  family {F:10s} seed_tot={tot} drop_func>150={100*df/max(tot,1):.1f}% drop_tok>512={100*dt/max(tot,1):.1f}%")

print("="*70); print("#4 probe kích thước: AUC trong khoảng chồng lấn num_functions (bb vs choco)"); print("="*70)
nf_pos = np.array([by_sha[r["sha256"]]["num_functions"] for r in bb if by_sha[r["sha256"]]["num_functions"]])
nf_neg = np.array([by_sha[r["sha256"]]["num_functions"] for r in ch if by_sha[r["sha256"]]["num_functions"]])
lo_ov, hi_ov = max(nf_pos.min(), nf_neg.min()), min(nf_pos.max(), nf_neg.max())
print(f"  num_functions: mal[{nf_pos.min()}-{nf_pos.max()}] choco[{nf_neg.min()}-{nf_neg.max()}] -> overlap [{lo_ov},{hi_ov}]")
ov = [r for r in bb+ch if lo_ov <= by_sha[r["sha256"]].get("num_functions",0) <= hi_ov and r["sha256"] in fc]
yov = np.array([r["label"] for r in ov]); print(f"  overlap n={len(ov)} (mal={int((yov==1).sum())} choco={int((yov==0).sum())})")
if len(set(yov)) > 1:
    nfov = np.array([by_sha[r["sha256"]]["num_functions"] for r in ov], float)
    print(f"  AUC(num_functions alone, overlap) = {auc(nfov, yov):.3f} (oriented {max(auc(nfov,yov),1-auc(nfov,yov)):.3f})")
    for m in MODELS:
        s, y, cl, te = build_RF_scores(tp, ov, m); lo, hi = cboot(s, y, cl); print(f"  {NAME[m]:14s} AUC={auc(s,y):.3f} [{lo:.3f},{hi:.3f}]")
    bs = np.array([bfbg[r["sha256"]] for r in ov if r["sha256"] in bfbg]); byy = np.array([r["label"] for r in ov if r["sha256"] in bfbg])
    print(f"  BFBG(4seed) AUC={auc(bs,byy):.3f}")
print("DONE bin experiments")
