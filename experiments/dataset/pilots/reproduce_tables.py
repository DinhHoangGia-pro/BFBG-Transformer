#!/usr/bin/env python
"""Tai lap TOAN BO bang bang chung tu manifest + cache (KHONG doc lai data/features_graph,
KHONG train GPU, KHONG cham holdout). Nguon cache:
  - docs/dataset_v2_manifest.jsonl
  - ~/bfbg_benign_work/feat_cache.jsonl   (meta/graph/tbin/source/label/split)
  - ~/bfbg_benign_work/bin_parse.pkl      (tokc/caic/apic counters, sd stats; model-view)
  - ~/bfbg_benign_work/foldrun_v2es{101,202,303,404}.json   (BFBG first-150, per-sample)
  - ~/bfbg_benign_work/foldrun_v2api{101,202,303,404}.json  (BFBG api-density, per-sample)
In cac bang: BFBG 4-seed (first-150 & api-density), within-MSVC14, LOFO-5-family, H2 ensemble, H3/H4.
Bang can per-func (selection coverage #3-sach) KHONG tai lap tu cache -> dung verify_sel.py (doc JSON).
"""
import os, json, pickle, warnings, numpy as np
warnings.filterwarnings("ignore")
os.chdir("/home/dhgia/Work/Defi/BFBG-Transformer"); import sys; sys.path.insert(0, ".")
from collections import Counter, defaultdict
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import roc_auc_score
from src.training.splits import by_split, group_key
W = os.path.expanduser("~/bfbg_benign_work")

man = [json.loads(l) for l in open("docs/dataset_v2_manifest.jsonl")]
sp = by_split(man); by_sha = {r["sha256"]: r for r in man}
fc = {json.loads(l)["sha256"]: json.loads(l) for l in open(os.path.join(W, "feat_cache.jsonl"))}
P = pickle.load(open(os.path.join(W, "bin_parse.pkl"), "rb")) if os.path.exists(os.path.join(W, "bin_parse.pkl")) else {}
tp = sp["train_pool"]; bb = sp["holdout_family_bumblebee"]; ch = sp["holdout_source_chocolatey"]
FAMS = ["TrickBot", "Dridex", "IcedID", "Emotet", "BumbleBee"]
def auc(s, y): return roc_auc_score(y, s) if len(set(y)) > 1 else float("nan")
def cboot(s, y, cl, n=2000, seed=20261008):
    cl = np.asarray(cl); uc = np.unique(cl); rng = np.random.RandomState(seed); idx = {c: np.where(cl == c)[0] for c in uc}; v = []
    for _ in range(n):
        ii = np.concatenate([idx[c] for c in rng.choice(uc, len(uc), replace=True)])
        if len(set(y[ii])) > 1: v.append(auc(s[ii], y[ii]))
    v = np.array(v); return (float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))) if len(v) else (float("nan"),) * 2
def elements(cnt):
    out = []
    for k, v in cnt.items(): out += [k] * v
    return out
def feats(recs, which):  # meta|graph|gapi|tokens|callapi
    if which in ("meta", "graph"):
        X = [fc[r["sha256"]][which] for r in recs if r["sha256"] in fc]; keep = [r["sha256"] in fc for r in recs]
        return ("vec", np.array(X, float)), keep
    if which == "gapi":
        agg = Counter();
        for r in recs:
            if r["sha256"] in P: agg.update(P[r["sha256"]]["apic"])
        return None, None  # gapi needs global top-api; handled inline
    return None, None

EVAL = [r for r in bb + ch if (by_sha[r["sha256"]].get("num_functions") or 0) > 0]
y_ev = np.array([r["label"] for r in EVAL]); cl_ev = [group_key(r) for r in EVAL]

def rf_probe(train, test, which, topapi=None):
    tr = [r for r in train if r["sha256"] in fc and (which not in ("tokens", "callapi", "gapi") or r["sha256"] in P)]
    te = [r for r in test if r["sha256"] in fc and (which not in ("tokens", "callapi", "gapi") or r["sha256"] in P)]
    ytr = np.array([r["label"] for r in tr]); yte = np.array([r["label"] for r in te])
    if which in ("tokens", "callapi"):
        key = "tokc" if which == "tokens" else "caic"
        vec = TfidfVectorizer(analyzer=lambda c: elements(c), min_df=(3 if which == "tokens" else 2))
        Xtr = vec.fit_transform([P[r["sha256"]][key] for r in tr]); Xte = vec.transform([P[r["sha256"]][key] for r in te])
    else:
        def fb(r):
            g = fc[r["sha256"]]["graph"]; m = fc[r["sha256"]]["meta"]
            if which == "meta": return m
            if which == "graph": return g
            if which == "gapi":
                h = P[r["sha256"]]["apic"]; return g + [h.get(a, 0) for a in topapi]
        Xtr = np.array([fb(r) for r in tr], float); Xte = np.array([fb(r) for r in te], float)
    clf = RandomForestClassifier(300, random_state=42, n_jobs=-1, class_weight="balanced").fit(Xtr, ytr)
    s = clf.predict_proba(Xte)[:, 1]
    return s, yte, [group_key(r) for r in te]

def bfbg_scores(tags):
    acc = defaultdict(list)
    for t in tags:
        p = os.path.join(W, f"foldrun_{t}.json")
        if not os.path.exists(p): continue
        for ps in json.load(open(p))["per_sample"]:
            if ps["score"] is not None: acc[ps["sha"]].append(ps["score"])
    return acc

print("="*68); print("BANG 1 — BFBG 4-seed choco AUC (best-val_loss, n ghep doi)"); print("="*68)
for name, tags in [("first-150", ["v2es101","v2es202","v2es303","v2es404"]),
                   ("api-density", ["v2api101","v2api202","v2api303","v2api404"])]:
    per = []
    for t in tags:
        p = os.path.join(W, f"foldrun_{t}.json")
        if not os.path.exists(p): continue
        per.append(json.load(open(p))["auc"]["BFBG"][0])
    per = np.array(per)
    print(f"  {name:12s} seeds={['%.3f'%x for x in per]} mean={per.mean():.3f} ± {per.std(ddof=1):.3f}")

print("="*68); print("BANG 2 — WITHIN-MSVC14 (train trong bin) AUC [CI cum]"); print("="*68)
tbin = lambda s: fc.get(s, {}).get("tbin")
tr14 = [r for r in tp if tbin(r["sha256"]) == "MSVC 14"]
ev14 = [r for r in bb + ch if tbin(r["sha256"]) == "MSVC 14" and r["sha256"] in fc]
topapi = [a for a, _ in Counter(x for s in P for x in P[s]["apic"]).most_common(50)]
for which in ("meta", "graph", "gapi", "tokens"):
    s, y, cl = rf_probe(tr14, ev14, which, topapi); lo, hi = cboot(s, y, cl)
    print(f"  {which:10s} AUC={auc(s,y):.3f} [{lo:.3f},{hi:.3f}] (n={len(y)}, neg={int((y==0).sum())})")

print("="*68); print("BANG 3 — LOFO 5-family (mal giu lai vs choco) AUC"); print("="*68)
allmal = [r for r in man if r["label"] == 1 and r.get("source") in FAMS]; ben_tr = [r for r in tp if r["label"] == 0]
res = {w: [] for w in ("meta", "graph", "gapi", "tokens")}
for F in FAMS:
    trn = [r for r in allmal if r.get("source") != F] + ben_tr; tst = [r for r in allmal if r.get("source") == F] + ch
    line = f"  {F:10s} "
    for w in res:
        s, y, cl = rf_probe(trn, tst, w, topapi); a = auc(s, y); res[w].append(a); line += f"{w}={a:.3f} "
    print(line)
for w in res:
    a = np.array(res[w]); print(f"    {w:10s} mean={a.mean():.3f} ± {a.std(ddof=1):.3f}")

print("="*68); print("BANG 4 — H2 ensemble + H3 tokens + H4 gapi (eval bb vs choco)"); print("="*68)
# So goc (experiments_h.py 2026-10-10, TOAN token/api) vs tai lap (bin_parse, model-view cap 150 ham/512 token).
# Lech vi H3/H4 goc dung TAT CA token+api cua chuong trinh; ban tai lap dung counter da CAT theo goc nhin model
# (chi 150 ham dau, <=512 node/ham) nen it dac trung hon -> AUC thap hon. Within-MSVC14/LOFO dung cung bin_parse nen khop.
ORIG = {"tokens": 0.972, "gapi": 0.950, "graph": 0.907, "meta": 0.982}  # so goc tham chieu
NAME4 = {"tokens": "H3 BoT-full→model-view", "gapi": "H4 graph+API", "graph": "   graph-only", "meta": "   metadata"}
acc = bfbg_scores(["v2es101","v2es202","v2es303","v2es404"])
shas = [r["sha256"] for r in EVAL if r["sha256"] in acc]
ens = np.array([np.mean(acc[s]) for s in shas]); yy = np.array([by_sha[s]["label"] for s in shas])
print(f"  {'model':24s} {'so goc (full)':>14s}  {'tai lap (model-view)':>20s}")
print(f"  {'H2 ensemble first-150':24s} {'—':>14s}  {auc(ens,yy):>20.3f}")
for which in ("tokens", "gapi", "graph", "meta"):
    s, y, cl = rf_probe(tp, EVAL, which, topapi)
    og = ORIG.get(which); ogs = f"{og:.3f}" if og else "—"
    print(f"  {NAME4[which]:24s} {ogs:>14s}  {auc(s,y):>20.3f}")
print("  * 'BoT-full' = bag-of-tokens TOAN token (experiments_h.py); 'BoT-model-view' = cat 150ham/512tok (bin_parse).")
print("    H3: full 0.972 vs model-view ~0.93; H4 graph+API: full 0.950 vs model-view ~0.92. Khac do pham vi token/api.")

print("="*68); print("BANG 5 — seed-evidence bi cat (first-150, tu bin_parse) theo nhan"); print("="*68)
for lab, recs in [("benign", [r for r in tp+ch if r["label"]==0]), ("malicious", [r for r in man if r["label"]==1])]:
    tot = sum(P[r["sha256"]]["sd_tot"] for r in recs if r["sha256"] in P)
    df = sum(P[r["sha256"]]["sd_drop_func"] for r in recs if r["sha256"] in P)
    print(f"  {lab:10s} seed_tot={tot} drop_by_funcs>150={100*df/max(tot,1):.1f}%")
print("\n[NOTE] Bang #3-sach (coverage theo policy first/spread/api-density) can per-func -> chay verify_sel.py (doc JSON).")
print("DONE reproduce_tables")
