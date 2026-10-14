#!/usr/bin/env python
"""Xuat moi bang cho bai ra paper_tables/ dang CSV + LaTeX, kem hash + ten script sinh.
- Dev / within-MSVC14 / LOFO: recompute tu CACHE (feat_cache + bin_parse + foldrun JSON),
  logic trung voi reproduce_tables.py (da commit). Cung chay reproduce_tables.py de luu stdout doi chieu.
- Bang v3: DOC TU docs/v3_eval_result.json (da khoa, SHA256 1dca53a2...); KHONG tinh lai.
KHONG train, KHONG cham holdout.
"""
import os, sys, json, hashlib, csv, subprocess, pickle, numpy as np
sys.path.insert(0, "."); os.chdir("/home/dhgia/Work/Defi/BFBG-Transformer")
from collections import Counter, defaultdict
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import roc_auc_score
from src.training.splits import by_split, group_key, group_kfold
W = os.path.expanduser("~/bfbg_benign_work")
OUT = "paper_tables"; os.makedirs(OUT, exist_ok=True)
def sha256f(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()
REPRO = "experiments/dataset/pilots/reproduce_tables.py"
EVALJSON = "docs/v3_eval_result.json"
HASHES = {REPRO: sha256f(REPRO), EVALJSON: sha256f(EVALJSON),
          "docs/dataset_v3_manifest.jsonl": sha256f("docs/dataset_v3_manifest.jsonl")}

def write_table(name, header, rows, source, note=""):
    # CSV
    with open(os.path.join(OUT, name+".csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["# source: "+source]);
        if note: w.writerow(["# note: "+note])
        w.writerow(header); [w.writerow(r) for r in rows]
    # LaTeX (booktabs)
    with open(os.path.join(OUT, name+".tex"), "w") as f:
        f.write(f"% source: {source}\n")
        if note: f.write(f"% note: {note}\n")
        f.write("\\begin{tabular}{" + "l"*1 + "r"*(len(header)-1) + "}\n\\toprule\n")
        f.write(" & ".join(str(h) for h in header) + " \\\\\n\\midrule\n")
        for r in rows: f.write(" & ".join(str(x) for x in r) + " \\\\\n")
        f.write("\\bottomrule\n\\end{tabular}\n")

# ---------- load caches ----------
man = [json.loads(l) for l in open("docs/dataset_v2_manifest.jsonl")]
sp = by_split(man); by_sha = {r["sha256"]: r for r in man}
fc = {json.loads(l)["sha256"]: json.loads(l) for l in open(os.path.join(W, "feat_cache.jsonl"))}
P = pickle.load(open(os.path.join(W, "bin_parse.pkl"), "rb"))
tp = sp["train_pool"]; bb = sp["holdout_family_bumblebee"]; ch = sp["holdout_source_chocolatey"]
FAMS = ["TrickBot", "Dridex", "IcedID", "Emotet", "BumbleBee"]
def auc(s, y): return roc_auc_score(y, s) if len(set(y)) > 1 else float("nan")
def elements(c):
    o = []; [o.extend([k]*v) for k, v in c.items()]; return o
EVAL = [r for r in bb + ch if (by_sha[r["sha256"]].get("num_functions") or 0) > 0 and r["sha256"] in fc]
y_ev = np.array([r["label"] for r in EVAL])
def rf(train, test, which, topapi=None):
    tr = [r for r in train if r["sha256"] in fc and (which not in ("tokens","gapi") or r["sha256"] in P)]
    te = [r for r in test if r["sha256"] in fc and (which not in ("tokens","gapi") or r["sha256"] in P)]
    ytr = np.array([r["label"] for r in tr])
    if which == "tokens":
        vec = TfidfVectorizer(analyzer=lambda c: elements(c), min_df=3)
        Xtr = vec.fit_transform([P[r["sha256"]]["tokc"] for r in tr]); Xte = vec.transform([P[r["sha256"]]["tokc"] for r in te])
    else:
        def fb(r):
            g = fc[r["sha256"]]["graph"]
            return fc[r["sha256"]]["meta"] if which=="meta" else (g if which=="graph" else g+[P[r["sha256"]]["apic"].get(a,0) for a in topapi])
        Xtr = np.array([fb(r) for r in tr], float); Xte = np.array([fb(r) for r in te], float)
    clf = RandomForestClassifier(300, random_state=42, n_jobs=-1, class_weight="balanced").fit(Xtr, ytr)
    return clf.predict_proba(Xte)[:,1], np.array([r["label"] for r in te])
topapi = [a for a,_ in Counter(x for s in P for x in P[s]["apic"]).most_common(50)]

# ---------- TABLE: BFBG 4-seed (tu foldrun JSON) ----------
def seedmean(tags):
    v=[json.load(open(os.path.join(W,f"foldrun_{t}.json")))["auc"]["BFBG"][0] for t in tags]
    return np.array(v)
f150=seedmean(["v2es101","v2es202","v2es303","v2es404"]); api=seedmean(["v2api101","v2api202","v2api303","v2api404"])
write_table("dev_bfbg_4seed", ["variant","seeds","mean","std"],
    [["first-150", "/".join("%.3f"%x for x in f150), "%.3f"%f150.mean(), "%.3f"%f150.std(ddof=1)],
     ["api-density", "/".join("%.3f"%x for x in api), "%.3f"%api.mean(), "%.3f"%api.std(ddof=1)]],
    source=f"foldrun_v2es*/v2api*.json (ensemble seeds); recomputed by {REPRO} (sha256 {HASHES[REPRO][:12]})")

# ---------- TABLE: within-MSVC14 ----------
def cboot(s,y,cl,n=2000):
    cl=np.asarray(cl); uc=np.unique(cl); rng=np.random.RandomState(20261008); idx={c:np.where(cl==c)[0] for c in uc}; v=[]
    for _ in range(n):
        ii=np.concatenate([idx[c] for c in rng.choice(uc,len(uc),replace=True)])
        if len(set(y[ii]))>1: v.append(auc(s[ii],y[ii]))
    v=np.array(v); return (np.percentile(v,2.5),np.percentile(v,97.5)) if len(v) else (float('nan'),)*2
tbin=lambda s: fc.get(s,{}).get("tbin")
tr14=[r for r in tp if tbin(r["sha256"])=="MSVC 14"]; ev14=[r for r in bb+ch if tbin(r["sha256"])=="MSVC 14" and r["sha256"] in fc]
rows14=[]
for m,lab in [("meta","metadata"),("graph","graph"),("gapi","graph+API"),("tokens","bag-of-tokens")]:
    s,y=rf(tr14,ev14,m,topapi); lo,hi=cboot(s,y,[group_key(r) for r in ev14 if r["sha256"] in fc])
    rows14.append([lab,"%.3f"%auc(s,y),"%.3f"%lo,"%.3f"%hi])
write_table("dev_within_msvc14", ["model","AUC","CI-lo","CI-hi"], rows14,
    source=f"{REPRO} (sha256 {HASHES[REPRO][:12]}); eval MSVC14 BumbleBee vs choco, n_neg=21")

# ---------- TABLE: LOFO 5-family ----------
allmal=[r for r in man if r["label"]==1 and r.get("source") in FAMS]; ben=[r for r in tp if r["label"]==0]
res={m:[] for m in ("meta","graph","gapi","tokens")}; perfam=[]
for F in FAMS:
    trn=[r for r in allmal if r.get("source")!=F]+ben; tst=[r for r in allmal if r.get("source")==F]+ch
    row=[F]
    for m in ("meta","graph","gapi","tokens"):
        s,y=rf(trn,tst,m,topapi); a=auc(s,y); res[m].append(a); row.append("%.3f"%a)
    perfam.append(row)
meanrow=["mean±std"]+["%.3f±%.3f"%(np.mean(res[m]),np.std(res[m],ddof=1)) for m in ("meta","graph","gapi","tokens")]
write_table("dev_lofo_5family", ["family","metadata","graph","graph+API","bag-of-tokens"], perfam+[meanrow],
    source=f"{REPRO} (sha256 {HASHES[REPRO][:12]}); leave-one-family-out, positives=family vs choco")

# ---------- TABLE v3 (DOC TU JSON, KHONG TINH LAI) ----------
r3=json.load(open(EVALJSON)); M=r3["models"]
order=["meta","graph","bag_of_tokens","bfbg_first150","bfbg_apidensity"]
disp={"meta":"metadata","graph":"graph","bag_of_tokens":"bag-of-tokens","bfbg_first150":"BFBG first-150","bfbg_apidensity":"BFBG api-density"}
rowsA=[[disp[m],"%.3f"%M[m]["auc"],"%.3f"%M[m]["auc_ci"][0],"%.3f"%M[m]["auc_ci"][1]] for m in order]
write_table("v3_auc", ["model","AUC","CI-lo","CI-hi"], rowsA,
    source=f"READ FROM {EVALJSON} (sha256 {HASHES[EVALJSON][:12]}); NOT recomputed",
    note="AUC = BumbleBee dev positives (262) vs v3 holdout negatives (165), cluster-bootstrap CI")
BINS=["MSVC<=10","MSVC 11-12","MSVC 14","GNU/MinGW","Go","Delphi","khac"]
# n per bin
nb=Counter(v["bin"] for v in r3["samples"].values() if v["set"]=="neg")
binrows=[]
for b in BINS:
    if nb.get(b,0)==0: continue
    row=[f"{('other' if b=='khac' else b)} (n={nb[b]})"]
    for m in order:
        fb=M[m]["fpr_by_bin"].get(b)
        row.append("%.1f"%(fb["fpr"]*100) if fb else "-")
    binrows.append(row)
binrows.append(["all (n=%d)"%sum(nb.values())]+["%.1f"%(M[m]["fpr"]*100) for m in order])
write_table("v3_fpr_by_bin", ["bin","meta","graph","tokens","BFBG-f150","BFBG-API"], binrows,
    source=f"READ FROM {EVALJSON} (sha256 {HASHES[EVALJSON][:12]}); NOT recomputed",
    note="FPR(%) at train-chosen threshold; READ WITHIN model only (not comparable across models); Wilson CI in JSON")

# ---------- manifest of tables ----------
with open(os.path.join(OUT, "TABLES_MANIFEST.md"), "w") as f:
    f.write("# paper_tables -- provenance\n\n")
    f.write("| table | CSV/LaTeX | source | hash |\n|---|---|---|---|\n")
    f.write(f"| BFBG 4-seed | dev_bfbg_4seed | foldrun JSON + {REPRO} | {HASHES[REPRO][:16]} |\n")
    f.write(f"| within-MSVC14 | dev_within_msvc14 | {REPRO} (cache) | {HASHES[REPRO][:16]} |\n")
    f.write(f"| LOFO 5-family | dev_lofo_5family | {REPRO} (cache) | {HASHES[REPRO][:16]} |\n")
    f.write(f"| v3 AUC | v3_auc | {EVALJSON} (READ, not recomputed) | {HASHES[EVALJSON][:16]} |\n")
    f.write(f"| v3 FPR-by-bin | v3_fpr_by_bin | {EVALJSON} (READ, not recomputed) | {HASHES[EVALJSON][:16]} |\n")
    f.write(f"\nFull hashes:\n")
    for k,v in HASHES.items(): f.write(f"- {k} = {v}\n")
print("WROTE:", sorted(os.listdir(OUT)))
