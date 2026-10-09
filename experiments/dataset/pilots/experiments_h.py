#!/usr/bin/env python
# 4 cheap experiments (CPU, no BFBG training). H1 truncation shortcut, H2 calibration/
# ensemble of 4 checkpoints, H3 bag-of-tokens TF-IDF+RF, H4 API-histogram probe.
import json, os, warnings, numpy as np
warnings.filterwarnings("ignore")
os.chdir("/home/dhgia/Work/Defi/BFBG-Transformer")
from collections import Counter, defaultdict
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import roc_auc_score
from src.training.splits import by_split, group_key

MF = 150
man = [json.loads(l) for l in open("docs/dataset_v2_manifest.jsonl")]
sp = by_split(man)
tp = sp["train_pool"]; bb = sp["holdout_family_bumblebee"]; ch = sp["holdout_source_chocolatey"]
fc = {json.loads(l)["sha256"]: json.loads(l) for l in open(os.path.expanduser("~/bfbg_benign_work/feat_cache.jsonl"))}
nfmap = {r["sha256"]: (r.get("num_functions") or 0) for r in man}
FEAT = "data/features_graph"

def auc(s, y): return roc_auc_score(y, s) if len(set(y)) > 1 else float("nan")
# paired eval set (drop num_functions==0)
evic = [r for r in bb + ch if nfmap.get(r["sha256"], 0) > 0 and r["sha256"] in fc]
y_ev = np.array([r["label"] for r in evic])
cl_ev = np.array([group_key(r) for r in evic])
def recall_at_fpr(sc, y, fprs=(0.01, 0.05, 0.10)):
    neg = np.sort(sc[y == 0]); out = []
    for f in fprs:
        thr = np.quantile(neg, 1 - f); out.append(float((sc[y == 1] >= thr).mean()))
    return out

print("="*70); print("H1 — truncation shortcut"); print("="*70)
# per-label truncation + dropped-function stats on train_pool
for name, recs in [("train_pool", tp), ("eval(bb+choco)", evic)]:
    for lab in (0, 1):
        sub = [r for r in recs if r["label"] == lab]
        nf = np.array([nfmap.get(r["sha256"], 0) for r in sub])
        tr = nf > MF
        dropped = (nf[tr] - MF)
        print(f"  {name:16s} label{lab}: n={len(sub)} trunc={tr.sum()}({100*tr.mean():.0f}%) "
              f"median_nf={np.median(nf):.0f} median_dropped(if trunc)={np.median(dropped) if len(dropped) else 0:.0f}")
# shortcut: predict label from num_functions alone on eval set
nf_ev = np.array([nfmap[r["sha256"]] for r in evic], float)
print(f"  AUC(label from num_functions alone, eval) = {auc(nf_ev, y_ev):.3f}")
print(f"  AUC(label from truncated-flag alone, eval) = {auc((nf_ev>MF).astype(float), y_ev):.3f}")
# probe AUC on truncated vs non-truncated eval subsets (RF on v2 train_pool)
def feats(recs, which):
    X=[]; keep=[]
    for r in recs:
        d=fc.get(r["sha256"]);
        if d is None: keep.append(False); continue
        X.append(d[which]); keep.append(True)
    return np.array(X,float), np.array(keep)
for which in ("meta", "graph"):
    Xtr,ktr=feats(tp,which); ytr=np.array([r["label"] for r in tp])[ktr]
    clf=RandomForestClassifier(n_estimators=300,random_state=42,n_jobs=-1,class_weight="balanced").fit(Xtr,ytr)
    Xev,kev=feats(evic,which); s=clf.predict_proba(Xev)[:,1]; yy=y_ev[kev]; nfe=nf_ev[kev]
    for tag,msk in [("truncated",nfe>MF),("non-trunc",nfe<=MF)]:
        a=auc(s[msk],yy[msk]); print(f"  probe[{which}] {tag:10s} n={int(msk.sum())} (ben={int((yy[msk]==0).sum())}) AUC={a:.3f}")

print("="*70); print("H2 — calibration / ensemble of 4 checkpoints (best-val_loss)"); print("="*70)
ps = {}
for t in ("v2es101","v2es202","v2es303","v2es404"):
    r=json.load(open(os.path.expanduser(f"~/bfbg_benign_work/foldrun_{t}.json")))
    ps[t]={p["sha"]:p["score"] for p in r["per_sample"] if p["score"] is not None}
shas=[r["sha256"] for r in evic]
M=np.array([[ps[t].get(s,np.nan) for t in ps] for s in shas])  # [n,4]
ok=~np.isnan(M).any(1); M=M[ok]; yv=y_ev[ok]
seeds=list(ps.keys())
for j,t in enumerate(seeds):
    sc=M[:,j]; a=auc(sc,yv); br=float(np.mean((sc-yv)**2)); r159=recall_at_fpr(sc,yv)
    print(f"  {t}: AUC={a:.3f} Brier={br:.3f} recall@FPR1/5/10={r159[0]*100:.0f}/{r159[1]*100:.0f}/{r159[2]*100:.0f}")
ens=M.mean(1); ae=auc(ens,yv); bre=float(np.mean((ens-yv)**2)); re159=recall_at_fpr(ens,yv)
print(f"  ENSEMBLE(mean4): AUC={ae:.3f} Brier={bre:.3f} recall@FPR1/5/10={re159[0]*100:.0f}/{re159[1]*100:.0f}/{re159[2]*100:.0f}")
print(f"  (single-seed AUC: mean={np.mean([auc(M[:,j],yv) for j in range(4)]):.3f} ± {np.std([auc(M[:,j],yv) for j in range(4)],ddof=1):.3f})")

print("="*70); print("H3+H4 — read JSON once (train_pool+bb+choco): bag-of-tokens TF-IDF, API histogram"); print("="*70)
docs={}; apihist={}
allrecs=tp+bb+ch
for i,r in enumerate(allrecs):
    sha=r["sha256"]; fp=os.path.join(FEAT,f"{sha}_static.json")
    if not os.path.exists(fp): continue
    d=json.load(open(fp)); toks=[]; apis=[]
    for g in d.get("intra_procedural_graphs",{}).values():
        for n in g.get("nodes",[]):
            t=n.get("token");
            if t: toks.append(t)
            a=n.get("api")
            if a: apis.append(a)
    docs[sha]=" ".join(toks); apihist[sha]=Counter(apis)
    if (i+1)%400==0: print(f"  ...read {i+1}/{len(allrecs)}",flush=True)
# H3: TF-IDF tokens
tr_sha=[r["sha256"] for r in tp if r["sha256"] in docs]; ytr=np.array([r["label"] for r in tp if r["sha256"] in docs])
vec=TfidfVectorizer(token_pattern=r"[^ ]+", min_df=3)
Xtr=vec.fit_transform([docs[s] for s in tr_sha])
clf=RandomForestClassifier(n_estimators=300,random_state=42,n_jobs=-1,class_weight="balanced").fit(Xtr,ytr)
ev_sha=[r["sha256"] for r in evic if r["sha256"] in docs]
Xev=vec.transform([docs[s] for s in ev_sha]); sev=clf.predict_proba(Xev)[:,1]
yev=np.array([r["label"] for r in evic if r["sha256"] in docs])
r159=recall_at_fpr(sev,yev)
print(f"  H3 bag-of-tokens TFIDF+RF: vocab={len(vec.vocabulary_)} AUC={auc(sev,yev):.3f} recall@FPR1/5/10={r159[0]*100:.0f}/{r159[1]*100:.0f}/{r159[2]*100:.0f}")
# H4: graph 7-scalar + API histogram
apivocab=Counter()
for s in tr_sha:
    apivocab.update(apihist[s].keys())
topapi=[a for a,_ in apivocab.most_common(50)]
def apivec(sha): h=apihist.get(sha,{}); return [h.get(a,0) for a in topapi]
def g7(sha): return fc[sha]["graph"]
for tag,build in [("graph-only",lambda s:g7(s)),("graph+APIhist",lambda s:g7(s)+apivec(s))]:
    Xtr2=np.array([build(s) for s in tr_sha],float)
    clf2=RandomForestClassifier(n_estimators=300,random_state=42,n_jobs=-1,class_weight="balanced").fit(Xtr2,ytr)
    Xev2=np.array([build(s) for s in ev_sha],float); se=clf2.predict_proba(Xev2)[:,1]
    r2=recall_at_fpr(se,yev)
    print(f"  H4 {tag:14s}: AUC={auc(se,yev):.3f} recall@FPR1/5/10={r2[0]*100:.0f}/{r2[1]*100:.0f}/{r2[2]*100:.0f}")
print("DONE experiments")
