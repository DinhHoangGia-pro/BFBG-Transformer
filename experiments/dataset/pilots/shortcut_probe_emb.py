#!/usr/bin/env python
# SHORTCUT DIAGNOSTIC (analysis, inference only — NOT training BFBG).
# Linear probe on the §17 checkpoint embedding to predict toolchain-bin and family,
# cluster-grouped CV, vs baselines: untrained embedding, 7 graph scalars, from-label.
# Excludes holdout_source_nirsoft (do not touch).
import os, sys, json, warnings
warnings.filterwarnings("ignore")
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")
os.chdir("/home/dhgia/Work/Defi/BFBG-Transformer"); sys.path.insert(0, ".")
import numpy as np, torch
from torch.utils.data import DataLoader
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from src.training.bfbg_dataset import BFBGDataset, collate
from src.training.splits import load_manifest, by_split, group_key, group_kfold
from src.models.bfbg_transformer import BFBGTransformer

dev = "cuda" if torch.cuda.is_available() else "cpu"
stoi = json.load(open("data/insn_vocab_v2.json"))
if isinstance(stoi, list): stoi = {t: i for i, t in enumerate(stoi)}
vsz = len(stoi); FEAT = "data/features_graph"
man = load_manifest(os.path.join("docs", "dataset_v2_manifest.jsonl"))
# probe set: train_pool + bumblebee + test_indist + choco (NOT nirsoft/lowfreq holdouts)
USE = {"train_pool", "holdout_family_bumblebee", "test_indist", "holdout_source_chocolatey"}
recs = [r for r in man if r["split"] in USE]
fc = {json.loads(l)["sha256"]: json.loads(l) for l in open(os.path.expanduser("~/bfbg_benign_work/feat_cache.jsonl"))}
recs = [r for r in recs if r["sha256"] in fc]
fam = {"TrickBot": 0, "Dridex": 1, "BumbleBee": 2, "IcedID": 3, "Emotet": 4, "vx-underground": 5}
BINS = ["MSVC<=10", "MSVC 11-12", "MSVC 14", "GNU/MinGW", "Go", "Delphi", "khac"]
binid = {b: i for i, b in enumerate(BINS)}
print(f"probe set n={len(recs)} dev={dev}", flush=True)

def embed(model):
    model.eval(); cap = {}
    h = model.fc1.register_forward_pre_hook(lambda m, inp: cap.__setitem__("v", inp[0].detach().cpu()))
    out = {}
    dl = DataLoader(BFBGDataset(recs, stoi, max_funcs=150, feat_dir=FEAT), batch_size=4, shuffle=False, num_workers=0, collate_fn=collate)
    with torch.no_grad():
        for batch in dl:
            if batch is None: continue
            cap.clear()
            try: model(batch, train_sem_predictor=False)
            except Exception:
                if dev == "cuda": torch.cuda.empty_cache(); continue
            if "v" in cap:
                for j, mt in enumerate(batch["metas"]): out[mt["sha256"]] = cap["v"][j].numpy()
    h.remove(); return out

# trained (best ep9) + untrained (random init); cache to disk so a probe bug doesn't lose extraction
import pickle
EMBP = os.path.expanduser("~/bfbg_benign_work/shortcut_emb.pkl")
if os.path.exists(EMBP):
    d = pickle.load(open(EMBP, "rb")); emb_tr, emb_un = d["tr"], d["un"]
    print(f"loaded cached embeddings: trained={len(emb_tr)} untrained={len(emb_un)}", flush=True)
else:
    mt = BFBGTransformer.from_config(vsz, num_global_features=0).to(dev)
    mt.load_state_dict(torch.load(os.path.expanduser("~/bfbg_benign_work/ckpt_v2es202.pt"), map_location=dev))
    emb_tr = embed(mt)
    torch.manual_seed(0)
    mu = BFBGTransformer.from_config(vsz, num_global_features=0).to(dev)
    emb_un = embed(mu)
    pickle.dump({"tr": emb_tr, "un": emb_un}, open(EMBP, "wb"))
    print(f"embeddings: trained={len(emb_tr)} untrained={len(emb_un)} dim={len(next(iter(emb_tr.values())))} (cached)", flush=True)
# keep only samples with an embedding in BOTH (num_functions=0 dropped at collate)
recs = [r for r in recs if r["sha256"] in emb_tr and r["sha256"] in emb_un]
print(f"probe set after emb filter: n={len(recs)}", flush=True)

def cv_probe(X, y, groups, recs_sub):
    # cluster-grouped CV accuracy (macro over folds), LogisticRegression
    folds = group_kfold(recs_sub, k=5)
    accs = []
    for fv in folds:
        tri = [i for i, r in enumerate(recs_sub) if r["sha256"] not in fv]
        vai = [i for i, r in enumerate(recs_sub) if r["sha256"] in fv]
        if not vai or len(set(y[tri])) < 2: continue
        sc = StandardScaler().fit(X[tri]);
        clf = LogisticRegression(max_iter=2000, C=1.0).fit(sc.transform(X[tri]), y[tri])
        accs.append((clf.predict(sc.transform(X[vai])) == y[vai]).mean())
    return float(np.mean(accs)) if accs else float("nan"), len(accs)

def majority_from_label(y, labels):
    # predict target from binary label: per label pick majority target, report accuracy
    pred = np.zeros_like(y)
    for lab in set(labels):
        m = labels == lab
        if m.any():
            vals, cnts = np.unique(y[m], return_counts=True); pred[m] = vals[np.argmax(cnts)]
    return float((pred == y).mean())

print("\n===== TASK A: predict TOOLCHAIN-BIN (all probe-set samples) =====", flush=True)
sub = recs
y = np.array([binid[fc[r["sha256"]]["tbin"]] for r in sub])
labels = np.array([r["label"] for r in sub])
Xtr = np.array([emb_tr[r["sha256"]] for r in sub]); Xun = np.array([emb_un[r["sha256"]] for r in sub])
X7 = np.array([fc[r["sha256"]]["graph"] for r in sub])
maj = np.bincount(y).max() / len(y)
for nm, X in [("trained-emb", Xtr), ("untrained-emb", Xun), ("7-scalar", X7)]:
    a, k = cv_probe(X, y, None, sub); print(f"  {nm:14s} CV-acc={a:.3f} (folds={k})", flush=True)
print(f"  from-label        acc={majority_from_label(y, labels):.3f}", flush=True)
print(f"  majority-class    acc={maj:.3f}  (classes present={sorted(set(y))})", flush=True)

print("\n===== TASK B: predict FAMILY (malicious only) =====", flush=True)
subm = [r for r in recs if r["label"] == 1 and r["source"] in fam]
ym = np.array([fam[r["source"]] for r in subm])
Xtrm = np.array([emb_tr[r["sha256"]] for r in subm]); Xunm = np.array([emb_un[r["sha256"]] for r in subm])
X7m = np.array([fc[r["sha256"]]["graph"] for r in subm])
majm = np.bincount(ym).max() / len(ym)
from collections import Counter
print(f"  n={len(subm)} family dist={dict(Counter(r['source'] for r in subm))}", flush=True)
for nm, X in [("trained-emb", Xtrm), ("untrained-emb", Xunm), ("7-scalar", X7m)]:
    a, k = cv_probe(X, ym, None, subm); print(f"  {nm:14s} CV-acc={a:.3f} (folds={k})", flush=True)
print(f"  majority-class    acc={majm:.3f}", flush=True)
json.dump({"n_bin": len(sub), "n_fam": len(subm)}, open(os.path.expanduser("~/bfbg_benign_work/shortcut_probe.json"), "w"))
print("DONE shortcut probe", flush=True)
