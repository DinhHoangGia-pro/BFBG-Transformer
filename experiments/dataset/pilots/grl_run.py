#!/usr/bin/env python
"""GRL variant 1 (toolchain-invariant) probe run. NOT a holdout touch; v2 train, BumbleBee fold, dev choco.
- Gradient Reversal Layer on pooled_program (fc1 input, global_features=0) -> toolchain adversary MLP(128->64->7).
- Loss = CE_detect + lambda_sem*sem + CE_adv(toolchain via GRL). DANN lambda ramp, cap lambda_max.
- section-17 early stopping on val detect-loss, grad-clip 1.0, 8h wall ceiling, best-by-val-loss checkpoint.
- After best reload: AUC(BumbleBee vs choco)+cluster CI; cluster-CV linear probe toolchain/family (+majority);
  recall@thr by bin. Saves result JSON. KHONG cham v3/holdout v2.
"""
import os, sys, json, time, random, warnings, argparse, numpy as np
warnings.filterwarnings("ignore"); os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")
os.chdir("/home/dhgia/Work/Defi/BFBG-Transformer"); sys.path.insert(0, ".")
import torch, torch.nn as nn, torch.nn.functional as F
from torch.utils.data import DataLoader
from src.training.bfbg_dataset import BFBGDataset, collate
from src.training.splits import load_manifest, by_split, group_key, group_kfold
from src.models.bfbg_transformer import BFBGTransformer
from src.utils.path_resolver import load_config, REPO_ROOT
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score
from collections import defaultdict, Counter

ap = argparse.ArgumentParser()
ap.add_argument("--model-seed", type=int, required=True)
ap.add_argument("--lambda-max", type=float, default=1.0)
ap.add_argument("--max-epochs", type=int, default=40)
ap.add_argument("--max-hours", type=float, default=8.0)
ap.add_argument("--min-delta", type=float, default=0.002)
ap.add_argument("--smoke", type=int, default=0)
ap.add_argument("--tag", required=True)
A = ap.parse_args(); WALL0 = time.time()
SEED = 20261008; MS = A.model_seed
random.seed(MS); np.random.seed(MS); torch.manual_seed(MS)
dev = "cuda" if torch.cuda.is_available() else "cpu"
W = os.path.expanduser("~/bfbg_benign_work")
stoi = json.load(open("data/insn_vocab_v2.json")); stoi = {t: i for i, t in enumerate(stoi)} if isinstance(stoi, list) else stoi
FEAT = "data/features_graph"
man = load_manifest(os.path.join(REPO_ROOT, "docs/dataset_v2_manifest.jsonl")); sp = by_split(man)
fc = {json.loads(l)["sha256"]: json.loads(l) for l in open(os.path.join(W, "feat_cache.jsonl"))}
BINS = ["MSVC<=10","MSVC 11-12","MSVC 14","GNU/MinGW","Go","Delphi","khac"]; binid = {b: i for i, b in enumerate(BINS)}
FAMS = ["TrickBot","Dridex","IcedID","Emotet","BumbleBee"]; famid = {f: i for i, f in enumerate(FAMS)}
def tbin(s): return fc.get(s, {}).get("tbin", "khac")

tp = sp["train_pool"]; bb = sp["holdout_family_bumblebee"]; ch = sp["holdout_source_chocolatey"]
# iso cap 113 + §17 val carve (seed 20261008)
iso = [r for r in tp if r.get("source") == "windows11-eval-iso"]; rnd = random.Random(SEED); rnd.shuffle(iso)
keep = set(r["sha256"] for r in iso[:113]); tp = [r for r in tp if r.get("source") != "windows11-eval-iso" or r["sha256"] in keep]
groups = defaultdict(list)
for r in tp: groups[group_key(r)].append(r)
gl = list(groups.items()); random.Random(SEED).shuffle(gl)
val = []; nval = 0; target = int(0.15 * len(tp))
for g, recs in gl:
    if nval < target: val += recs; nval += len(recs)
vs = set(r["sha256"] for r in val); train = [r for r in tp if r["sha256"] not in vs]
if A.smoke: train = train[:6]; val = val[:6]
cfg = load_config("model")["training"]; LAM = load_config("model")["semantic"]["lambda_sem"]
EP = 4 if A.smoke else A.max_epochs; LR = cfg["learning_rate"]; MF = cfg["max_functions_per_sample"]; GC = cfg["grad_clip"]; MICRO = 2; ACC = 2
print(f"[{A.tag}] seed={MS} lambda_max={A.lambda_max} train={len(train)} val={len(val)} bb={len(bb)} choco={len(ch)} dev={dev}", flush=True)

def mkds(recs): return BFBGDataset(recs, stoi, max_funcs=MF, feat_dir=FEAT, select="first")
dl = DataLoader(mkds(train), batch_size=MICRO, shuffle=True, num_workers=0, collate_fn=collate, generator=torch.Generator().manual_seed(MS))
model = BFBGTransformer.from_config(len(stoi), num_global_features=0).to(dev)

class GradReverse(torch.autograd.Function):
    @staticmethod
    def forward(ctx, x, lamb): ctx.lamb = lamb; return x.view_as(x)
    @staticmethod
    def backward(ctx, g): return g.neg() * ctx.lamb, None
def grl(x, lamb): return GradReverse.apply(x, lamb)
adv = nn.Sequential(nn.Linear(model.hidden_dim, 64), nn.ReLU(), nn.Linear(64, len(BINS))).to(dev)
opt = torch.optim.Adam(list(model.parameters()) + list(adv.parameters()), lr=LR, weight_decay=cfg["weight_decay"])

cap = {}
h = model.fc1.register_forward_pre_hook(lambda m, inp: cap.__setitem__("v", inp[0]))
def tool_labels(metas): return torch.tensor([binid.get(tbin(m["sha256"]), 6) for m in metas], dtype=torch.long, device=dev)

@torch.no_grad()
def val_detect_loss():
    model.eval(); tot = 0.0; n = 0
    for b in DataLoader(mkds(val), batch_size=MICRO, shuffle=False, num_workers=0, collate_fn=collate):
        if b is None: continue
        y = b["labels"].to(dev)
        try:
            lg, _ = model(b, train_sem_predictor=False)
            if torch.isfinite(lg).all(): tot += float(F.cross_entropy(lg, y, reduction="sum")); n += len(y)
        except Exception:
            if dev == "cuda": torch.cuda.empty_cache()
    return tot / max(n, 1)

CKPT = os.path.join(W, f"ckpt_{A.tag}.pt")
best_vl = float("inf"); best_ep = -1; no_improve = 0; lr_cuts = 0; stop_reason = "max_epochs"; losses = []; vlc = []
total_steps = EP * max(1, len(train) // (MICRO * ACC))
step = 0
for ep in range(EP):
    model.train(); adv.train(); t0 = time.time(); tl = ta = 0.0; nb = 0; oom = 0; bad = 0; opt.zero_grad(); acc_i = 0
    for b in dl:
        if b is None: continue
        y = b["labels"].to(dev); tl_lab = tool_labels(b["metas"])
        lamb = min(A.lambda_max, 2.0/(1.0+np.exp(-10.0*(step/max(total_steps,1))))-1.0); step += 1
        try:
            lg, sem = model(b, train_sem_predictor=True)
            if not torch.isfinite(lg).all(): bad += 1; continue
            pooled = cap["v"]
            adv_logits = adv(grl(pooled, lamb))
            ld = F.cross_entropy(lg, y); la = F.cross_entropy(adv_logits, tl_lab)
            loss = (ld + LAM * sem + la) / ACC
            loss.backward(); acc_i += 1; tl += float(ld); ta += float(la); nb += 1
            if acc_i == ACC:
                torch.nn.utils.clip_grad_norm_(list(model.parameters()) + list(adv.parameters()), GC); opt.step(); opt.zero_grad(); acc_i = 0
        except torch.cuda.OutOfMemoryError:
            oom += 1; opt.zero_grad(); acc_i = 0
            if dev == "cuda": torch.cuda.empty_cache()
        except Exception: bad += 1
    if acc_i: torch.nn.utils.clip_grad_norm_(list(model.parameters()) + list(adv.parameters()), GC); opt.step(); opt.zero_grad()
    vl = val_detect_loss(); vlc.append(vl); losses.append(tl / max(nb, 1))
    note = ""
    if vl < best_vl - A.min_delta: best_vl = vl; best_ep = ep; no_improve = 0; torch.save(model.state_dict(), CKPT); note = "*best"
    else:
        no_improve += 1
        if no_improve % 5 == 0 and lr_cuts < 2:
            for g in opt.param_groups: g["lr"] *= 0.5
            lr_cuts += 1; note = f"lr_halved#{lr_cuts}"
    gt = os.popen("sensors 2>/dev/null|grep -oE 'Package id 0:\\s*\\+?[0-9.]+'|grep -oE '[0-9.]+$'").read().strip().split("\n")[0] if dev=="cuda" else "NA"
    print(f"epoch {ep:2d}: det_loss={losses[-1]:.4f} adv_loss={ta/max(nb,1):.4f} val_loss={vl:.4f} lambda={lamb:.3f} no_improve={no_improve} CPU={gt}C t={time.time()-t0:.0f}s {note}", flush=True)
    if no_improve >= 10: stop_reason = f"early_stop@ep{ep}"; break
    if time.time() - WALL0 > A.max_hours * 3600: stop_reason = f"wall@ep{ep}"; break
h.remove()
if os.path.exists(CKPT): model.load_state_dict(torch.load(CKPT, map_location=dev)); print(f"reloaded best ep{best_ep} vl={best_vl:.4f}", flush=True)

# ---- scoring + embeddings (hook again) ----
cap2 = {}; h2 = model.fc1.register_forward_pre_hook(lambda m, inp: cap2.__setitem__("v", inp[0].detach().cpu()))
@torch.no_grad()
def score_embed(recs):
    model.eval(); sc = {}; emb = {}
    for b in DataLoader(mkds(recs), batch_size=1, shuffle=False, num_workers=0, collate_fn=collate):
        pass
    # per-sample loop (batch 1) to align
    i = 0
    dl2 = DataLoader(mkds(recs), batch_size=1, shuffle=False, num_workers=0, collate_fn=collate)
    for b in dl2:
        sha = recs[i]["sha256"]
        if b is None: i += 1; continue
        cap2.clear()
        try:
            lg, _ = model(b, train_sem_predictor=False)
            sc[sha] = float(torch.softmax(lg, 1)[0, 1])
            if "v" in cap2: emb[sha] = cap2["v"][0].numpy()
        except Exception:
            if dev == "cuda": torch.cuda.empty_cache()
        i += 1
    return sc, emb
if A.smoke:
    print("[SMOKE OK] grl plumbing", flush=True); h2.remove(); sys.exit(0)
s_bb, e_bb = score_embed(bb); s_ch, e_ch = score_embed(ch)
probe_recs = train + bb + ch
_, e_tr = score_embed(train)
h2.remove()
def auc(s, y): return roc_auc_score(y, s) if len(set(y)) > 1 else float("nan")
shas = [r["sha256"] for r in bb if r["sha256"] in s_bb] + [r["sha256"] for r in ch if r["sha256"] in s_ch]
yy = np.r_[np.ones(sum(1 for r in bb if r["sha256"] in s_bb)), np.zeros(sum(1 for r in ch if r["sha256"] in s_ch))]
ss = np.array([ (s_bb.get(x) if x in s_bb else s_ch.get(x)) for x in shas], float)
cl = np.array([group_key({"sha256": x, "cluster": fc.get(x, {}).get("cluster")}) for x in shas])
# cluster bootstrap AUC
uc = np.unique(cl); rng = np.random.RandomState(SEED); idx = {c: np.where(cl == c)[0] for c in uc}; bv = []
for _ in range(2000):
    ii = np.concatenate([idx[c] for c in rng.choice(uc, len(uc), replace=True)])
    if len(set(yy[ii])) > 1: bv.append(auc(ss[ii], yy[ii]))
AUC = auc(ss, yy); ci = (float(np.percentile(bv, 2.5)), float(np.percentile(bv, 97.5)))
# ---- linear probe toolchain/family (cluster CV) on post-GRL embeddings ----
EMB = {}; EMB.update(e_tr); EMB.update(e_bb); EMB.update(e_ch)
def cv_probe(recs, labelfn, lab_space):
    rs = [r for r in recs if r["sha256"] in EMB and labelfn(r) is not None]
    X = np.array([EMB[r["sha256"]] for r in rs]); y = np.array([labelfn(r) for r in rs])
    folds = group_kfold(rs, k=5); accs = []
    for fv in folds:
        tri = [i for i, r in enumerate(rs) if r["sha256"] not in fv]; vai = [i for i, r in enumerate(rs) if r["sha256"] in fv]
        if not vai or len(set(y[tri])) < 2: continue
        scl = StandardScaler().fit(X[tri]); clf = LogisticRegression(max_iter=2000).fit(scl.transform(X[tri]), y[tri])
        accs.append((clf.predict(scl.transform(X[vai])) == y[vai]).mean())
    maj = np.bincount(y, minlength=lab_space).max() / len(y)
    return (float(np.mean(accs)) if accs else float("nan")), float(maj), len(rs)
tool_acc, tool_maj, nt = cv_probe(train + bb + ch, lambda r: binid.get(tbin(r["sha256"])), len(BINS))
fam_acc, fam_maj, nf = cv_probe([r for r in train + bb if r["label"] == 1 and r.get("source") in FAMS], lambda r: famid.get(r.get("source")), len(FAMS))
# recall@thr by bin (threshold = TPR95 on val positives scored)
sv, _ = score_embed(val); vy = {r["sha256"]: r["label"] for r in val}
valpos = [sv[s] for s in sv if vy.get(s) == 1]
thr = float(np.percentile(valpos, 5)) if valpos else 0.5
recall_bin = {}
for b in BINS:
    sub = [r for r in bb if tbin(r["sha256"]) == b and r["sha256"] in s_bb]
    if sub: recall_bin[b] = {"n": len(sub), "recall": float(np.mean([s_bb[r["sha256"]] >= thr for r in sub]))}
res = {"tag": A.tag, "seed": MS, "lambda_max": A.lambda_max, "stop": stop_reason, "best_ep": best_ep,
       "auc_bb_vs_choco": AUC, "auc_ci": ci, "thr": thr,
       "toolchain_probe_acc": tool_acc, "toolchain_majority": tool_maj, "toolchain_n": nt,
       "family_probe_acc": fam_acc, "family_majority": fam_maj, "family_n": nf,
       "recall_by_bin": recall_bin, "losses": losses, "val_loss_curve": vlc,
       "elapsed_h": (time.time()-WALL0)/3600}
json.dump(res, open(os.path.join(W, f"grl_{A.tag}.json"), "w"), indent=2)
print(f"\nRESULT {A.tag}: AUC(bb vs choco)={AUC:.3f} [{ci[0]:.3f},{ci[1]:.3f}]  "
      f"toolchain_probe={tool_acc:.3f} (maj {tool_maj:.3f})  family_probe={fam_acc:.3f} (maj {fam_maj:.3f})", flush=True)
print(f"DONE {A.tag}", flush=True)
