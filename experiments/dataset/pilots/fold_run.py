#!/usr/bin/env python
# PIPELINE CHECK / DEV RUN (NOT a result). Parametrized BumbleBee fold.
#   --model-seed N, --manifest v1|v2, --iso-cap K, --carve-val 0|1, --cosine 0|1, --tag STR
# Fixed 20 epochs (TRAINING_DESIGN section 15). Logs sha of bad/oom/dropped (task5),
# dumps per-sample scores (sha,label,score,num_functions,truncated) for bb+choco (task3).
import os, sys, json, time, random, warnings, resource, argparse
warnings.filterwarnings("ignore")
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")
os.chdir("/home/dhgia/Work/Defi/BFBG-Transformer"); sys.path.insert(0, ".")
import numpy as np, torch, torch.nn.functional as F
from torch.utils.data import DataLoader
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
from src.training.bfbg_dataset import BFBGDataset, collate
from src.training.splits import load_manifest, by_split, group_key
from src.models.bfbg_transformer import BFBGTransformer
from src.utils.path_resolver import load_config, REPO_ROOT
from collections import defaultdict

ap = argparse.ArgumentParser()
ap.add_argument("--model-seed", type=int, required=True)
ap.add_argument("--manifest", choices=["v1", "v2"], default="v1")
ap.add_argument("--iso-cap", type=int, default=0)
ap.add_argument("--carve-val", type=int, default=1)
ap.add_argument("--cosine", type=int, default=0)
ap.add_argument("--es", type=int, default=0)            # section 17 early-stopping
ap.add_argument("--max-epochs", type=int, default=40)
ap.add_argument("--min-delta", type=float, default=0.002)
ap.add_argument("--smoke", type=int, default=0)         # plumbing test, not real training
ap.add_argument("--resume", type=int, default=0)        # resume from last checkpoint
ap.add_argument("--max-hours", type=float, default=8.0) # wall-clock ceiling
ap.add_argument("--tag", default="run")
A = ap.parse_args()
WALL0 = time.time()
SPLIT_SEED = 20261008; MS = A.model_seed
random.seed(MS); np.random.seed(MS); torch.manual_seed(MS)
dev = "cuda" if torch.cuda.is_available() else "cpu"
stoi = json.load(open("data/insn_vocab_v2.json"))
if isinstance(stoi, list): stoi = {t: i for i, t in enumerate(stoi)}
vsz = len(stoi); FEAT = "data/features_graph"
MANP = os.path.join(REPO_ROOT, "docs", f"dataset_{A.manifest}_manifest.jsonl")
OUT = os.path.expanduser(f"~/bfbg_benign_work/foldrun_{A.tag}.json")

man = load_manifest(MANP); sp = by_split(man)
tp = sp["train_pool"]; bb = sp["holdout_family_bumblebee"]; ch = sp["holdout_source_chocolatey"]
nfmap = {r["sha256"]: (r.get("num_functions") or 0) for r in man}
print(f"[{A.tag}] manifest={A.manifest} seed={MS} iso_cap={A.iso_cap} cosine={A.cosine} dev={dev}", flush=True)

iso_dropped = []
if A.iso_cap > 0:
    iso = [r for r in tp if r.get("source") == "windows11-eval-iso"]
    rnd = random.Random(SPLIT_SEED); rnd.shuffle(iso)
    keep = set(r["sha256"] for r in iso[:A.iso_cap]); iso_dropped = [r["sha256"] for r in iso[A.iso_cap:]]
    tp = [r for r in tp if r.get("source") != "windows11-eval-iso" or r["sha256"] in keep]
    print(f"ISO cap: kept {min(A.iso_cap,len(iso))}/{len(iso)} dropped {len(iso_dropped)} -> train_pool {len(tp)}", flush=True)

if A.es: A.carve_val = 1  # section 17 requires a validation set
train, val = tp, []
if A.carve_val:
    groups = defaultdict(list)
    for r in tp: groups[group_key(r)].append(r)
    gl = list(groups.items()); random.Random(SPLIT_SEED).shuffle(gl)
    frac = 0.15; train = []
    while True:
        nval = 0; target = int(frac * len(tp)); val = []
        for g, recs in gl:
            if nval < target: val += recs; nval += len(recs)
        nben = sum(1 for r in val if r["label"] == 0)
        if nben >= 40 or frac >= 0.35: break
        frac += 0.05  # enlarge (cluster, same seed) until >=40 benign
    train = [r for r in tp if r["sha256"] not in set(x["sha256"] for x in val)]
    print(f"validation carve frac={frac:.2f} benign={sum(1 for r in val if r['label']==0)}", flush=True)
if A.smoke:  # plumbing test only (NOT real training): tiny data, few epochs
    train = train[:6]; val = val[:6] if val else train[:4]
print(f"train={len(train)} val={len(val)} bb={len(bb)} choco={len(ch)} (train benign={sum(1 for r in train if r['label']==0)})", flush=True)

cfg = load_config("model")["training"]; LAM = load_config("model")["semantic"]["lambda_sem"]
EP = cfg["epochs"]; LR = cfg["learning_rate"]; MF = cfg["max_functions_per_sample"]; GC = cfg["grad_clip"]
if A.es: EP = A.max_epochs
if A.smoke: EP = 4
BS = cfg["batch_size"]; MICRO = 2; ACC = max(1, BS // MICRO)
def mkds(recs): return BFBGDataset(recs, stoi, max_funcs=MF, feat_dir=FEAT)
dl = DataLoader(mkds(train), batch_size=MICRO, shuffle=True, num_workers=0, collate_fn=collate,
                generator=torch.Generator().manual_seed(MS))
model = BFBGTransformer.from_config(vsz, num_global_features=0).to(dev)
opt = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=cfg["weight_decay"])
sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=EP) if A.cosine else None
def peak_gb(): return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1e6

@torch.no_grad()
def scores(recs, fail=None):
    model.eval(); out = []
    d2 = DataLoader(mkds(recs), batch_size=1, shuffle=False, num_workers=0, collate_fn=collate)
    i = 0
    for batch in d2:
        if batch is None:
            out.append(np.nan)
            if fail is not None: fail.append([recs[i]["sha256"], "num_functions=0/collate_None"])
            i += 1; continue
        try:
            logits, _ = model(batch, train_sem_predictor=False)
            out.append(float(torch.softmax(logits, 1)[0, 1]))
        except Exception as e:
            if dev == "cuda": torch.cuda.empty_cache()
            out.append(np.nan)
            if fail is not None: fail.append([recs[i]["sha256"], type(e).__name__])
        i += 1
    return np.array(out, float)

@torch.no_grad()
def val_loss_auc(recs):
    model.eval(); tot = 0.0; n = 0; ss = []; yy = []
    d2 = DataLoader(mkds(recs), batch_size=MICRO, shuffle=False, num_workers=0, collate_fn=collate)
    for batch in d2:
        if batch is None: continue
        labels = batch["labels"].to(dev)
        try:
            logits, _ = model(batch, train_sem_predictor=False)
            if not torch.isfinite(logits).all(): continue
            tot += float(F.cross_entropy(logits, labels, reduction="sum")); n += len(labels)
            ss += torch.softmax(logits, 1)[:, 1].cpu().tolist(); yy += labels.cpu().tolist()
        except Exception:
            if dev == "cuda": torch.cuda.empty_cache()
    vl = tot / max(n, 1)
    va = roc_auc_score(yy, ss) if len(set(yy)) > 1 else float("nan")
    return vl, va

CKPT = os.path.expanduser(f"~/bfbg_benign_work/ckpt_{A.tag}.pt")        # best (by val_loss) — primary
CKPT_A = os.path.expanduser(f"~/bfbg_benign_work/ckpt_{A.tag}_vauc.pt") # best (by val_auc) — secondary
LAST = os.path.expanduser(f"~/bfbg_benign_work/ckpt_{A.tag}_last.pt")   # last (every epoch, for --resume)
# section 17 early-stopping state
best_vl = float("inf"); best_ep = -1; no_improve = 0; lr_cuts = 0; stop_reason = "max_epochs"
best_vauc = -1.0; best_vauc_ep = -1
val_y = np.array([r["label"] for r in val]) if val else None
val_curve = []; val_loss_curve = []; losses = []; fail_train = []; fail_oom = []
start_ep = 0
if A.resume and os.path.exists(LAST):
    st = torch.load(LAST, map_location=dev)
    model.load_state_dict(st["model"]); opt.load_state_dict(st["opt"])
    best_vl = st["best_vl"]; best_ep = st["best_ep"]; no_improve = st["no_improve"]; lr_cuts = st["lr_cuts"]
    losses = st["losses"]; val_curve = st["val_curve"]; val_loss_curve = st["val_loss_curve"]; start_ep = st["epoch"] + 1
    print(f"RESUME from ep{start_ep} (best_ep{best_ep} best_vl={best_vl:.4f} no_improve={no_improve} lr_cuts={lr_cuts})", flush=True)
for ep in range(start_ep, EP):
    model.train(); t0 = time.time(); tl = 0.0; nb = 0; bad = 0; oom = 0
    opt.zero_grad(); acc_i = 0
    for batch in dl:
        if batch is None: continue
        labels = batch["labels"].to(dev); shas = [m["sha256"] for m in batch["metas"]]
        try:
            logits, sem = model(batch, train_sem_predictor=True)
            if not torch.isfinite(logits).all():
                bad += 1; fail_train.append([ep, shas, "nonfinite"]); continue
            loss = (F.cross_entropy(logits, labels) + LAM * sem) / ACC
            loss.backward(); acc_i += 1; tl += float(loss) * ACC; nb += 1
            if acc_i == ACC:
                torch.nn.utils.clip_grad_norm_(model.parameters(), GC); opt.step(); opt.zero_grad(); acc_i = 0
        except torch.cuda.OutOfMemoryError:
            oom += 1; fail_oom.append([ep, shas]); opt.zero_grad(); acc_i = 0
            if dev == "cuda": torch.cuda.empty_cache()
        except Exception as e:
            bad += 1; fail_train.append([ep, shas, type(e).__name__])
    if acc_i: torch.nn.utils.clip_grad_norm_(model.parameters(), GC); opt.step(); opt.zero_grad()
    if sched: sched.step()
    if val:
        vl, vauc = val_loss_auc(val)
    else:
        vl = float("nan"); vauc = float("nan")
    val_curve.append(vauc); val_loss_curve.append(vl); losses.append(tl/max(nb, 1))
    pk = torch.cuda.max_memory_allocated()/1e9 if dev == "cuda" else 0.0
    lr_now = opt.param_groups[0]["lr"]
    gtemp = os.popen("nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader 2>/dev/null").read().strip() if dev == "cuda" else "NA"
    # section 17 early-stopping bookkeeping
    es_note = ""
    if A.es and val and vauc == vauc and vauc > best_vauc:   # track peak val-AUC checkpoint (secondary)
        best_vauc = vauc; best_vauc_ep = ep; torch.save(model.state_dict(), CKPT_A)
    if A.es:
        if vl < best_vl - A.min_delta:
            best_vl = vl; best_ep = ep; no_improve = 0; torch.save(model.state_dict(), CKPT); es_note = "*best"
        else:
            no_improve += 1
            if no_improve % 5 == 0 and lr_cuts < 2:
                for g in opt.param_groups: g["lr"] *= 0.5
                lr_cuts += 1; es_note = f"lr_halved(#{lr_cuts})"
    print(f"epoch {ep:2d}: tr_loss={losses[-1]:.4f} val_loss={vl:.4f} val_auc={vauc:.4f} lr={lr_now:.2e} "
          f"no_improve={no_improve} lr_cuts={lr_cuts} GPU={gtemp}C nb={nb} bad={bad} oom={oom} t={time.time()-t0:.0f}s VRAM={pk:.2f}GB {es_note}", flush=True)
    # last checkpoint EVERY epoch (model+opt+lr+counters+epoch+curves) for --resume
    torch.save({"model": model.state_dict(), "opt": opt.state_dict(), "epoch": ep,
                "best_vl": best_vl, "best_ep": best_ep, "no_improve": no_improve, "lr_cuts": lr_cuts,
                "losses": losses, "val_curve": val_curve, "val_loss_curve": val_loss_curve}, LAST)
    if A.es and no_improve >= 10:
        stop_reason = f"early_stop@ep{ep}(no_improve>=10)"; print(f"EARLY STOP: {stop_reason}, reloading best ep{best_ep}", flush=True); break
    if time.time() - WALL0 > A.max_hours * 3600:
        stop_reason = f"wall_clock@ep{ep}(>{A.max_hours}h)"; print(f"WALL-CLOCK CEILING hit: {stop_reason}, reloading best ep{best_ep}", flush=True); break
if A.es and os.path.exists(CKPT):
    model.load_state_dict(torch.load(CKPT)); print(f"reloaded best checkpoint ep{best_ep} val_loss={best_vl:.4f}", flush=True)

if A.smoke:
    print(f"[SMOKE OK] epochs_ran={len(losses)} stop_reason={stop_reason} best_ep={best_ep} "
          f"best_val_loss={None if best_vl==float('inf') else round(best_vl,4)} lr_cuts={lr_cuts} "
          f"ckpt_exists={os.path.exists(CKPT)} val_loss_curve={['%.3f'%x for x in val_loss_curve]}", flush=True)
    print("DONE smoke (plumbing only, NOT training)", flush=True); sys.exit(0)

fail_eval = []
s_bb = scores(bb, fail_eval); s_ch = scores(ch, fail_eval)
# per-sample dump (task3)
per_sample = []
for r, s in list(zip(bb, s_bb)) + list(zip(ch, s_ch)):
    nfv = nfmap.get(r["sha256"], 0)
    per_sample.append({"sha": r["sha256"], "label": r["label"], "score": None if s != s else float(s),
                       "num_functions": nfv, "truncated": int(nfv > MF)})

fc = {json.loads(l)["sha256"]: json.loads(l) for l in open(os.path.expanduser("~/bfbg_benign_work/feat_cache.jsonl"))}
def feats(recs, which):
    X, keep = [], []
    for r in recs:
        d = fc.get(r["sha256"])
        if d is None: keep.append(False); continue
        X.append(d[which]); keep.append(True)
    return np.array(X, float), np.array(keep)
pr = {}
for which in ("meta", "graph"):
    Xtr, ktr = feats(train, which); ytr = np.array([r["label"] for r in train])[ktr]
    clf = RandomForestClassifier(n_estimators=300, random_state=42, n_jobs=-1, class_weight="balanced").fit(Xtr, ytr)
    sbb = np.full(len(bb), np.nan); sch = np.full(len(ch), np.nan)
    Xbb, kbb = feats(bb, which); Xch, kch = feats(ch, which)
    sbb[kbb] = clf.predict_proba(Xbb)[:, 1]; sch[kch] = clf.predict_proba(Xch)[:, 1]
    pr[which] = (sbb, sch)

y = np.r_[np.ones(len(bb)), np.zeros(len(ch))]
cl = np.array([group_key(r) for r in bb] + [group_key(r) for r in ch])
S = {"BFBG": np.r_[s_bb, s_ch], "metadata": np.r_[pr["meta"][0], pr["meta"][1]], "graph": np.r_[pr["graph"][0], pr["graph"][1]]}
valid = np.all([np.isfinite(S[k]) for k in S], axis=0)
yv = y[valid]; clv = cl[valid]; Sv = {k: S[k][valid] for k in S}
def auc(s, yy): return roc_auc_score(yy, s) if len(set(yy)) > 1 else float("nan")
def cboot(fn, n=2000):
    uc = np.unique(clv); rng = np.random.RandomState(SPLIT_SEED); idx = {c: np.where(clv == c)[0] for c in uc}; v = []
    for _ in range(n):
        ii = np.concatenate([idx[c] for c in rng.choice(uc, len(uc), replace=True)])
        try: v.append(fn(ii))
        except Exception: pass
    v = np.array([x for x in v if np.isfinite(x)]); return float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))

R = {"tag": A.tag, "manifest": A.manifest, "model_seed": MS, "iso_cap": A.iso_cap, "cosine": A.cosine,
     "es": A.es, "max_epochs": A.max_epochs, "epochs_ran": len(losses), "stop_reason": stop_reason,
     "best_ep": best_ep, "best_val_loss": (None if best_vl == float("inf") else best_vl), "lr_cuts": lr_cuts,
     "val_loss_curve": val_loss_curve,
     "train_n": len(train), "val_n": len(val), "usable": int(valid.sum()), "prevalence": float((yv == 1).mean()),
     "losses": losses, "val_curve": val_curve, "iso_dropped": iso_dropped,
     "fail_train": fail_train, "fail_oom": fail_oom, "fail_eval": fail_eval,
     "per_sample": per_sample, "auc": {}, "diff": {}, "recall_at_fpr": {}}
print(f"\n[{A.tag}] usable={valid.sum()}/{len(y)} prevalence={R['prevalence']:.3f}", flush=True)
for k in ("BFBG", "graph", "metadata"):
    a = auc(Sv[k], yv); lo, hi = cboot(lambda ii: auc(Sv[k][ii], yv[ii]))
    R["auc"][k] = [a, lo, hi]; print(f"  AUC {k:9s}={a:.3f} [{lo:.3f},{hi:.3f}]", flush=True)
for o in ("graph", "metadata"):
    d = auc(Sv["BFBG"], yv) - auc(Sv[o], yv); lo, hi = cboot(lambda ii: auc(Sv["BFBG"][ii], yv[ii]) - auc(Sv[o][ii], yv[ii]))
    R["diff"][f"BFBG-{o}"] = [d, lo, hi]; print(f"  dAUC BFBG-{o:9s}={d:+.3f} [{lo:+.3f},{hi:+.3f}]", flush=True)
cm = yv == 0; bm = yv == 1
for fpr in (0.01, 0.05, 0.10):
    row = {}
    for k in ("BFBG", "graph", "metadata"):
        thr = np.quantile(np.sort(Sv[k][cm]), 1 - fpr); row[k] = float((Sv[k][bm] >= thr).mean())
    R["recall_at_fpr"][str(fpr)] = row
    print(f"  recall@FPR{int(fpr*100)}%: BFBG={row['BFBG']*100:.1f} graph={row['graph']*100:.1f} metadata={row['metadata']*100:.1f}", flush=True)
# task3: BFBG AUC truncated vs non-truncated (per-sample)
ps = [p for p in per_sample if p["score"] is not None]
for grp, name in ((1, "truncated"), (0, "non-truncated")):
    sub = [p for p in ps if p["truncated"] == grp]
    yy = np.array([p["label"] for p in sub]); ss = np.array([p["score"] for p in sub])
    a = auc(ss, yy) if len(set(yy)) > 1 else float("nan")
    R.setdefault("trunc_auc", {})[name] = [a, int((yy == 1).sum()), int((yy == 0).sum())]
    print(f"  BFBG AUC {name:14s}: {a:.3f}  (mal={int((yy==1).sum())} ben={int((yy==0).sum())})", flush=True)
print(f"  val_fin={val_curve[-1]} val_max={max([x for x in val_curve if x==x], default=float('nan'))} loss_fin={losses[-1]:.3f}", flush=True)
print(f"  best_val_loss_ep={best_ep}(vl={None if best_vl==float('inf') else round(best_vl,4)}) peak_val_auc_ep={best_vauc_ep}(va={best_vauc:.4f})", flush=True)

# SECONDARY: metrics at peak val-AUC checkpoint (model currently holds best val_loss ckpt)
if A.es and os.path.exists(CKPT_A):
    print("\n----- SECONDARY: at peak val-AUC checkpoint -----", flush=True)
    model.load_state_dict(torch.load(CKPT_A, map_location=dev))
    sb2 = np.r_[scores(bb), scores(ch)]
    v2 = np.isfinite(sb2) & np.isfinite(S["graph"]) & np.isfinite(S["metadata"])
    y2 = y[v2]; cl2 = cl[v2]; B2 = sb2[v2]; G2 = S["graph"][v2]; M2 = S["metadata"][v2]
    def cb2(fn, n=2000):
        uc = np.unique(cl2); rng = np.random.RandomState(SPLIT_SEED); idx = {c: np.where(cl2 == c)[0] for c in uc}; vv = []
        for _ in range(n):
            ii = np.concatenate([idx[c] for c in rng.choice(uc, len(uc), replace=True)])
            try: vv.append(fn(ii))
            except Exception: pass
        vv = np.array([x for x in vv if np.isfinite(x)]); return float(np.percentile(vv, 2.5)), float(np.percentile(vv, 97.5))
    aB = auc(B2, y2); lo, hi = cb2(lambda ii: auc(B2[ii], y2[ii]))
    dG = aB - auc(G2, y2); dglo, dghi = cb2(lambda ii: auc(B2[ii], y2[ii]) - auc(G2[ii], y2[ii]))
    dM = aB - auc(M2, y2); dmlo, dmhi = cb2(lambda ii: auc(B2[ii], y2[ii]) - auc(M2[ii], y2[ii]))
    sec = {"auc_BFBG": [aB, lo, hi], "dAUC_graph": [dG, dglo, dghi], "dAUC_metadata": [dM, dmlo, dmhi], "recall_at_fpr": {}}
    print(f"  AUC BFBG(peak-vauc)={aB:.3f} [{lo:.3f},{hi:.3f}]  dAUC-graph={dG:+.3f} [{dglo:+.3f},{dghi:+.3f}]  dAUC-metadata={dM:+.3f} [{dmlo:+.3f},{dmhi:+.3f}]", flush=True)
    bm2 = y2 == 1; cmk2 = y2 == 0
    for fpr in (0.01, 0.05, 0.10):
        thr = np.quantile(np.sort(B2[cmk2]), 1 - fpr); rec = float((B2[bm2] >= thr).mean()); sec["recall_at_fpr"][str(fpr)] = rec
        print(f"  recall@FPR{int(fpr*100)}%(peak-vauc)={rec*100:.1f}", flush=True)
    R["secondary_peak_vauc"] = sec
    R["best_val_loss_ep"] = best_ep; R["peak_val_auc_ep"] = best_vauc_ep; R["peak_val_auc"] = best_vauc

print(f"  fail_oom={[[e,len(s)] for e,s in fail_oom]} fail_eval={fail_eval}", flush=True)
json.dump(R, open(OUT, "w")); print(f"DONE {A.tag}", flush=True)
