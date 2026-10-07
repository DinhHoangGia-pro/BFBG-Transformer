import os, sys, json, time, random, glob, warnings
warnings.filterwarnings("ignore")
os.chdir("/home/dhgia/Work/Defi/BFBG-Transformer"); sys.path.insert(0, ".")
import torch, torch.nn.functional as F
from torch.utils.data import DataLoader
from src.training.bfbg_dataset import BFBGDataset, collate
from src.training.splits import load_manifest, by_split
from src.models.bfbg_transformer import BFBGTransformer
from src.utils.path_resolver import load_config, get_path

dev = "cuda" if torch.cuda.is_available() else "cpu"
man = load_manifest(); tr = by_split(man)["train_pool"]
random.seed(42); random.shuffle(tr); subset = tr[:400]
feat_dir = os.path.join(os.path.dirname(get_path("vex_vocab")), "features_graph")

# vex_vocab.json la VEX-mode nhung node.token la INSN-mode -> UNK 100%.
# Cho SMOKE: build vocab INSN tu chinh du lieu de token co nghia.
toks = set()
for r in subset[:200]:
    fp = os.path.join(feat_dir, r["sha256"] + "_static.json")
    if not os.path.exists(fp): continue
    d = json.load(open(fp))
    for g in list(d["intra_procedural_graphs"].values())[:100]:
        for n in g["nodes"]:
            toks.add(n.get("token") or "<UNK>")
itos = ["<UNK>"] + sorted(t for t in toks if t != "<UNK>")
stoi = {t: i for i, t in enumerate(itos)}; vsz = len(itos)
print("INSN vocab built from data: size=%d device=%s" % (vsz, dev), flush=True)

ds = BFBGDataset(subset, stoi, max_funcs=100, feat_dir=feat_dir)
unk = tot = 0
for i in range(10):
    for fd in ds[i]["func_data"]:
        tot += fd.x.numel(); unk += int((fd.x == 0).sum())
print("UNK rate (10 mau, insn-vocab): %d/%d = %.1f%%" % (unk, tot, unk/max(tot,1)*100), flush=True)

dl = DataLoader(ds, batch_size=2, shuffle=True, num_workers=2, collate_fn=collate)
mcfg = load_config("model")
model = BFBGTransformer.from_config(vsz, num_global_features=0).to(dev)
lr = mcfg["training"]["learning_rate"]; lam = mcfg["semantic"]["lambda_sem"]
opt = torch.optim.Adam(model.parameters(), lr=lr)
print("params=%.2fM lr=%s lambda_sem=%s" % (sum(p.numel() for p in model.parameters())/1e6, lr, lam), flush=True)

model.train()
for ep in range(3):
    t0 = time.time(); tl = 0.0; nb = 0; bad = 0
    for batch in dl:
        if batch is None: continue
        labels = batch["labels"].to(dev)
        opt.zero_grad()
        try:
            logits, sem = model(batch, train_sem_predictor=True)
        except Exception as e:
            bad += 1; continue
        if not torch.isfinite(logits).all(): bad += 1; continue
        loss = F.cross_entropy(logits, labels) + lam * sem
        loss.backward(); opt.step()
        tl += float(loss); nb += 1
    print("epoch %d: loss=%.4f batches=%d bad=%d time=%.1fs" % (ep, tl/max(nb,1), nb, bad, time.time()-t0), flush=True)

# capture embedding (input fc1 = pooled_program vi global=0)
cap = {}
def hook(m, inp): cap["v"] = inp[0].detach().cpu()
h = model.fc1.register_forward_pre_hook(hook)
model.eval(); emb = []; metas = []
dl2 = DataLoader(ds, batch_size=2, shuffle=False, num_workers=2, collate_fn=collate)
with torch.no_grad():
    for batch in dl2:
        if batch is None: continue
        cap.clear()
        try: model(batch, train_sem_predictor=False)
        except Exception: continue
        if "v" in cap:
            for j, mt in enumerate(batch["metas"]):
                emb.append(cap["v"][j].tolist()); metas.append(mt)
h.remove()
import pickle
pickle.dump({"emb": emb, "metas": metas}, open(os.path.expanduser("~/bfbg_benign_work/smoke_emb.pkl"), "wb"))
print("captured embeddings: %d (dim=%d)" % (len(emb), len(emb[0]) if emb else 0), flush=True)
print("DONE smoke", flush=True)
