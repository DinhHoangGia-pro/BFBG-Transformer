import os, sys, json, hashlib
from collections import Counter
os.chdir("/home/dhgia/Work/Defi/BFBG-Transformer"); sys.path.insert(0,".")
from src.training.splits import load_manifest, by_split
tr = by_split(load_manifest())["train_pool"]
feat="data/features_graph"
cnt=Counter()
for r in tr:
    fp=os.path.join(feat, r["sha256"]+"_static.json")
    if not os.path.exists(fp): continue
    d=json.load(open(fp))
    for g in d["intra_procedural_graphs"].values():
        for n in g["nodes"]:
            cnt[n.get("token") or "<UNK>"]+=1
# itos: <UNK>=0 roi token theo tan suat giam dan (on dinh: tie-break alpha)
toks=[t for t in cnt if t!="<UNK>"]
itos=["<UNK>"]+sorted(toks, key=lambda t:(-cnt[t], t))
out="data/insn_vocab_v2.json"
json.dump(itos, open(out,"w"))
h=hashlib.sha256(open(out,"rb").read()).hexdigest()
print(f"train_pool mau quet: {sum(1 for r in tr if os.path.exists(os.path.join(feat,r['sha256']+'_static.json')))}")
print(f"vocab size (insn, tu train_pool): {len(itos)}")
print(f"token pho bien nhat: {[t for t in itos[1:11]]}")
print(f"file: {out}")
print(f"VOCAB_SHA256: {h}")
