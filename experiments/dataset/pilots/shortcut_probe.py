import os, json, pickle, warnings
warnings.filterwarnings("ignore")
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score
d = pickle.load(open(os.path.expanduser("~/bfbg_benign_work/smoke_emb.pkl"), "rb"))
emb = np.array(d["emb"], float); metas = d["metas"]
recs = {json.loads(l)["sha256"]: json.loads(l) for l in open(os.path.expanduser("~/bfbg_benign_work/records.jsonl"))}
def reclass(x):
    s=set(x["secs"]); lk=x["lk"]; rich=x["rich"]
    if ".buildid" in s or ".symtab" in s: return "Go"
    if "CODE" in s or "DATA" in s or ".itext" in s: return "Delphi"
    if ".eh_fram" in s or x["has_mingw"] or (lk<=2 and not rich and ".bss" in s and (".CRT" in s or {".edata",".pdata"}<=s)): return "GNU/MinGW"
    if rich or x["has_other_crt"] or (x["has_msvcrt"] and lk>=6):
        return "MSVC<=10" if lk<=10 else ("MSVC 11-12" if lk in (11,12) else "MSVC 14")
    return "khac"
print("=== TASK 4: shortcut probe tren embedding smoke (THAM DO, model 3-epoch) ===")
print(f"n embeddings={len(emb)} dim={emb.shape[1] if len(emb) else 0}")
# bin
ybin=[]; keep=[]
for i,m in enumerate(metas):
    r=recs.get(m["sha256"])
    if r: ybin.append(reclass(r)); keep.append(i)
Xb=emb[keep]; ybin=np.array(ybin)
from collections import Counter
cb=Counter(ybin); maj=max(cb.values())/len(ybin)
# gop bin hiem
if len(emb)>=20 and len(set(ybin))>1:
    acc=cross_val_score(LogisticRegression(max_iter=1000,class_weight="balanced"), Xb, ybin, cv=3, scoring="accuracy")
    print(f"toolchain-bin: 3-fold acc={acc.mean():.3f}±{acc.std():.3f} | majority={maj:.3f} | phan bo={dict(cb)}")
# family (malicious only)
yf=[]; keepf=[]
for i,m in enumerate(metas):
    if m["label"]==1: yf.append(m["source"]); keepf.append(i)
if keepf:
    Xf=emb[keepf]; yf=np.array(yf); cf=Counter(yf); mf=max(cf.values())/len(yf)
    if len(set(yf))>1 and len(yf)>=20:
        accf=cross_val_score(LogisticRegression(max_iter=1000,class_weight="balanced"), Xf, yf, cv=3, scoring="accuracy")
        print(f"family (malicious n={len(yf)}): 3-fold acc={accf.mean():.3f}±{accf.std():.3f} | majority={mf:.3f} | phan bo={dict(cf)}")
    else:
        print(f"family: khong du lop/mau (n={len(yf)}, lop={dict(cf)})")
print("NOTE: embedding tu model smoke 3-epoch + vocab insn tu data -> chi THAM DO shortcut, khong phai ket qua.")
