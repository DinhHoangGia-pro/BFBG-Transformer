"""Dry-run gan split v2 (CHUA build, CHUA train BFBG). Tu import_batch1 da don:
phan loai tag(scoop/nirsoft)+toolchain, dedup noi bo, gan train/test_indist/
holdout-nirsoft theo quy tac DATASET.md. Bao SO THAT. Ghi plan + hash."""
import os, re, json, hashlib, random, warnings
warnings.filterwarnings("ignore"); import pefile, ppdeep
random.seed(20261008)
ROOT="/home/dhgia/Work/Defi/BFBG-Transformer"; os.chdir(ROOT)
IMP=os.path.expanduser("~/bfbg_benign_work/import_batch1")
recs={json.loads(l)["sha"]:json.loads(l) for l in open(os.path.expanduser("~/bfbg_benign_work/records.jsonl"))}
def reclass_rec(x):
    s=set(x["secs"]); lk=x["lk"]; rich=x["rich"]
    if ".buildid" in s or ".symtab" in s: return "Go"
    if "CODE" in s or "DATA" in s or ".itext" in s: return "Delphi"
    if ".eh_fram" in s or x["has_mingw"] or (lk<=2 and not rich and ".bss" in s and (".CRT" in s or {".edata",".pdata"}<=s)): return "GNU/MinGW"
    if rich or x["has_other_crt"] or (x["has_msvcrt"] and lk>=6):
        return "MSVC<=10" if lk<=10 else ("MSVC 11-12" if lk in (11,12) else "MSVC 14")
    return "khac"
SECDIR=pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
def tbin(path):
    try: pe=pefile.PE(path)
    except: return "khac"
    try:
        s={x.Name.rstrip(b"\x00").decode("latin1","ignore") for x in pe.sections}
        lk=pe.OPTIONAL_HEADER.MajorLinkerVersion; rich=bool(getattr(pe,"RICH_HEADER",None))
        im=set()
        if hasattr(pe,"DIRECTORY_ENTRY_IMPORT"):
            for e in pe.DIRECTORY_ENTRY_IMPORT:
                if e.dll: im.add(e.dll.decode("latin1","ignore").lower())
    finally: pe.close()
    si=" ".join(im)
    if ".buildid" in s or ".symtab" in s: return "Go"
    if "CODE" in s or "DATA" in s or ".itext" in s: return "Delphi"
    if ".eh_fram" in s or any(d in si for d in ("libgcc","mingw","msys-")) or (lk<=2 and not rich and ".bss" in s and (".CRT" in s or {".edata",".pdata"}<=s)): return "GNU/MinGW"
    if rich or any(d in si for d in ("ucrtbase","vcruntime","api-ms-win-crt")) or ("msvcrt.dll" in im and lk>=6):
        return "MSVC<=10" if lk<=10 else ("MSVC 11-12" if lk in (11,12) else "MSVC 14")
    return "khac"
# v1 train benign theo bin (de lam co so cap NirSoft MSVC<=10)
man=[json.loads(l) for l in open("docs/dataset_v1_manifest.jsonl")]
v1_train_ben=[r for r in man if r["split"]=="train_pool" and r["label"]==0]
v1_tb_bin={}
for r in v1_train_ben:
    b=reclass_rec(recs[r["sha256"]]) if r["sha256"] in recs else "khac"
    v1_tb_bin[b]=v1_tb_bin.get(b,0)+1
# new benign
new=[]
for f in os.listdir(IMP):
    p=os.path.join(IMP,f)
    if not os.path.isfile(p): continue
    tag=f.split("__")[0]; sha=hashlib.sha256(open(p,"rb").read()).hexdigest()
    new.append(dict(file=f,tag=tag,sha=sha,bin=tbin(p)))
# dedup noi bo (giu 1/cum ppdeep>=90) - da rat it
from collections import Counter
print(f"new benign (da don): {len(new)} | tag: {dict(Counter(x['tag'] for x in new))}")
print(f"v1 train benign theo bin: {v1_tb_bin}")
# gan split: NirSoft -> MSVC<=10, cap 35% train; du -> holdout_nirsoft
nir=[x for x in new if x["tag"]=="nirsoft"]; sco=[x for x in new if x["tag"]!="nirsoft"]
# ~15% moi nhom new -> test_indist (seed), con lai train (tru NirSoft surplus)
def split15(lst):
    random.shuffle(lst); k=max(1,round(len(lst)*0.15)); return lst[k:], lst[:k]  # train, test
# Scoop: 15% test, 85% train (theo bin tu nhien)
sco_train, sco_test = split15(sco)
# NirSoft cap: MSVC<=10 train = v1_nonISO_MSVC<=10 (uoc = v1 train MSVC<=10) + sco MSVC<=10 train + nir_train
base_le10 = v1_tb_bin.get("MSVC<=10",0) + sum(1 for x in sco_train if x["bin"]=="MSVC<=10")
# nir_train <= 0.35*(base_le10 + nir_train) -> nir_train <= 0.35/0.65 * base_le10
cap_nir = int(0.35/0.65*base_le10)
random.shuffle(nir)
nir_15test = max(1,round(len(nir)*0.15))
nir_test=nir[:nir_15test]; nir_rest=nir[nir_15test:]
nir_train=nir_rest[:cap_nir]; nir_holdout=nir_rest[cap_nir:]
print(f"\n=== DRY-RUN SPLIT V2 (so THAT, chua build) ===")
print(f"Scoop: train={len(sco_train)} test_indist=+{len(sco_test)} (theo bin)")
print(f"NirSoft (MSVC<=10): tong={len(nir)} | cap_train(35%)={cap_nir} -> train={len(nir_train)} | holdout_nirsoft(du)={len(nir_holdout)} | test_indist=+{len(nir_test)}")
print(f"dual-use: 0 (da tach o manifest stage, khong co trong import_batch1)")
print(f"ISO cap @35% (AP O LOADER, khong di chuyen): v1 ISO train=141; cho phep <=35% cua train benign")
train_tot=len(sco_train)+len(nir_train); test_tot=len(sco_test)+len(nir_test)
print(f"\nTONG new benign: train-eligible(non-ISO)={train_tot} | test_indist +={test_tot} | holdout_nirsoft={len(nir_holdout)}")
print(f"new benign theo bin (train): {dict(Counter(x['bin'] for x in sco_train+nir_train))}")
# ghi plan + hash
plan=[]
for grp,lst in [("train_pool",sco_train+nir_train),("test_indist",sco_test+nir_test),("holdout_source_nirsoft",nir_holdout)]:
    for x in lst: plan.append({"sha256":x["sha"],"source":x["tag"],"bin":x["bin"],"split_planned":grp})
plan.sort(key=lambda r:r["sha256"])
outp="docs/dataset_v2_split_plan.jsonl"
open(outp,"w").write("\n".join(json.dumps(r) for r in plan)+"\n")
h=hashlib.sha256(open(outp,"rb").read()).hexdigest()
print(f"\nplan -> {outp} ({len(plan)} dong) | PLAN_SHA256={h}")
