"""Dry-run split v2 (CHUA build/train). Tu import_batch1 da don: loai .NET
(out-of-scope), phan loai tag+toolchain, cap NirSoft<=35% MSVC<=10 train,
cap GNU/Go/Rust<=10% benign train (du -> holdout), ~15% test_indist. So THAT."""
import os, re, json, hashlib, random, warnings
warnings.filterwarnings("ignore"); import pefile
random.seed(20261008)
ROOT="/home/dhgia/Work/Defi/BFBG-Transformer"; os.chdir(ROOT)
IMP=os.path.expanduser("~/bfbg_benign_work/import_batch1")
recs={json.loads(l)["sha"]:json.loads(l) for l in open(os.path.expanduser("~/bfbg_benign_work/records.jsonl"))}
COM=pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']
def analyze(p):
    try: pe=pefile.PE(p)
    except: return None
    try:
        dd=pe.OPTIONAL_HEADER.DATA_DIRECTORY
        dotnet = COM<len(dd) and dd[COM].Size>0 and dd[COM].VirtualAddress!=0
        s={x.Name.rstrip(b'\x00').decode('latin1','ignore') for x in pe.sections}
        lk=pe.OPTIONAL_HEADER.MajorLinkerVersion; rich=bool(getattr(pe,'RICH_HEADER',None))
        im=set()
        if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
            for e in pe.DIRECTORY_ENTRY_IMPORT:
                if e.dll: im.add(e.dll.decode('latin1','ignore').lower())
    finally: pe.close()
    si=' '.join(im)
    if dotnet: b="dotnet"
    elif '.buildid' in s or '.symtab' in s: b="Go"
    elif 'CODE' in s or 'DATA' in s or '.itext' in s: b="Delphi"
    elif '.eh_fram' in s or any(d in si for d in ('libgcc','mingw','msys-')) or (lk<=2 and not rich and '.bss' in s and ('.CRT' in s or {'.edata','.pdata'}<=s)): b="GNU/MinGW"
    elif rich or any(d in si for d in ('ucrtbase','vcruntime','api-ms-win-crt')) or ('msvcrt.dll' in im and lk>=6):
        b="MSVC<=10" if lk<=10 else ("MSVC 11-12" if lk in (11,12) else "MSVC 14")
    else: b="khac"
    return b
def rc(x):
    s=set(x["secs"]);lk=x["lk"];rich=x["rich"]
    if ".eh_fram" in s or x["has_mingw"] or (lk<=2 and not rich and ".bss" in s and (".CRT" in s or {".edata",".pdata"}<=s)): return "GNU/MinGW"
    if rich or x["has_other_crt"] or (x["has_msvcrt"] and lk>=6):
        return "MSVC<=10" if lk<=10 else ("MSVC 11-12" if lk in (11,12) else "MSVC 14")
    return "khac"
man=[json.loads(l) for l in open("docs/dataset_v1_manifest.jsonl")]
v1tb=[r for r in man if r["split"]=="train_pool" and r["label"]==0]
v1bin={}
for r in v1tb:
    b=rc(recs[r["sha256"]]) if r["sha256"] in recs else "khac"; v1bin[b]=v1bin.get(b,0)+1
new=[]; dotnet=0
for f in os.listdir(IMP):
    p=os.path.join(IMP,f)
    if not os.path.isfile(p): continue
    b=analyze(p)
    if b is None: continue
    if b=="dotnet": dotnet+=1; continue   # OUT-OF-SCOPE
    new.append(dict(tag=f.split("__")[0], sha=hashlib.sha256(open(p,'rb').read()).hexdigest(), bin=b))
from collections import Counter
print(f".NET loai (out-of-scope): {dotnet} | new native con lai: {len(new)}")
print(f"new theo nguon x bin: scoop={dict(Counter(x['bin'] for x in new if x['tag']=='scoop'))} nirsoft={dict(Counter(x['bin'] for x in new if x['tag']=='nirsoft'))}")
nir=[x for x in new if x["tag"]=="nirsoft"]; sco=[x for x in new if x["tag"]!="nirsoft"]
def s15(lst): random.shuffle(lst); k=max(1,round(len(lst)*0.15)); return lst[k:],lst[:k]
sco_tr,sco_te=s15(sco)
base_le10=v1bin.get("MSVC<=10",0)+sum(1 for x in sco_tr if x["bin"]=="MSVC<=10")
cap_nir=int(0.35/0.65*base_le10); random.shuffle(nir)
k=max(1,round(len(nir)*0.15)); nir_te=nir[:k]; rest=nir[k:]; nir_tr=rest[:cap_nir]; nir_ho=rest[cap_nir:]
# cap GNU/Go/Rust <=10% benign train
train=sco_tr+nir_tr
v1_ggr=v1bin.get("GNU/MinGW",0)+v1bin.get("Go",0)
def is_ggr(b): return b in ("GNU/MinGW","Go","Rust")
# tong train benign tam thoi
base_train=len(v1tb)+len(train)
ggr=[x for x in train if is_ggr(x["bin"])]; nonggr=[x for x in train if not is_ggr(x["bin"])]
cap_ggr=max(0,int(0.10*(len(v1tb)+len(nonggr))/0.90)-v1_ggr)  # (v1_ggr+new_ggr)<=10%*total
random.shuffle(ggr); ggr_tr=ggr[:cap_ggr]; ggr_ho=ggr[cap_ggr:]
train=nonggr+ggr_tr
print(f"\n=== DRY-RUN V2 (sau loai .NET + cap) ===")
print(f"train-eligible non-ISO = {len(train)} (scoop {sum(1 for x in train if x['tag']=='scoop')} + nirsoft {len(nir_tr)})")
print(f"test_indist += {len(sco_te)+len(nir_te)}")
print(f"holdout_source_nirsoft (NirSoft du) = {len(nir_ho)}")
print(f"holdout GNU/Go/Rust (du >10% cap) = {len(ggr_ho)} | GNU/Go train giu = {len(ggr_tr)} (cap {cap_ggr}, v1 da co {v1_ggr})")
print(f"dual-use = 0")
print(f"NirSoft trong MSVC<=10 train = {len(nir_tr)} | non-NirSoft MSVC<=10 train = {v1bin.get('MSVC<=10',0)}(v1)+{sum(1 for x in sco_tr if x['bin']=='MSVC<=10')}(scoop)")
print(f"train benign theo bin: {dict(Counter(x['bin'] for x in train))}")
# plan + hash
plan=[]
for grp,lst in [("train_pool",train),("test_indist",sco_te+nir_te),("holdout_source_nirsoft",nir_ho),("holdout_lowfreq_toolchain",ggr_ho)]:
    for x in lst: plan.append({"sha256":x["sha"],"source":x["tag"],"bin":x["bin"],"split_planned":grp})
plan.sort(key=lambda r:r["sha256"])
open("docs/dataset_v2_split_plan.jsonl","w").write("\n".join(json.dumps(r) for r in plan)+"\n")
h=hashlib.sha256(open("docs/dataset_v2_split_plan.jsonl","rb").read()).hexdigest()
print(f"\nplan: {len(plan)} dong | PLAN_SHA256_MOI={h}")
