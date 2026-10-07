"""Sinh manifest v2 THAT: v1 bat bien + benign dot1 BUILT (chi mau build duoc),
split theo plan 7f33cfc2; mau roi (fail) loai. cluster: ppdeep>=90 noi bo (hiem).
Bao delta plan-vs-built. CHUA train BFBG."""
import os, json, glob, hashlib, warnings
warnings.filterwarnings("ignore"); import ppdeep
ROOT="/home/dhgia/Work/Defi/BFBG-Transformer"; os.chdir(ROOT)
v1=[json.loads(l) for l in open("docs/dataset_v1_manifest.jsonl")]
plan={json.loads(l)["sha256"]:json.loads(l) for l in open("docs/dataset_v2_split_plan.jsonl")}
# source tu fetch_manifest (scoop/nirsoft)
src={}
for l in open("data/raw/fetch_manifest.jsonl"):
    d=json.loads(l); 
    if d.get("source") in ("scoop","nirsoft"): src[d["sha256"]]=d["source"]
# benign dot1 built = co JSON + nam trong plan
built=[]; 
for sha,p in plan.items():
    jp=f"data/features_graph/{sha}_static.json"
    if os.path.exists(jp): built.append((sha,p,jp))
print(f"plan={len(plan)} built={len(built)} roi(fail)={len(plan)-len(built)}")
# ppdeep cluster noi bo built
H={}
for sha,_,_ in built:
    rp=f"data/raw/benign/{sha}"
    try: H[sha]=ppdeep.hash(open(rp,"rb").read())
    except: H[sha]=None
shas=[s for s,_,_ in built]; par={s:s for s in shas}
def find(x):
    while par[x]!=x: par[x]=par[par[x]]; x=par[x]
    return x
for i in range(len(shas)):
    for j in range(i+1,len(shas)):
        if H[shas[i]] and H[shas[j]] and ppdeep.compare(H[shas[i]],H[shas[j]])>=90: par[find(shas[i])]=find(shas[j])
clid={}
import collections
groups=collections.defaultdict(list)
for s in shas: groups[find(s)].append(s)
cl_merged=sum(1 for g in groups.values() if len(g)>1)
for root,mem in groups.items():
    for s in mem: clid[s]=("v2cl_"+root[:10]) if len(mem)>1 else None
# rows moi
newrows=[]
from collections import Counter
delta_plan=Counter(p["split_planned"] for p in plan.values())
delta_built=Counter()
for sha,p,jp in built:
    d=json.load(open(jp))
    newrows.append({"sha256":sha,"label":0,"source":src.get(sha,p["source"]),
                    "num_functions":d.get("num_functions"),"cluster":clid[sha],"split":p["split_planned"]})
    delta_built[p["split_planned"]]+=1
out=[dict(r) for r in v1]+newrows
out.sort(key=lambda r:r["sha256"])
with open("docs/dataset_v2_manifest.jsonl","w") as f:
    for r in out: f.write(json.dumps(r,sort_keys=True)+"\n")
h=hashlib.sha256(open("docs/dataset_v2_manifest.jsonl","rb").read()).hexdigest()
print(f"\n=== DELTA plan-vs-built theo split ===")
for s in ["train_pool","test_indist","holdout_source_nirsoft","holdout_lowfreq_toolchain"]:
    print(f"  {s:28s} plan={delta_plan[s]:3d} built={delta_built[s]:3d} roi={delta_plan[s]-delta_built[s]}")
print(f"cluster near-dup noi bo built: {cl_merged} cum ghep")
print(f"\nv2 manifest: {len(out)} dong (v1 {len(v1)} + benign moi {len(newrows)})")
# tong benign v2 + ISO share
ben=[r for r in out if r["label"]==0]; tr_ben=[r for r in ben if r["split"]=="train_pool"]
iso=sum(1 for r in tr_ben if r["source"]=="windows11-eval-iso")
print(f"benign v2={len(ben)} | train benign={len(tr_ben)} (ISO {iso} = {iso/len(tr_ben)*100:.0f}%)")
print(f"V2_MANIFEST_SHA256={h}")
