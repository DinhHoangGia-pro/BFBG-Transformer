"""Task 3: kiem chung classifier toolchain tren 30 mau phan tang.
Ground-truth ('tay') = chuoi compiler + ten section + CRT import (tin hieu manh).
So heuristic vs ground-truth -> confusion matrix. Rust? sai >30% -> de xuat bo."""
import os, re, json, random, warnings
warnings.filterwarnings('ignore'); import pefile
from collections import Counter, defaultdict
ROOT='/home/dhgia/Work/Defi/BFBG-Transformer'; os.chdir(ROOT)
man={json.loads(l)['sha256']:json.loads(l) for l in open('docs/dataset_v1_manifest.jsonl')}

def pe_info(path):
    pe=pefile.PE(path)
    try:
        secs={s.Name.rstrip(b'\x00').decode('latin1','ignore') for s in pe.sections}
        lk=pe.OPTIONAL_HEADER.MajorLinkerVersion
        rich=bool(getattr(pe,'RICH_HEADER',None))
        imps=set()
        if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
            for e in pe.DIRECTORY_ENTRY_IMPORT:
                if e.dll: imps.add(e.dll.decode('latin1','ignore').lower())
        return secs,lk,rich,imps
    finally: pe.close()

def heuristic(secs,lk,rich,imps):
    simp=' '.join(imps)
    if '.symtab' in secs or any(s.startswith('.go') for s in secs): return 'Go'
    if 'CODE' in secs or 'DATA' in secs or '.itext' in secs or '.didata' in secs: return 'Delphi'
    mingw=any(d in simp for d in ('libgcc','libstdc++','libwinpthread','mingw','msys-'))
    if '.eh_frame' in secs or mingw or (not rich and 'msvcrt.dll' in imps and lk<14): return 'GNU/MinGW'
    if ('bcrypt.dll' in imps) and any('api-ms-win-crt' in d for d in imps): return 'Rust?'
    if rich or 'ucrtbase.dll' in imps or any('vcruntime' in d for d in imps) or any('api-ms-win-crt' in d for d in imps) or 'msvcrt.dll' in imps:
        if lk<=10: return 'MSVC<=10'
        if lk in (11,12): return 'MSVC 11-12'
        if lk>=14: return 'MSVC 14'
        return 'MSVC khac'
    return 'khac'

def ground_truth(path,secs,lk,rich,imps):
    try: data=open(path,'rb').read()
    except: data=b''
    ev=[]
    if b'Go build ID' in data or re.search(rb'go1\.\d', data): ev.append('go'); return 'Go','go-string'
    if b'rustc' in data or b'\\.cargo\\' in data or b'/rustc/' in data or b'cargo registry' in data: return 'Rust','rustc-string'
    if b'GCC: (' in data or '.eh_frame' in secs: return 'GNU/MinGW','gcc/.eh_frame'
    if any(m in data for m in (b'Embarcadero',b'CodeGear',b'Borland',b'Delphi')) or 'CODE' in secs: return 'Delphi','delphi-string'
    if rich or any(d in ' '.join(imps) for d in ('ucrtbase','vcruntime','api-ms-win-crt','msvcr')):
        tag='rich' if rich else 'msvc-crt'
        if lk<=10: return 'MSVC<=10',tag
        if lk in (11,12): return 'MSVC 11-12',tag
        if lk>=14: return 'MSVC 14',tag
        return 'MSVC khac',tag
    return 'khac','none'

# gom mau theo nhom
def grp(r):
    if r['label']==1: return 'malicious'
    return {'windows11-eval-iso':'ISO','chocolatey':'choco'}.get(r['source'],'cu')
def rawpath(sha,r): return f"data/raw/{'malicious' if r['label']==1 else 'benign'}/{sha}"

random.seed(42)
pool=defaultdict(list)
mal=[s for s,r in man.items() if r['label']==1]; random.shuffle(mal)
for s in mal[:150]: pool['malicious'].append(s)
for s,r in man.items():
    if r['label']==0: pool[grp(r)].append(s)
SCOOP=os.path.expanduser("~/bfbg_benign_work/pilot_scoop/payloads")
scoop_files=[os.path.join(SCOOP,f) for f in os.listdir(SCOOP) if os.path.isfile(os.path.join(SCOOP,f))]

# tinh heuristic cho pool de chon da dang lop
def hlabel(path):
    try: return heuristic(*pe_info(path))
    except: return 'khac'
quota={'malicious':8,'ISO':5,'choco':5,'cu':4,'scoop':8}
chosen=[]  # (tag_group, path, sha_or_name)
for g in ['malicious','ISO','choco','cu']:
    items=pool[g][:120]
    byc=defaultdict(list)
    for s in items:
        byc[hlabel(rawpath(s,man[s]))].append(s)
    picks=[]
    # lay tron cac lop
    classes=list(byc); random.shuffle(classes)
    i=0
    while len(picks)<quota[g] and any(byc.values()):
        c=classes[i%len(classes)]; i+=1
        if byc[c]: picks.append(byc[c].pop())
        if i>200: break
    for s in picks: chosen.append((g, rawpath(s,man[s]), s[:16]))
# scoop
random.shuffle(scoop_files)
for p in scoop_files[:quota['scoop']]: chosen.append(('scoop', p, os.path.basename(p)[:16]))

print(f"=== 30 MAU PHAN TANG: heuristic vs ground-truth ===")
print(f"{'group':10s} {'id':16s} {'heuristic':12s} {'ground-truth':12s} {'evidence':16s} {'match':5s}")
cm=defaultdict(Counter); rust_total=0; rust_wrong=0
for g,path,idn in chosen:
    try: secs,lk,rich,imps=pe_info(path)
    except Exception:
        print(f"{g:10s} {idn:16s} {'(loi doc PE)':12s}"); continue
    h=heuristic(secs,lk,rich,imps); gt,ev=ground_truth(path,secs,lk,rich,imps)
    # chuan hoa Rust? vs Rust khi so
    h_norm='Rust' if h=='Rust?' else h
    m = 'OK' if h_norm==gt else 'X'
    cm[gt][h]+=1
    if h=='Rust?':
        rust_total+=1
        if gt!='Rust': rust_wrong+=1
    print(f"{g:10s} {idn:16s} {h:12s} {gt:12s} {ev:16s} {m:5s}")

print("\n=== CONFUSION (hang=ground-truth, cot=heuristic) ===")
cols=sorted({c for row in cm.values() for c in row})
print(f"{'gt \\ heur':12s} " + " ".join(f"{c[:10]:>10s}" for c in cols))
for gt in sorted(cm):
    print(f"{gt:12s} " + " ".join(f"{cm[gt].get(c,0):>10d}" for c in cols))
tot=sum(sum(r.values()) for r in cm.values())
correct=sum(cm[gt].get(gt if gt!='Rust' else 'Rust?',0) + (cm[gt].get('Rust?',0) if gt=='Rust' else 0) for gt in cm)
# dem match don gian
match=0; alln=0
for g,path,idn in chosen:
    pass
print(f"\nRust?: tong {rust_total}, sai {rust_wrong} -> {'BO NHAN (sai >30%)' if rust_total and rust_wrong/rust_total>0.30 else ('giu' if rust_total else 'khong co mau Rust?')}")
