"""Task 5: pilot Scoop ~20 mau (khong tai nhieu hon). Tai manifest tu bucket
Main/Extras, lay url 64bit, giai nen, lay 1 payload PE/app. Bao: yield,
<=12MB, native(is_dotnet), vendor, linker+rich+sig tung mau, ppdeep near-dup
vs benign hien co. Uu tien tool toolchain cu (GNU/MinGW) de xem co linker<12."""
import json, os, subprocess, shutil, math, warnings, urllib.request
warnings.filterwarnings('ignore')
import pefile, ppdeep

WORK=os.path.expanduser("~/bfbg_benign_work/pilot_scoop")
PAY=os.path.join(WORK,"payloads")
shutil.rmtree(WORK, ignore_errors=True); os.makedirs(PAY)
CAP=12*1024*1024
SEC_DIR=pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
COM_DIR=pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']

# ~22 app, uu tien GNU/MinGW (toolchain cu) + vai Rust/Go/C hien dai de doi chieu
APPS=["busybox","grep","sed","gawk","gzip","make","wget","curl","less","nano",
      "zip","unzip","jq","sqlite","nmap","upx","nasm","ripgrep","fd","fzf","putty","graphviz"]
BUCKETS=["https://raw.githubusercontent.com/ScoopInstaller/Main/master/bucket/",
         "https://raw.githubusercontent.com/ScoopInstaller/Extras/master/bucket/"]

def get_manifest(app):
    for b in BUCKETS:
        try:
            with urllib.request.urlopen(b+app+".json", timeout=30) as r:
                return json.load(r)
        except Exception: continue
    return None

def url64(m):
    a=m.get('architecture',{})
    if '64bit' in a and a['64bit'].get('url'): u=a['64bit']['url']
    elif m.get('url'): u=m['url']
    else: return None
    if isinstance(u,list): u=u[0]
    return u.split('#/')[0]

def seventype(f):
    try:
        out=subprocess.run(['7z','l','-slt',f],capture_output=True,text=True,errors='replace',timeout=60).stdout
        import re; mm=re.search(r'^Type = (.+)$',out,re.M); return mm.group(1).strip() if mm else None
    except Exception: return None

def is_mz(f):
    try:
        with open(f,'rb') as fh: return fh.read(2)==b'MZ'
    except Exception: return False

def pe_meta(f):
    pe=pefile.PE(f)
    try:
        oh=pe.OPTIONAL_HEADER; dd=oh.DATA_DIRECTORY
        linker=oh.MajorLinkerVersion+oh.MinorLinkerVersion/100.0
        rich=1 if getattr(pe,'RICH_HEADER',None) else 0
        sig=1 if (SEC_DIR<len(dd) and dd[SEC_DIR].Size>0) else 0
        dotnet=1 if (COM_DIR<len(dd) and dd[COM_DIR].Size>0 and dd[COM_DIR].VirtualAddress) else 0
        return linker,rich,sig,dotnet
    finally: pe.close()

# ppdeep hash benign hien co
benign_dir="/home/dhgia/Work/Defi/BFBG-Transformer/data/raw/benign"
import re
ben_hashes=[]
for n in os.listdir(benign_dir):
    if re.match(r'^[0-9a-f]{64}$',n):
        try: ben_hashes.append(ppdeep.hash(open(os.path.join(benign_dir,n),'rb').read()))
        except Exception: pass
print(f"benign ref hashes: {len(ben_hashes)}", flush=True)

rows=[]
for app in APPS:
    m=get_manifest(app)
    if not m: rows.append((app,'no-manifest',None)); continue
    u=url64(m)
    if not u: rows.append((app,'no-url',None)); continue
    d=os.path.join(WORK,app); os.makedirs(d,exist_ok=True)
    dl=os.path.join(d,"dl.bin")
    try: urllib.request.urlretrieve(u, dl)
    except Exception as e: rows.append((app,f'dl-fail',None)); continue
    # thu thap PE payload
    pes=[]
    if is_mz(dl) and seventype(dl)=='PE':
        pes=[dl]   # url tro thang toi binary
    else:
        ex=os.path.join(d,"x"); subprocess.run(['7z','x','-y','-o'+ex,dl],capture_output=True,timeout=300)
        for dp,_,fs in os.walk(ex):
            for fn in fs:
                fp=os.path.join(dp,fn)
                if is_mz(fp) and not re.search(r'(setup|install|uninst)',fn,re.I) and seventype(fp)=='PE':
                    pes.append(fp)
    # chon 1 payload: uu tien ten khop 'bin' manifest, else lon nhat <=CAP
    binhint=m.get('bin');
    if isinstance(binhint,list): binhint=[b if isinstance(b,str) else (b[0] if b else '') for b in binhint]
    elif isinstance(binhint,str): binhint=[binhint]
    else: binhint=[]
    binnames={os.path.basename(b).lower() for b in binhint}
    cand=[p for p in pes if 0<os.path.getsize(p)<=CAP]
    if not cand: rows.append((app, f'{len(pes)} PE nhung 0 hop le(<=12MB)', None)); continue
    pick=None
    for p in cand:
        if os.path.basename(p).lower() in binnames: pick=p; break
    if not pick: pick=max(cand, key=os.path.getsize)
    # copy payload
    dst=os.path.join(PAY, f"{app}__{os.path.basename(pick)}")
    shutil.copy2(pick,dst)
    sz=os.path.getsize(pick)
    try: linker,rich,sig,dotnet=pe_meta(pick)
    except Exception: linker,rich,sig,dotnet=(0,0,0,0)
    # near-dup
    try:
        h=ppdeep.hash(open(pick,'rb').read()); maxc=max((ppdeep.compare(h,bh) for bh in ben_hashes), default=0)
    except Exception: maxc=-1
    rows.append((app, 'OK', dict(n_pe=len(pes), size=sz, le12=sz<=CAP, linker=linker, rich=rich,
                                 sig=sig, dotnet=dotnet, maxdup=maxc, fname=os.path.basename(pick))))

# ===== bao cao =====
print("\n===== TASK 5: SCOOP PILOT =====")
ok=[r for r in rows if r[1]=='OK']
print(f"App thu: {len(APPS)} | lay duoc payload: {len(ok)} | that bai/khong nhung: {len(rows)-len(ok)}")
print(f"{'app':12s} {'size(KB)':>8s} {'<=12':>4s} {'.NET':>4s} {'linker':>6s} {'rich':>4s} {'sig':>3s} {'dupmax':>6s}  file")
for app,st,info in rows:
    if st=='OK':
        print(f"{app:12s} {info['size']//1024:8d} {str(info['le12']):>4s} {str(bool(info['dotnet'])):>4s} "
              f"{info['linker']:6.2f} {info['rich']:>4d} {info['sig']:>3d} {info['maxdup']:6d}  {info['fname']}")
    else:
        print(f"{app:12s} -- {st}")
if ok:
    import statistics as sx
    sizes=[i['size'] for _,_,i in ok]; linkers=[i['linker'] for _,_,i in ok]
    print(f"\nTONG KET: yield payload/app={len(ok)}/{len(APPS)} | <=12MB={sum(i['le12'] for _,_,i in ok)}/{len(ok)} "
          f"| native(non-.NET)={sum(1 for _,_,i in ok if not i['dotnet'])}/{len(ok)} | co chu ky={sum(i['sig'] for _,_,i in ok)}/{len(ok)}")
    print(f"linker range: {min(linkers):.2f}-{max(linkers):.2f} | so mau linker<12: {sum(1 for l in linkers if l<12)} "
          f"| near-dup>=90 vs benign: {sum(1 for _,_,i in ok if i['maxdup']>=90)}")
    print(f"vendor(app) khac nhau: {len(ok)}")
