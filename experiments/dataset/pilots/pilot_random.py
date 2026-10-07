"""Task 4: pilot NGAU NHIEN (seed co dinh) 25 app Scoop Main + 25 nirsoft.
Loai tool khoi phuc mat khau/hack. Dung 'bo da kiem' (chuoi compiler+section+CRT,
BO nhan Rust? heuristic). Bao yield, <=12MB, .NET, toolchain, linker, rich, ky,
near-dup (ca sha256 trung), timeout uoc tinh (proxy: Rust/Go hoac >6MB -> cao)."""
import os, re, json, subprocess, shutil, urllib.request, hashlib, warnings, random
warnings.filterwarnings('ignore'); import pefile, ppdeep
SEED=20261007; random.seed(SEED)
WORK=os.path.expanduser("~/bfbg_benign_work/pilot_random"); PAY=os.path.join(WORK,"payloads")
shutil.rmtree(WORK, ignore_errors=True); os.makedirs(PAY)
CAP=12*1024*1024
SEC=pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']; COM=pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']
EXCLUDE=re.compile(r'(pass|pwd|recover|crack|keygen|hashcat|mimikatz|hydra|john-|lazagne|'
 r'dialupass|netpass|mailpv|iepv|webbrowser|passwordfox|produkey|licensecrawler|serial|'
 r'sniff|keylog|wirelesskey|protected.storage|ophcrack|cain|rainbow|bruteforce)', re.I)

def gh_tree(owner,repo):
    url=f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
    d=json.load(urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'p'}),timeout=40))
    return [t['path'][len('bucket/'):-5] for t in d['tree'] if t['path'].startswith('bucket/') and t['path'].endswith('.json')]

def manifest(owner,repo,app):
    url=f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/bucket/{app}.json"
    return json.load(urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'p'}),timeout=30))

def url64(m):
    a=m.get('architecture',{})
    if '64bit' in a and a['64bit'].get('url'): u=a['64bit']['url']
    elif m.get('url'): u=m['url']
    else: return None
    if isinstance(u,list): u=u[0]
    return u.split('#/')[0]

def stype(f):
    try:
        o=subprocess.run(['7z','l','-slt',f],capture_output=True,text=True,errors='replace',timeout=60).stdout
        m=re.search(r'^Type = (.+)$',o,re.M); return m.group(1).strip() if m else None
    except: return None
def is_mz(f):
    try:
        with open(f,'rb') as fh: return fh.read(2)==b'MZ'
    except: return False

def classify(path):  # BO DA KIEM (chuoi + section + rich/linker), khong co Rust? heuristic
    try: pe=pefile.PE(path)
    except: return 'khac',0,0,0,0
    try:
        secs={s.Name.rstrip(b'\x00').decode('latin1','ignore') for s in pe.sections}
        lk=pe.OPTIONAL_HEADER.MajorLinkerVersion+pe.OPTIONAL_HEADER.MinorLinkerVersion/100.0
        rich=1 if getattr(pe,'RICH_HEADER',None) else 0
        dd=pe.OPTIONAL_HEADER.DATA_DIRECTORY
        sig=1 if (SEC<len(dd) and dd[SEC].Size>0) else 0
        dotnet=1 if (COM<len(dd) and dd[COM].Size>0 and dd[COM].VirtualAddress) else 0
        imps=set()
        if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
            for e in pe.DIRECTORY_ENTRY_IMPORT:
                if e.dll: imps.add(e.dll.decode('latin1','ignore').lower())
    finally: pe.close()
    try: data=open(path,'rb').read()
    except: data=b''
    lkm=int(lk)
    if b'Go build ID' in data or re.search(rb'go1\.\d',data): tc='Go'
    elif b'rustc' in data or b'/rustc/' in data or b'\\.cargo\\' in data: tc='Rust'
    elif b'GCC: (' in data or '.eh_frame' in secs: tc='GNU/MinGW'
    elif any(m in data for m in (b'Embarcadero',b'CodeGear',b'Borland')) or 'CODE' in secs: tc='Delphi'
    elif rich or any(d in ' '.join(imps) for d in ('ucrtbase','vcruntime','api-ms-win-crt','msvcr')):
        tc = 'MSVC<=10' if lkm<=10 else ('MSVC 11-12' if lkm in (11,12) else ('MSVC 14' if lkm>=14 else 'MSVC khac'))
    else: tc='khac'
    return tc,lk,rich,sig,dotnet

bdir="/home/dhgia/Work/Defi/BFBG-Transformer/data/raw/benign"
ben=[]; ben_sha=set()
for n in os.listdir(bdir):
    p=os.path.join(bdir,n)
    if re.match(r'^[0-9a-f]{64}$',n) and os.path.isfile(p):
        ben_sha.add(n)
        try: ben.append(ppdeep.hash(open(p,'rb').read()))
        except: pass
print(f"SEED={SEED} | benign ref: {len(ben)}", flush=True)

def run_bucket(owner,repo,label,k):
    apps=[a for a in gh_tree(owner,repo) if not EXCLUDE.search(a)]
    random.shuffle(apps); sel=apps[:k]
    print(f"\n### {label}: {len(apps)} app (sau loai pass/hack), chon {len(sel)} ###", flush=True)
    rows=[]
    for app in sel:
        try: m=manifest(owner,repo,app); lic=m.get('license'); lic=lic if isinstance(lic,str) else (lic or {}).get('identifier','?') if lic else '?'
        except Exception: rows.append((app,'manifest-fail')); continue
        u=url64(m)
        if not u: rows.append((app,'no-url')); continue
        d=os.path.join(WORK,label,app); os.makedirs(d,exist_ok=True); dl=os.path.join(d,'dl.bin')
        try: urllib.request.urlretrieve(u,dl)
        except Exception: rows.append((app,'dl-fail')); continue
        pes=[]
        if is_mz(dl) and stype(dl)=='PE': pes=[dl]
        else:
            ex=os.path.join(d,'x'); subprocess.run(['7z','x','-y','-o'+ex,dl],capture_output=True,timeout=300)
            for dp,_,fs in os.walk(ex):
                for fn in fs:
                    fp=os.path.join(dp,fn)
                    if is_mz(fp) and not re.search(r'(setup|install|uninst)',fn,re.I) and stype(fp)=='PE': pes.append(fp)
        cand=[p for p in pes if 0<os.path.getsize(p)<=CAP]
        if not cand: rows.append((app, f'{len(pes)}PE/0le')); continue
        pick=max(cand,key=os.path.getsize); sz=os.path.getsize(pick)
        tc,lk,rich,sig,dn=classify(pick)
        dat=open(pick,'rb').read(); sha=hashlib.sha256(dat).hexdigest(); h=ppdeep.hash(dat)
        exact = sha in ben_sha
        mx=max((ppdeep.compare(h,b) for b in ben),default=0)
        est_to = 'cao' if (tc in ('Rust','Go') or sz>6*1024*1024) else 'thap'
        rows.append((app,'OK',dict(sz=sz,tc=tc,lk=lk,rich=rich,sig=sig,dn=dn,dup=mx,exact=exact,est=est_to,lic=lic or '?')))
    return rows

def report(label,rows):
    ok=[r for r in rows if r[1]=='OK']
    print(f"\n===== {label}: payload {len(ok)}/{len(rows)} =====")
    from collections import Counter
    if ok:
        tc=Counter(i['tc'] for _,_,i in ok)
        print(f"<=12MB={len(ok)}/{len(ok)} | .NET={sum(i['dn'] for _,_,i in ok)} | co ky={sum(i['sig'] for _,_,i in ok)} "
              f"| rich={sum(i['rich'] for _,_,i in ok)} | near-dup>=90={sum(1 for _,_,i in ok if i['dup']>=90)} "
              f"| sha256-trung={sum(1 for _,_,i in ok if i['exact'])} | est-timeout-cao={sum(1 for _,_,i in ok if i['est']=='cao')}")
        print(f"toolchain: {dict(tc)}")
        lks=[i['lk'] for _,_,i in ok]; print(f"linker {min(lks):.1f}-{max(lks):.1f} | <12={sum(1 for l in lks if l<12)}")
    fails=Counter(r[1] for r in rows if r[1]!='OK')
    print(f"fail: {dict(fails)}")

rs=run_bucket("ScoopInstaller","Main","Scoop-Main-random",25); report("SCOOP MAIN (random)",rs)
rn=run_bucket("ScoopInstaller","Nirsoft","Nirsoft-random",25); report("NIRSOFT (random)",rn)
print(f"\nSEED dung: {SEED} (tai lap duoc)")
