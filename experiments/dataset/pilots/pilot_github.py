"""Task 5b: pilot GitHub Releases ~OSS Windows build MSVC (chon tay, ghi compiler).
Bao nhu pilot Scoop + license (field license repo)."""
import os, re, json, subprocess, shutil, urllib.request, warnings
warnings.filterwarnings('ignore'); import pefile, ppdeep
WORK=os.path.expanduser("~/bfbg_benign_work/pilot_github"); PAY=os.path.join(WORK,"payloads")
shutil.rmtree(WORK, ignore_errors=True); os.makedirs(PAY)
CAP=12*1024*1024
SEC=pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']; COM=pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']
# repo chon tay: C/C++ MSVC/Qt + 2 Delphi (heidisql, issrc) de da dang toolchain
REPOS=["notepad-plus-plus/notepad-plus-plus","x64dbg/x64dbg","WinMerge/winmerge",
 "winsiderss/systeminformer","sumatrapdfreader/sumatrapdf","qbittorrent/qBittorrent",
 "keepassxreboot/keepassxc","hluk/CopyQ","HeidiSQL/HeidiSQL","jrsoftware/issrc",
 "radareorg/radare2","mcmilk/7-Zip-zstd","maficomp/..","ArsenArsen/.."]
def gh(url):
    req=urllib.request.Request(url, headers={'User-Agent':'pilot','Accept':'application/vnd.github+json'})
    return json.load(urllib.request.urlopen(req, timeout=40))
def pick_asset(assets):
    # uu tien zip/7z windows x64, tranh src/arm/installer-only neu co zip
    cand=[]
    for a in assets:
        n=a['name'].lower()
        if any(n.endswith(e) for e in ('.zip','.7z')) and not any(b in n for b in ('src','source','arm','linux','mac','debug','pdb','symbol')):
            score = (0 if ('x64' in n or 'win64' in n or '64bit' in n or 'windows' in n) else 1)
            cand.append((score, a['size'], a['browser_download_url'], a['name']))
    if not cand:  # fallback: .exe (installer) windows
        for a in assets:
            n=a['name'].lower()
            if n.endswith('.exe') and not any(b in n for b in ('src','arm','linux','mac')):
                cand.append((2, a['size'], a['browser_download_url'], a['name']))
    cand.sort(); return cand[0] if cand else None
def seventype(f):
    try:
        out=subprocess.run(['7z','l','-slt',f],capture_output=True,text=True,errors='replace',timeout=60).stdout
        m=re.search(r'^Type = (.+)$',out,re.M); return m.group(1).strip() if m else None
    except: return None
def is_mz(f):
    try:
        with open(f,'rb') as fh: return fh.read(2)==b'MZ'
    except: return False
def meta(f):
    pe=pefile.PE(f)
    try:
        oh=pe.OPTIONAL_HEADER; dd=oh.DATA_DIRECTORY
        return (oh.MajorLinkerVersion+oh.MinorLinkerVersion/100.0,
                1 if getattr(pe,'RICH_HEADER',None) else 0,
                1 if (SEC<len(dd) and dd[SEC].Size>0) else 0,
                1 if (COM<len(dd) and dd[COM].Size>0 and dd[COM].VirtualAddress) else 0)
    finally: pe.close()
# benign ref hashes
bdir="/home/dhgia/Work/Defi/BFBG-Transformer/data/raw/benign"
ben=[ppdeep.hash(open(os.path.join(bdir,n),'rb').read()) for n in os.listdir(bdir)
     if re.match(r'^[0-9a-f]{64}$',n) and os.path.isfile(os.path.join(bdir,n))]
print(f"benign ref: {len(ben)}", flush=True)

rows=[]
for repo in REPOS:
    if '/..' in repo or repo.endswith('..'): continue
    try:
        rel=gh(f"https://api.github.com/repos/{repo}/releases/latest")
        lic=gh(f"https://api.github.com/repos/{repo}")
        license=(lic.get('license') or {}).get('spdx_id') or '?'
    except Exception as e:
        rows.append((repo,f'api-fail',None)); continue
    a=pick_asset(rel.get('assets',[]))
    if not a: rows.append((repo,'no-asset',None)); continue
    _,_,url,aname=a
    d=os.path.join(WORK,repo.replace('/','_')); os.makedirs(d,exist_ok=True)
    dl=os.path.join(d,aname)
    try: urllib.request.urlretrieve(url, dl)
    except Exception: rows.append((repo,'dl-fail',None)); continue
    pes=[]
    if is_mz(dl) and seventype(dl)=='PE': pes=[dl]
    else:
        ex=os.path.join(d,"x"); subprocess.run(['7z','x','-y','-o'+ex,dl],capture_output=True,timeout=300)
        # 1 lop long them (installer long zip)
        for _ in range(2):
            for dp,_2,fs in os.walk(ex):
                for fn in fs:
                    fp=os.path.join(dp,fn)
                    if seventype(fp) in ('zip','7z','Nsis','Cab','Compound') and not fp.endswith('.extracted'):
                        subprocess.run(['7z','x','-y','-o'+fp+'.extracted',fp],capture_output=True,timeout=300)
        for dp,_2,fs in os.walk(ex):
            for fn in fs:
                fp=os.path.join(dp,fn)
                if is_mz(fp) and not re.search(r'(setup|install|uninst|vcredist|vc_redist)',fn,re.I) and seventype(fp)=='PE':
                    pes.append(fp)
    cand=[p for p in pes if 0<os.path.getsize(p)<=CAP]
    if not cand: rows.append((repo,f'{len(pes)}PE/0 hop le',None)); continue
    pick=max(cand,key=os.path.getsize)
    dst=os.path.join(PAY,f"{repo.replace('/','_')}__{os.path.basename(pick)}"); shutil.copy2(pick,dst)
    sz=os.path.getsize(pick)
    try: lk,rich,sig,dn=meta(pick)
    except: lk,rich,sig,dn=(0,0,0,0)
    try:
        h=ppdeep.hash(open(pick,'rb').read()); mx=max((ppdeep.compare(h,b) for b in ben),default=0)
    except: mx=-1
    rows.append((repo,'OK',dict(npe=len(pes),size=sz,lk=lk,rich=rich,sig=sig,dn=dn,dup=mx,lic=license,f=os.path.basename(pick))))

print("\n===== TASK 5b: GITHUB RELEASES PILOT =====")
ok=[r for r in rows if r[1]=='OK']
print(f"repo thu: {len([r for r in REPOS if not r.endswith('..')])} | payload: {len(ok)} | fail: {len(rows)-len(ok)}")
print(f"{'repo':30s} {'KB':>7s} {'.NET':>4s} {'lk':>5s} {'rich':>4s} {'sig':>3s} {'dup':>4s} {'license':>10s}  file")
for repo,st,i in rows:
    if st=='OK':
        print(f"{repo:30s} {i['size']//1024:7d} {str(bool(i['dn'])):>4s} {i['lk']:5.1f} {i['rich']:>4d} {i['sig']:>3d} {i['dup']:>4d} {i['lic']:>10s}  {i['f']}")
    else: print(f"{repo:30s} -- {st}")
if ok:
    lks=[i['lk'] for _,_,i in ok]
    print(f"\nTONG: payload/repo={len(ok)} | <=12MB={sum(1 for _,_,i in ok)}/{len(ok)} | native={sum(1 for _,_,i in ok if not i['dn'])}/{len(ok)} "
          f"| co ky={sum(i['sig'] for _,_,i in ok)}/{len(ok)} | linker {min(lks):.1f}-{max(lks):.1f} | linker<12={sum(1 for l in lks if l<12)} "
          f"| near-dup>=90={sum(1 for _,_,i in ok if i['dup']>=90)}")
