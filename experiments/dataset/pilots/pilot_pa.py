"""Task 5a: pilot PortableApps.com ~10 app (uu tien app cu). Fetch page -> a=/f=
-> download2 URL -> .paf.exe (NSIS) -> payload trong App/ (bo launcher *Portable.exe,
bo $PLUGINSDIR). Bao nhu pilot truoc."""
import os, re, subprocess, shutil, urllib.request, warnings
warnings.filterwarnings('ignore'); import pefile, ppdeep
WORK=os.path.expanduser("~/bfbg_benign_work/pilot_pa"); PAY=os.path.join(WORK,"payloads")
shutil.rmtree(WORK, ignore_errors=True); os.makedirs(PAY)
CAP=12*1024*1024
SEC=pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']; COM=pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']
PAGES=[
 "https://portableapps.com/apps/utilities/windirstat_portable",
 "https://portableapps.com/apps/development/notepadpp_portable",
 "https://portableapps.com/apps/utilities/7-zip_portable",
 "https://portableapps.com/apps/internet/putty_portable",
 "https://portableapps.com/apps/graphics_pictures/irfanview_portable",
 "https://portableapps.com/apps/music_video/smplayer_portable",
 "https://portableapps.com/apps/development/notepad2-mod_portable",
 "https://portableapps.com/apps/internet/filezilla_portable",
 "https://portableapps.com/apps/office/sumatrapdf_portable",
 "https://portableapps.com/apps/utilities/process-explorer_portable",
]
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
        return (oh.MajorLinkerVersion+oh.MinorLinkerVersion/100.0, 1 if getattr(pe,'RICH_HEADER',None) else 0,
                1 if (SEC<len(dd) and dd[SEC].Size>0) else 0, 1 if (COM<len(dd) and dd[COM].Size>0 and dd[COM].VirtualAddress) else 0)
    finally: pe.close()
bdir="/home/dhgia/Work/Defi/BFBG-Transformer/data/raw/benign"
ben=[ppdeep.hash(open(os.path.join(bdir,n),'rb').read()) for n in os.listdir(bdir)
     if re.match(r'^[0-9a-f]{64}$',n) and os.path.isfile(os.path.join(bdir,n))]
print(f"benign ref: {len(ben)}", flush=True)

rows=[]
for page in PAGES:
    name=page.rsplit('/',1)[-1]
    try:
        html=urllib.request.urlopen(urllib.request.Request(page,headers={'User-Agent':'pilot'}),timeout=40).read().decode('utf-8','ignore')
    except Exception: rows.append((name,'page-fail',None)); continue
    m=re.search(r'a=([A-Za-z0-9]+)&[^"\' ]*?f=([A-Za-z0-9._-]+\.paf\.exe)', html)
    if not m: rows.append((name,'no-url',None)); continue
    app,fn=m.group(1),m.group(2)
    url=f"https://download2.portableapps.com/portableapps/{app}/{fn}"
    d=os.path.join(WORK,name); os.makedirs(d,exist_ok=True); dl=os.path.join(d,fn)
    try: urllib.request.urlretrieve(url,dl)
    except Exception: rows.append((name,f'dl-fail',None)); continue
    ex=os.path.join(d,"x"); subprocess.run(['7z','x','-y','-o'+ex,dl],capture_output=True,timeout=300)
    pes=[]
    for dp,_,fs in os.walk(ex):
        for f in fs:
            fp=os.path.join(dp,f)
            low=f.lower()
            if (is_mz(fp) and seventype(fp)=='PE' and not low.endswith('portable.exe')
                and '$pluginsdir' not in fp.lower() and not re.search(r'(setup|install|uninst|unins)',low)):
                pes.append(fp)
    cand=[p for p in pes if 0<os.path.getsize(p)<=CAP and os.sep+'App'+os.sep in p] or [p for p in pes if 0<os.path.getsize(p)<=CAP]
    if not cand: rows.append((name,f'{len(pes)}PE/0 hop le',None)); continue
    pick=max(cand,key=os.path.getsize)
    dst=os.path.join(PAY,f"{name}__{os.path.basename(pick)}"); shutil.copy2(pick,dst)
    sz=os.path.getsize(pick)
    try: lk,rich,sig,dn=meta(pick)
    except: lk,rich,sig,dn=(0,0,0,0)
    try:
        h=ppdeep.hash(open(pick,'rb').read()); mx=max((ppdeep.compare(h,b) for b in ben),default=0)
    except: mx=-1
    rows.append((name,'OK',dict(npe=len(pes),size=sz,lk=lk,rich=rich,sig=sig,dn=dn,dup=mx,f=os.path.basename(pick),ver=fn)))

print("\n===== TASK 5a: PORTABLEAPPS PILOT =====")
ok=[r for r in rows if r[1]=='OK']
print(f"app thu: {len(PAGES)} | payload: {len(ok)} | fail: {len(rows)-len(ok)}")
print(f"{'app':22s} {'KB':>7s} {'.NET':>4s} {'lk':>5s} {'rich':>4s} {'sig':>3s} {'dup':>4s}  file (ver)")
for name,st,i in rows:
    if st=='OK': print(f"{name:22s} {i['size']//1024:7d} {str(bool(i['dn'])):>4s} {i['lk']:5.1f} {i['rich']:>4d} {i['sig']:>3d} {i['dup']:>4d}  {i['f']} ({i['ver']})")
    else: print(f"{name:22s} -- {st}")
if ok:
    lks=[i['lk'] for _,_,i in ok]
    print(f"\nTONG: payload/app={len(ok)} | <=12MB={len(ok)}/{len(ok)} | native={sum(1 for _,_,i in ok if not i['dn'])}/{len(ok)} "
          f"| co ky={sum(i['sig'] for _,_,i in ok)}/{len(ok)} | linker {min(lks):.1f}-{max(lks):.1f} | linker<12={sum(1 for l in lks if l<12)} "
          f"| near-dup>=90={sum(1 for _,_,i in ok if i['dup']>=90)}")
print("GHI CHU giay phep: PortableApps dong goi theo giay phep tung app (hon hop); PA Format/launcher la GPL.")
