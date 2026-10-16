#!/usr/bin/env python
"""PILOT nguon benign moi cho o MSVC<=10 x 256K-1M (o #1) va MSVC11-12 (seed 20261016).
CHI do yield theo o, KHONG train, KHONG khoa v4, KHONG viet fetcher quy mo lon.
Quy tac loai/dedup: V4_BENIGN_RULES_FROZEN.md (sha+ppdeep>=90 vs toan bo cu; installer/forwarder/
3rd-party-DLL/size>12MB loai). Isolation: ~/bfbg_benign_work/v4_pilot2/. KHONG dung v4_benign/.
"""
import os, re, sys, json, random, shutil, subprocess, urllib.request, warnings, hashlib, socket
warnings.filterwarnings("ignore"); import pefile, ppdeep
socket.setdefaulttimeout(60)   # urlretrieve khong treo vo han
os.chdir("/home/dhgia/Work/Defi/BFBG-Transformer")
SEED = 20261016
CAP = 12 * 1024 * 1024
WORK = os.path.expanduser("~/bfbg_benign_work"); P2 = os.path.join(WORK, "v4_pilot2")
DL = os.path.join(P2, "dl"); shutil.rmtree(P2, ignore_errors=True); os.makedirs(DL, exist_ok=True)
THIRD = re.compile(r"(vcruntime|msvcp|msvcr|concrt|ucrtbase|api-ms-win|ext-ms-|qt5|qt6|libcrypto|libssl|"
                   r"ffmpeg|avcodec|avformat|avutil|icu[a-z0-9]*|zlib|libpng|d3d|openssl|python3|mfc\d|libgcc|libstdc)", re.I)
PA_PAGES = [
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
    "https://portableapps.com/apps/music_video/foobar2000_portable",
    "https://portableapps.com/apps/music_video/audacity_portable",
    "https://portableapps.com/apps/security/keepass_portable",
    "https://portableapps.com/apps/utilities/winmerge_portable",
    "https://portableapps.com/apps/internet/pidgin_portable"]


def hex64(n): return bool(re.match(r"^[0-9a-f]{64}$", n))

# dedup refs tu cache
old_sha = set(); v_h = []
for sub in ("data/raw/benign", "data/raw/malicious"):
    if os.path.isdir(sub):
        old_sha |= {n for n in os.listdir(sub) if hex64(n)}
for fam in ("Zeus", "Gozi", "Zloader", "Ramnit"):
    d = f"data/raw/pilot_v4_malicious/{fam}"
    if os.path.isdir(d): old_sha |= {n for n in os.listdir(d) if hex64(n)}
imp = os.path.join(WORK, "import_v3")
if os.path.isdir(imp): old_sha |= {n for n in os.listdir(imp) if hex64(n)}
# v4 benign da giu phien 1 (tranh trung lai)
v4b = os.path.join(WORK, "v4_benign")
if os.path.isdir(v4b): old_sha |= {n for n in os.listdir(v4b) if hex64(n)}
for c in ("v12_benign_ppdeep.json", "v3_benign_ppdeep.json", "old_mal_ppdeep.json", "pilot_v4_ppdeep.json"):
    p = os.path.join(WORK, c)
    if os.path.isfile(p):
        try: v_h.extend(x for x in json.load(open(p)).values() if x)
        except Exception: pass
print(f"[refs] sha={len(old_sha)} ppdeep={len(v_h)}", flush=True)


def pe_bin(path):
    try:
        pe = pefile.PE(path, fast_load=True)
        secs = [s.Name.decode(errors="ignore").rstrip("\x00") for s in pe.sections]
        lk = pe.OPTIONAL_HEADER.MajorLinkerVersion
        rich = hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER is not None
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            imps = [e.dll.decode(errors="ignore").lower() for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]
        except Exception: imps = []
    except Exception:
        return "khac", None
    simp = " ".join(imps)
    if ".symtab" in secs or any(s.startswith(".go") for s in secs): return "Go", lk
    if "CODE" in secs or "DATA" in secs or ".itext" in secs: return "Delphi", lk
    if ".eh_frame" in secs or any(d in simp for d in ("libgcc", "libstdc++", "libwinpthread", "mingw", "msys-")): return "GNU/MinGW", lk
    if lk is not None:   # linker-primary (pack xoa rich/CRT nhung linker major con)
        if 6 <= lk <= 10: return "MSVC<=10", lk
        if lk in (11, 12, 13): return "MSVC 11-12", lk
        if 14 <= lk <= 19: return "MSVC 14", lk
    if rich or "ucrtbase.dll" in imps or any("vcruntime" in d for d in imps) or any("api-ms-win-crt" in d for d in imps) or "msvcrt.dll" in imps:
        if lk and lk <= 10: return "MSVC<=10", lk
        if lk in (11, 12): return "MSVC 11-12", lk
        if lk and lk >= 14: return "MSVC 14", lk
    return "khac", lk


def sizeb(n):
    if n < 256*1024: return "<256K"
    if n < 1024*1024: return "256K-1M"
    if n < 4*1024*1024: return "1-4M"
    if n < 12*1024*1024: return "4-12M"
    return ">12M"


def is_mz(f):
    try:
        with open(f, "rb") as fh: return fh.read(2) == b"MZ"
    except Exception: return False


def stype(f):
    try:
        o = subprocess.run(["7z", "l", "-slt", f], capture_output=True, text=True, errors="replace", timeout=60).stdout
        m = re.search(r"^Type = (.+)$", o, re.M); return m.group(1).strip() if m else None
    except Exception: return None


def payloads_from(dirpath):
    out = []
    for dp, _, fs in os.walk(dirpath):
        for fn in fs:
            fp = os.path.join(dp, fn); low = fn.lower()
            if re.search(r"(setup|install|uninst|unins)", low): continue
            if re.match(r"(api-ms-win-|ext-ms-)", low): continue
            if THIRD.search(fn): continue
            if low.endswith("portable.exe"): continue
            if "$pluginsdir" in fp.lower(): continue
            if is_mz(fp) and 0 < os.path.getsize(fp) <= CAP and stype(fp) == "PE":
                out.append(fp)
    out.sort(key=os.path.getsize, reverse=True)
    return out[:3]  # cap 3/app


def take(fp, src, app, recs):
    try: data = open(fp, "rb").read()
    except Exception: return
    sha = hashlib.sha256(data).hexdigest()
    if sha in old_sha:
        recs.append(dict(src=src, app=app, step="dedup_sha")); return
    try: h = ppdeep.hash(data)
    except Exception: h = None
    if h and max((ppdeep.compare(h, b) for b in v_h), default=0) >= 90:
        recs.append(dict(src=src, app=app, step="dedup_ppdeep")); return
    b, lk = pe_bin(fp); sz = len(data)
    old_sha.add(sha); v_h.append(h) if h else None
    recs.append(dict(src=src, app=app, step="kept", bin=b, sizeb=sizeb(sz), linker=lk, size=sz))


# ---- NirSoft via Scoop bucket ----
def scoop_nirsoft_apps():
    u = "https://api.github.com/repos/ScoopInstaller/Nirsoft/git/trees/HEAD?recursive=1"
    d = json.load(urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "p"}), timeout=60))
    return [os.path.basename(t["path"])[:-5] for t in d.get("tree", []) if t["path"].startswith("bucket/") and t["path"].endswith(".json")]


def scoop_url(app):
    u = f"https://raw.githubusercontent.com/ScoopInstaller/Nirsoft/HEAD/bucket/{app}.json"
    m = json.load(urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "p"}), timeout=40))
    a = m.get("architecture", {})
    url = a.get("64bit", {}).get("url") if "64bit" in a else m.get("url")
    if isinstance(url, list): url = url[0]
    return url.split("#/")[0] if url else None


recs = []
# NirSoft 25 random
try:
    apps = scoop_nirsoft_apps(); random.Random(SEED).shuffle(apps); apps = apps[:25]
    print(f"[NirSoft] {len(apps)} app random (seed {SEED})", flush=True)
    for app in apps:
        try:
            url = scoop_url(app)
            if not url: recs.append(dict(src="NirSoft", app=app, step="no_url")); continue
            d = os.path.join(DL, "nir_" + app); os.makedirs(d, exist_ok=True); dl = os.path.join(d, "f.bin")
            urllib.request.urlretrieve(url, dl)
            if is_mz(dl) and stype(dl) == "PE":
                take(dl, "NirSoft", app, recs)
            else:
                ex = os.path.join(d, "x"); subprocess.run(["7z", "x", "-y", "-o"+ex, dl], capture_output=True, timeout=200)
                for p in payloads_from(ex): take(p, "NirSoft", app, recs)
            shutil.rmtree(d, ignore_errors=True)
        except Exception as e:
            recs.append(dict(src="NirSoft", app=app, step="fail", reason=str(e)[:60]))
except Exception as e:
    print(f"[NirSoft] bucket fail: {e}", flush=True)

json.dump(recs, open(os.path.join(P2, "pilot_v4_src_recs.json"), "w"))  # luu sau NirSoft (phong PA treo)
print(f"[NirSoft DONE] kept={sum(1 for r in recs if r['step']=='kept')}", flush=True)

# PortableApps (list app cu)
print(f"[PortableApps] {len(PA_PAGES)} app", flush=True)
for page in PA_PAGES:
    app = page.rsplit("/", 1)[-1]
    try:
        try:
            html = urllib.request.urlopen(urllib.request.Request(page, headers={"User-Agent": "p"}), timeout=30).read().decode("utf-8", "ignore")
        except Exception:
            html = ""
        m = re.search(r"a=([A-Za-z0-9]+)&[^\"' ]*?f=([A-Za-z0-9._-]+\.paf\.exe)", html)
        if not m:
            # thu trang generic apps/<cat>/<app> qua cong cu tim: bo qua neu khong ra URL
            recs.append(dict(src="PortableApps", app=app, step="no_url")); continue
        aid, fn = m.group(1), m.group(2)
        url = f"https://download2.portableapps.com/portableapps/{aid}/{fn}"
        d = os.path.join(DL, "pa_" + app); os.makedirs(d, exist_ok=True); dl = os.path.join(d, fn)
        urllib.request.urlretrieve(url, dl)
        ex = os.path.join(d, "x"); subprocess.run(["7z", "x", "-y", "-o"+ex, dl], capture_output=True, timeout=300)
        # uu tien payload trong App/ (bo launcher)
        ps = [p for p in payloads_from(ex) if os.sep+"App"+os.sep in p] or payloads_from(ex)
        for p in ps[:3]: take(p, "PortableApps", app, recs)
        shutil.rmtree(d, ignore_errors=True)
    except Exception as e:
        recs.append(dict(src="PortableApps", app=app, step="fail", reason=str(e)[:60]))

json.dump(recs, open(os.path.join(P2, "pilot_v4_src_recs.json"), "w"))

# ---- report ----
from collections import Counter, defaultdict
print("\n===== PILOT NGUON MOI v4 (seed 20261016) — YIELD O #1 & MSVC11-12 =====")
for src in ("NirSoft", "PortableApps"):
    sr = [r for r in recs if r["src"] == src]
    kept = [r for r in sr if r["step"] == "kept"]
    steps = Counter(r["step"] for r in sr)
    cell = Counter((r["bin"], r["sizeb"]) for r in kept)
    msvc10 = [r for r in kept if r["bin"] == "MSVC<=10"]
    o1 = cell.get(("MSVC<=10", "256K-1M"), 0)
    m11 = sum(v for (b, s), v in cell.items() if b == "MSVC 11-12")
    n_pl = len(kept)
    y1 = 100*o1/n_pl if n_pl else 0
    print(f"\n[{src}] app/payload: kept={n_pl} | steps={dict(steps)}")
    print(f"   MSVC<=10 tong={len(msvc10)} | O#1 (MSVC<=10 x256K-1M)={o1} ({y1:.0f}% payload) | MSVC11-12={m11}")
    szc = Counter(r["sizeb"] for r in msvc10)
    print(f"   MSVC<=10 phan bo size: {dict(szc)}")
    print(f"   cell chi tiet: {dict(cell)}")
print("\nGHI: yield O#1 = #payload MSVC<=10 x256K-1M / tong payload giu. Dedup theo V4 rules.")
