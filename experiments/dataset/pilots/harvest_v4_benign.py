#!/usr/bin/env python
"""Harvest benign v4 theo PHIEN, resumable. Quy tac: docs/V4_BENIGN_RULES_FROZEN.md.
Nham 6 O THIEU (toolchain x size); dung mot o khi day. Co lap hoan toan khoi v1-3 va VT.
KHONG train, khong cham holdout, khong khoa v4. Chay trong cgroup systemd (MemoryMax=14G).
"""
import os, re, sys, json, time, hashlib, shutil, subprocess, urllib.request, urllib.error, warnings, random
warnings.filterwarnings("ignore"); import pefile, ppdeep
os.chdir("/home/dhgia/Work/Defi/BFBG-Transformer"); sys.path.insert(0, ".")

V4_SEED = 20261015
SESSION_CAP = 7.5 * 3600
CAP_SIZE = 12 * 1024 * 1024
BATCH = 40
BUILD_WORKERS = 4
WORK = os.path.expanduser("~/bfbg_benign_work")
V4 = os.path.join(WORK, "v4_benign"); V4FEAT = os.path.join(WORK, "v4_benign_features")
V4DL = os.path.join(WORK, "v4_benign_dl"); STATE = os.path.join(WORK, "v4_benign_state.jsonl")
KEPT_SHA = os.path.join(WORK, "v4_benign_kept_sha.txt")
V4FAIL = os.path.join(WORK, "v4_benign_lift_failures.jsonl"); V4OOS = os.path.join(WORK, "v4_benign_oos.jsonl")
for d in (V4, V4FEAT, V4DL): os.makedirs(d, exist_ok=True)
WALL0 = time.time()
BUCKET = {"Main": "ScoopInstaller/Main", "Extras": "ScoopInstaller/Extras", "Versions": "ScoopInstaller/Versions"}

# 6 o muc tiêu (bin, size-bucket) -> cap (muc tieu v4 §5.1: o lon 100, o nho 20)
TARGET_CELLS = {
    ("MSVC<=10", "256K-1M"): 100, ("MSVC 14", "256K-1M"): 100, ("MSVC 14", "1-4M"): 100,
    ("MSVC 11-12", "256K-1M"): 20, ("MSVC 11-12", "1-4M"): 20, ("MSVC 11-12", "<256K"): 20,
}
THIRD_PARTY = re.compile(r"(vcruntime|msvcp|msvcr|concrt|ucrtbase|api-ms-win|ext-ms-|qt5|qt6|libcrypto|"
                         r"libssl|ffmpeg|avcodec|avformat|avutil|swscale|icu[a-z0-9]*|zlib|libpng|d3d|"
                         r"openssl|python3|vcomp|mfc\d|tbb|boost|libgcc|libstdc)", re.I)


def log(**kw):
    kw["ts"] = round(time.time(), 1)
    with open(STATE, "a") as f: f.write(json.dumps(kw) + "\n")


def pe_info(path):
    pe = pefile.PE(path, fast_load=True)
    secs = [s.Name.decode(errors="ignore").rstrip("\x00") for s in pe.sections]
    lk = pe.OPTIONAL_HEADER.MajorLinkerVersion
    rich = hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER is not None
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        imps = [e.dll.decode(errors="ignore").lower() for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]
    except Exception:
        imps = []
    return secs, lk, rich, imps


def tc_bin(path):
    """Bin toolchain tu PE tho (heuristic da kiem validate_tc)."""
    try:
        secs, lk, rich, imps = pe_info(path)
    except Exception:
        return "khac", None
    simp = " ".join(imps)
    if ".symtab" in secs or any(s.startswith(".go") for s in secs): return "Go", lk
    if "CODE" in secs or "DATA" in secs or ".itext" in secs or ".didata" in secs: return "Delphi", lk
    mingw = any(d in simp for d in ("libgcc", "libstdc++", "libwinpthread", "mingw", "msys-"))
    if ".eh_frame" in secs or mingw: return "GNU/MinGW", lk   # chi GNU khi co .eh_frame/mingw-dll (bo da kiem; old-MSVC khong Rich + msvcrt KHONG phai GNU)
    if rich or "ucrtbase.dll" in imps or any("vcruntime" in d for d in imps) \
            or any("api-ms-win-crt" in d for d in imps) or "msvcrt.dll" in imps:
        if lk <= 10: return "MSVC<=10", lk
        if lk in (11, 12): return "MSVC 11-12", lk
        if lk >= 14: return "MSVC 14", lk
        return "MSVC khac", lk
    return "khac", lk


def sizebucket(n):
    if n < 256 * 1024: return "<256K"
    if n < 1024 * 1024: return "256K-1M"
    if n < 4 * 1024 * 1024: return "1-4M"
    if n < 12 * 1024 * 1024: return "4-12M"
    return ">12M"


# ---------- dedup refs (sha + ppdeep) vs TOAN BO du lieu cu + 614 malware moi ----------
def hex64(n): return bool(re.match(r"^[0-9a-f]{64}$", n))
old_sha = set(); v_h = []
# sha: benign + malicious raw + 614 malware moi + v3 benign (import_v3)
for sub in ("data/raw/benign", "data/raw/malicious"):
    if os.path.isdir(sub):
        for n in os.listdir(sub):
            if hex64(n): old_sha.add(n)
for fam in ("Zeus", "Gozi", "Zloader", "Ramnit"):
    d = f"data/raw/pilot_v4_malicious/{fam}"
    if os.path.isdir(d):
        for n in os.listdir(d):
            if hex64(n): old_sha.add(n)
imp_v3 = os.path.join(WORK, "import_v3")
if os.path.isdir(imp_v3):
    for n in os.listdir(imp_v3):
        if hex64(n): old_sha.add(n)
# ppdeep refs: dung cache co san + bo sung benign/v3
for cache in ("old_mal_ppdeep.json", "pilot_v4_ppdeep.json"):
    p = os.path.join(WORK, cache)
    if os.path.isfile(p):
        try: v_h.extend(json.load(open(p)).values())
        except Exception: pass
# benign ppdeep (cache rieng)
bcache = os.path.join(WORK, "v12_benign_ppdeep.json")
if os.path.isfile(bcache):
    bh = json.load(open(bcache))
else:
    bh = {}
    for n in os.listdir("data/raw/benign"):
        if hex64(n):
            try: bh[n] = ppdeep.hash(open(f"data/raw/benign/{n}", "rb").read())
            except Exception: pass
    json.dump(bh, open(bcache, "w"))
v_h.extend(bh.values())
# v3 benign ppdeep
if os.path.isdir(imp_v3):
    v3cache = os.path.join(WORK, "v3_benign_ppdeep.json")
    if os.path.isfile(v3cache):
        v3h = json.load(open(v3cache))
    else:
        v3h = {}
        for n in os.listdir(imp_v3):
            if hex64(n):
                try: v3h[n] = ppdeep.hash(open(os.path.join(imp_v3, n), "rb").read())
                except Exception: pass
        json.dump(v3h, open(v3cache, "w"))
    v_h.extend(v3h.values())
v_h = [h for h in v_h if h]
print(f"[dedup refs] sha={len(old_sha)} ppdeep={len(v_h)}", flush=True)

# v2 apps da thu (bo qua theo orig_name)
v2_apps = set()
if os.path.exists("docs/dataset_v2_manifest.jsonl"):
    for l in open("docs/dataset_v2_manifest.jsonl"):
        o = (json.loads(l).get("orig_name") or "")
        if "/" in o: v2_apps.add(o.split("/")[0].lower())

# ---------- resume ----------
done_apps = set(); kept_shas = set(); cell_count = {c: 0 for c in TARGET_CELLS}
if os.path.exists(STATE):
    for l in open(STATE):
        try: r = json.loads(l)
        except Exception: continue
        if r.get("step") == "app_done": done_apps.add(r["app"])
        if r.get("step") == "kept":
            kept_shas.add(r["sha"])
            c = (r.get("bin"), r.get("sizeb"))
            if c in cell_count: cell_count[c] += 1
print(f"[resume] apps xong={len(done_apps)} kept={len(kept_shas)} cells={cell_count}", flush=True)


def cells_full():
    return all(cell_count[c] >= TARGET_CELLS[c] for c in TARGET_CELLS)


def fetch(url, dst, tries=4):
    for k in range(tries):
        try:
            urllib.request.urlretrieve(url, dst); return True
        except urllib.error.HTTPError as e:
            if e.code in (429, 502, 503) and k < tries - 1:
                time.sleep(10 * (k + 1)); continue
            raise
        except Exception:
            if k < tries - 1: time.sleep(5 * (k + 1)); continue
            raise
    return False


def is_mz(f):
    try:
        with open(f, "rb") as fh: return fh.read(2) == b"MZ"
    except Exception: return False


def stype(f):
    try:
        o = subprocess.run(["7z", "l", "-slt", f], capture_output=True, text=True, errors="replace", timeout=60).stdout
        m = re.search(r"^Type = (.+)$", o, re.M); return m.group(1).strip() if m else None
    except Exception: return None


def bucket_apps(bucket):
    u = f"https://api.github.com/repos/{BUCKET[bucket]}/git/trees/HEAD?recursive=1"
    try:
        d = json.load(urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "p"}), timeout=60))
    except Exception as e:
        print(f"[tree fail] {bucket}: {e}", flush=True); return []
    return [os.path.basename(t["path"])[:-5] for t in d.get("tree", [])
            if t["path"].startswith("bucket/") and t["path"].endswith(".json")]


def manifest(bucket, app):
    u = f"https://raw.githubusercontent.com/{BUCKET[bucket]}/HEAD/bucket/{app}.json"
    return json.load(urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "p"}), timeout=40))


def url64(m):
    a = m.get("architecture", {})
    u = a.get("64bit", {}).get("url") if "64bit" in a else m.get("url")
    if not u: return None
    if isinstance(u, list): u = u[0]
    return u.split("#/")[0]


def take_payload(fp, app, bucket):
    try: data = open(fp, "rb").read()
    except Exception: return None
    sz = len(data)
    if sz == 0 or sz > CAP_SIZE:
        return None
    sha = hashlib.sha256(data).hexdigest()
    if sha in kept_shas or sha in old_sha:
        log(app=app, bucket=bucket, sha=sha, step="dedup_drop", reason="sha256"); return None
    # BIN/O check TRUOC (pefile re) -> chi chay ppdeep (cham) cho payload vao o dich
    b, lk = tc_bin(fp); sb = sizebucket(sz); cell = (b, sb)
    if cell not in TARGET_CELLS:
        log(app=app, bucket=bucket, sha=sha, step="skip_nontarget", reason=f"{b}/{sb}", bin=b, sizeb=sb); return None
    if cell_count[cell] >= TARGET_CELLS[cell]:
        log(app=app, bucket=bucket, sha=sha, step="cell_full", reason=f"{b}/{sb}", bin=b, sizeb=sb); return None
    try: h = ppdeep.hash(data)
    except Exception: h = None
    if h and max((ppdeep.compare(h, bb) for bb in v_h), default=0) >= 90:
        log(app=app, bucket=bucket, sha=sha, step="dedup_drop", reason="ppdeep>=90"); return None
    dst = os.path.join(V4, sha); shutil.copy2(fp, dst)
    kept_shas.add(sha); v_h.append(h) if h else None; cell_count[cell] += 1
    with open(KEPT_SHA, "a") as kf: kf.write(sha + "\n")
    log(app=app, bucket=bucket, sha=sha, step="kept", reason=os.path.basename(fp),
        bin=b, sizeb=sb, linker=lk, size=sz)
    return dst


def process_app(bucket, app):
    try: m = manifest(bucket, app)
    except Exception as e:
        log(app=f"{bucket}:{app}", bucket=bucket, step="app_fail", reason=f"manifest:{e}"); return []
    u = url64(m)
    if not u:
        log(app=f"{bucket}:{app}", bucket=bucket, step="app_fail", reason="no_url"); return []
    d = os.path.join(V4DL, f"{bucket}_{app}"); shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
    dl = os.path.join(d, "dl.bin")
    try: fetch(u, dl)
    except Exception as e:
        log(app=f"{bucket}:{app}", bucket=bucket, step="app_fail", reason=f"dl:{e}")
        shutil.rmtree(d, ignore_errors=True); return []
    pes = []
    if is_mz(dl) and stype(dl) == "PE":
        pes = [dl]
    else:
        ex = os.path.join(d, "x")
        subprocess.run(["7z", "x", "-y", "-o" + ex, dl], capture_output=True, timeout=300)
        for dp, _, fs in os.walk(ex):
            for fn in fs:
                fp = os.path.join(dp, fn)
                if re.search(r"(setup|install|uninst)", fn, re.I): continue      # installer
                if re.match(r"(api-ms-win-|ext-ms-)", fn, re.I): continue          # forwarder
                if THIRD_PARTY.search(fn): continue                                # DLL ben thu ba lap
                if is_mz(fp) and 0 < os.path.getsize(fp) <= CAP_SIZE and stype(fp) == "PE":
                    pes.append(fp)
    pes.sort(key=os.path.getsize, reverse=True)
    out = []
    for p in pes:
        if len(out) >= 3: break    # cap 3 payload/app
        r = take_payload(p, app, bucket)
        if r: out.append(r)
    shutil.rmtree(d, ignore_errors=True)
    return out


def build_batch(paths):
    if not paths: return
    subprocess.run([sys.executable, "scripts/build_graphs.py", *paths, "--label", "0",
                    "--out-dir", V4FEAT, "--failures", V4FAIL, "--out-of-scope", V4OOS,
                    "--workers", str(BUILD_WORKERS), "--timeout", "900", "--append"],
                   capture_output=True, text=True, timeout=7800)
    oos = set()
    if os.path.isfile(V4OOS):
        for l in open(V4OOS):
            try: oos.add(json.loads(l)["sha256"])
            except Exception: pass
    fails = {}
    if os.path.isfile(V4FAIL):
        for l in open(V4FAIL):
            try: r = json.loads(l); fails[r["sha256"]] = r.get("exception_type", "?")
            except Exception: pass
    for p in paths:
        sha = os.path.basename(p)
        jp = os.path.join(V4FEAT, f"{sha}_static.json")
        if os.path.exists(jp):
            try: nf = json.load(open(jp)).get("num_functions")
            except Exception: nf = None
            if nf == 0:
                log(sha=sha, step="nf0_drop", reason="num_functions=0")
                os.remove(os.path.join(V4, sha)) if os.path.exists(os.path.join(V4, sha)) else None
            else:
                log(sha=sha, step="build_ok", reason=f"nf={nf}")
        elif sha in oos:
            log(sha=sha, step="dotnet_drop", reason="dotnet_clr")
        elif sha in fails:
            log(sha=sha, step="build_fail", reason=fails[sha])   # Timeout / ProcessCrash(OOM) / ...
        else:
            log(sha=sha, step="build_fail", reason="no_feature_json")


# ---------- candidate list ----------
cands = []
for bucket in ("Main", "Extras", "Versions"):
    for a in bucket_apps(bucket):
        cands.append((bucket, a))
cands = [(b, a) for (b, a) in cands
         if a.lower() not in v2_apps and f"{b}:{a}" not in done_apps]
cands.sort(key=lambda c: (c[1].lower(), c[0]))
random.Random(V4_SEED).shuffle(cands)
print(f"[cands] tong {len(cands)} app (Main+Extras+Versions, sau loai v2-apps + da-xong)", flush=True)

batch_paths = []; n_app = 0; stop = "het_candidate"
for bucket, app in cands:
    if time.time() - WALL0 > SESSION_CAP:
        stop = "session_cap_7h30"; break
    if cells_full():
        stop = "6_o_da_day"; break
    paths = process_app(bucket, app)
    batch_paths += paths
    log(app=f"{bucket}:{app}", bucket=bucket, step="app_done", reason=f"kept={len(paths)}")
    n_app += 1
    if len(batch_paths) >= BATCH:
        print(f"[batch] build {len(batch_paths)} (workers={BUILD_WORKERS})...", flush=True)
        build_batch(batch_paths); batch_paths = []
        print(f"[cells] {cell_count}", flush=True)
if batch_paths:
    print(f"[final batch] build {len(batch_paths)}...", flush=True); build_batch(batch_paths)

print("\n=== SESSION SUMMARY ===", flush=True)
print(f"stop={stop} apps={n_app} kept_raw={len(kept_shas)} cells={cell_count} "
      f"elapsed={(time.time()-WALL0)/3600:.2f}h", flush=True)
print("DONE harvest_v4_benign", flush=True)
