#!/usr/bin/env python
"""Harvest benign holdout v3 theo PHIEN, resumable. Quy tac: docs/V3_RULES_FROZEN.md.
- Tran phien 7h30: het tran -> khong bat dau app moi, ket thuc sach.
- State tung mau -> ~/bfbg_benign_work/v3_state.jsonl (ngoai git): {ts,app,bucket,sha,step,reason}.
  Phien sau bo qua app/sha da xong.
- Batch ~40 payload: download+dedup -> build_graphs --workers 2 -> nghi 5 phut.
- Nhiet GPU >85C keo dai -> tam dung 10'; >90C hoac 3 tam dung lien tiep -> ket thuc sach.
- Raw -> import_v3/ (ngoai data/); feature -> v3_features/ (ngoai data/features_graph). KHONG vao train.
- Cuoi phien: tom tat + commit cuc bo (khong trailer, khong push) mot dong log session.
KHONG sinh manifest o day (Task 4, khi moi phien xong). KHONG cham holdout.
"""
import os, re, sys, json, time, hashlib, shutil, subprocess, urllib.request, warnings, random
warnings.filterwarnings("ignore"); import pefile, ppdeep
os.chdir("/home/dhgia/Work/Defi/BFBG-Transformer"); sys.path.insert(0, ".")

V3_SEED = 20261008
SESSION_CAP = 7.5 * 3600
CAP_SIZE = 12 * 1024 * 1024
BATCH = 40
REST = 300
TEMP_WARN, TEMP_HARD, MAX_PAUSES = 85, 90, 3
TARGET = {"scoop": 75, "nirsoft": 50}   # PortableApps hoan phien sau (khong API sach)
BUCKET = {"Main": "ScoopInstaller/Main", "Extras": "ScoopInstaller/Extras", "Nirsoft": "ScoopInstaller/Nirsoft"}
WORK = os.path.expanduser("~/bfbg_benign_work"); IMP = os.path.join(WORK, "import_v3")
FEAT = os.path.join(WORK, "v3_features"); STATE = os.path.join(WORK, "v3_state.jsonl")
DL = os.path.join(WORK, "v3_dl"); os.makedirs(IMP, exist_ok=True); os.makedirs(FEAT, exist_ok=True); os.makedirs(DL, exist_ok=True)
WALL0 = time.time()

def log(**kw):
    kw["ts"] = round(time.time(), 1)
    with open(STATE, "a") as f: f.write(json.dumps(kw) + "\n")

# ---- resume state ----
done_apps = set(); kept_shas = set(); dropped = 0; kept = 0
if os.path.exists(STATE):
    for l in open(STATE):
        try: r = json.loads(l)
        except: continue
        if r.get("step") == "app_done": done_apps.add(r["app"])
        if r.get("step") == "kept": kept_shas.add(r["sha"]);
    kept = len(kept_shas)
print(f"[resume] app xong truoc: {len(done_apps)} | sha giu truoc: {len(kept_shas)}", flush=True)

# ---- v1/v2 dedup refs ----
v_sha = set(); v_h = []
bdir = "data/raw/benign"
for n in os.listdir(bdir):
    p = os.path.join(bdir, n)
    if re.match(r"^[0-9a-f]{64}$", n) and os.path.isfile(p):
        v_sha.add(n)
        try: v_h.append(ppdeep.hash(open(p, "rb").read()))
        except: pass
# v2 orig_name apps da thu (bo qua)
v2_apps = set()
for mf in ("docs/dataset_v2_manifest.jsonl",):
    if os.path.exists(mf):
        for l in open(mf):
            o = json.loads(l).get("orig_name") or ""
            if "/" in o: v2_apps.add(o.split("/")[0].lower())
print(f"[dedup refs] v1/v2 benign sha={len(v_sha)} ppdeep={len(v_h)} | v2 apps skip={len(v2_apps)}", flush=True)

def gpu_temp():
    try: return int(subprocess.run(["nvidia-smi","--query-gpu=temperature.gpu","--format=csv,noheader"],capture_output=True,text=True,timeout=10).stdout.strip().split("\n")[0])
    except: return 0
def is_mz(f):
    try:
        with open(f, "rb") as fh: return fh.read(2) == b"MZ"
    except: return False
def stype(f):
    try:
        o = subprocess.run(["7z","l","-slt",f],capture_output=True,text=True,errors="replace",timeout=60).stdout
        m = re.search(r"^Type = (.+)$", o, re.M); return m.group(1).strip() if m else None
    except: return None
def bucket_apps(bucket):
    u = f"https://api.github.com/repos/{BUCKET[bucket]}/git/trees/HEAD?recursive=1"
    try:
        d = json.load(urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "p"}), timeout=60))
    except Exception as e:
        print(f"[tree fail] {bucket}: {e}", flush=True); return []
    return [os.path.basename(t["path"])[:-5] for t in d.get("tree", []) if t["path"].startswith("bucket/") and t["path"].endswith(".json")]
def manifest(bucket, app):
    u = f"https://raw.githubusercontent.com/{BUCKET[bucket]}/HEAD/bucket/{app}.json"
    return json.load(urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "p"}), timeout=40))
def url64(m):
    a = m.get("architecture", {})
    u = a.get("64bit", {}).get("url") if "64bit" in a else m.get("url")
    if not u: return None
    if isinstance(u, list): u = u[0]
    return u.split("#/")[0]

def thermal_ok(pauses):
    t = gpu_temp()
    if t >= TEMP_HARD:
        print(f"[THERMAL] GPU {t}C >= {TEMP_HARD} -> ket thuc phien sach", flush=True); return False, pauses
    if t >= TEMP_WARN:
        time.sleep(180); t2 = gpu_temp()
        if t2 >= TEMP_WARN:
            pauses += 1; print(f"[THERMAL] GPU {t2}C >= {TEMP_WARN} keo dai -> tam dung 10' (pause #{pauses})", flush=True)
            time.sleep(600)
            if pauses >= MAX_PAUSES: print(f"[THERMAL] {pauses} tam dung lien tiep -> ket thuc sach", flush=True); return False, pauses
        else: pauses = 0
    else: pauses = 0
    return True, pauses

# ---- build a batch with build_graphs --workers 2 ----
def build_batch(paths):
    if not paths: return
    r = subprocess.run([sys.executable, "scripts/build_graphs.py", *paths, "--label", "0",
                        "--out-dir", FEAT, "--workers", "2", "--append"],
                       capture_output=True, text=True, timeout=7200)
    for p in paths:
        sha = os.path.basename(p)
        jp = os.path.join(FEAT, f"{sha}_static.json")
        if os.path.exists(jp):
            try: nf = json.load(open(jp)).get("num_functions")
            except: nf = None
            if nf == 0: log(app="?", sha=sha, step="nf0_drop", reason="num_functions=0");
            else: log(app="?", sha=sha, step="build_ok", reason=f"nf={nf}")
        else:
            log(app="?", sha=sha, step="build_fail", reason="no feature json")

def take_payload(fp, app, bucket):
    global kept, dropped
    try: data = open(fp, "rb").read()
    except: return None
    sha = hashlib.sha256(data).hexdigest()
    if sha in kept_shas or sha in v_sha:
        log(app=app, bucket=bucket, sha=sha, step="dedup_drop", reason="sha256"); dropped += 1; return None
    try: h = ppdeep.hash(data)
    except: h = None
    if h and max((ppdeep.compare(h, b) for b in v_h), default=0) >= 90:
        log(app=app, bucket=bucket, sha=sha, step="dedup_drop", reason="ppdeep>=90"); dropped += 1; return None
    dst = os.path.join(IMP, sha); shutil.copy2(fp, dst)
    kept_shas.add(sha); v_h.append(h) if h else None; kept += 1
    log(app=app, bucket=bucket, sha=sha, step="kept", reason=os.path.basename(fp))
    return dst

def process_app(bucket, app):
    """tra ve list payload paths da giu (sau dedup, size, installer, forwarder, cap 3/app)."""
    try: m = manifest(bucket, app)
    except Exception as e: log(app=app, bucket=bucket, step="app_fail", reason=f"manifest:{e}"); return []
    u = url64(m)
    if not u: log(app=app, bucket=bucket, step="app_fail", reason="no_url"); return []
    d = os.path.join(DL, f"{bucket}_{app}"); shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
    dl = os.path.join(d, "dl.bin")
    try: urllib.request.urlretrieve(u, dl)
    except Exception as e: log(app=app, bucket=bucket, step="app_fail", reason=f"dl:{e}"); return []
    pes = []
    if is_mz(dl) and stype(dl) == "PE": pes = [dl]
    else:
        ex = os.path.join(d, "x"); subprocess.run(["7z", "x", "-y", "-o" + ex, dl], capture_output=True, timeout=300)
        for dp, _, fs in os.walk(ex):
            for fn in fs:
                fp = os.path.join(dp, fn)
                if re.search(r"(setup|install|uninst)", fn, re.I): continue
                if re.match(r"(api-ms-win-|ext-ms-)", fn, re.I): continue
                if is_mz(fp) and 0 < os.path.getsize(fp) <= CAP_SIZE and stype(fp) == "PE": pes.append(fp)
    pes.sort(key=os.path.getsize, reverse=True)
    out = []
    for p in pes:
        if len(out) >= 3: break
        dst = take_payload(p, app, bucket)
        if dst: out.append(dst)
    shutil.rmtree(d, ignore_errors=True)
    return out

# ---- candidate list (deterministic) ----
cands = []
for bucket in ("Main", "Extras"):
    for a in bucket_apps(bucket): cands.append(("scoop", bucket, a))
for a in bucket_apps("Nirsoft"): cands.append(("nirsoft", "Nirsoft", a))
rnd = random.Random(V3_SEED)
cands = [c for c in cands if c[2].lower() not in v2_apps and f"{c[1]}:{c[2]}" not in done_apps and c[2].lower() not in done_apps]
cands.sort(key=lambda c: (c[0], c[2].lower()))
rnd.shuffle(cands)
print(f"[cands] {len(cands)} app ung vien (sau loai v2-apps + da-xong)", flush=True)

got = {"scoop": 0, "nirsoft": 0}
for s in kept_shas: pass  # got counted via state below (approx by source not tracked per-sha; dung TARGET tren tong)
batch_paths = []; pauses = 0; n_app = 0; stop_reason = "het_candidate"
for src, bucket, app in cands:
    if time.time() - WALL0 > SESSION_CAP:
        stop_reason = "session_cap_7h30"; break
    if got.get(src, 0) >= TARGET.get(src, 0): continue
    ok, pauses = thermal_ok(pauses)
    if not ok: stop_reason = "thermal"; break
    paths = process_app(bucket, app)
    got[src] = got.get(src, 0) + len(paths)
    batch_paths += paths
    log(app=f"{bucket}:{app}", bucket=bucket, step="app_done", reason=f"kept={len(paths)}")
    n_app += 1
    if len(batch_paths) >= BATCH:
        print(f"[batch] build {len(batch_paths)} payload (workers=2)...", flush=True)
        build_batch(batch_paths); batch_paths = []
        print(f"[rest] nghi {REST}s", flush=True); time.sleep(REST)
if batch_paths:
    print(f"[final batch] build {len(batch_paths)}...", flush=True); build_batch(batch_paths)

# ---- summary ----
from collections import Counter
steps = Counter()
for l in open(STATE):
    try: steps[json.loads(l)["step"]] += 1
    except: pass
summary = (f"stop={stop_reason} apps_xu_ly={n_app} kept_tong={len(kept_shas)} "
           f"dedup_drop={steps.get('dedup_drop',0)} build_ok={steps.get('build_ok',0)} "
           f"nf0_drop={steps.get('nf0_drop',0)} build_fail={steps.get('build_fail',0)} app_fail={steps.get('app_fail',0)} "
           f"got={got} elapsed={ (time.time()-WALL0)/3600:.2f}h")
print("\n=== SESSION SUMMARY ===\n" + summary, flush=True)
with open(os.path.join(WORK, "v3_session_summary.txt"), "w") as f: f.write(summary + "\n")
print("DONE harvest_v3 session", flush=True)
