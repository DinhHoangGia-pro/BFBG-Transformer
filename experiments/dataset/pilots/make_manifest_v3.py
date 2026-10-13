#!/usr/bin/env python
"""Tat dinh: xay dung docs/dataset_v3_manifest.jsonl cho holdout benign moi.
CHUA TAI du lieu -> chay khi da co PE trong --indir. Quy tac: HOLDOUT_V3_PLAN.md.

- Loai sha trung v1/v2 (exact).
- Loai forwarder api-ms-win-*/ext-ms-*.
- Near-dup ppdeep >=90 -> gom cum; khong de 2 mau cung cum; cum trung cum v1/v2 -> loai ca cum.
- orig_name = basename; label=0; split=holdout_v3_benign.
- Sap xep theo sha256 -> ghi + in SHA256 manifest de dong bang.

Usage:
  python make_manifest_v3.py --indir <dir_PE_moi> [--build-feats] [--out docs/dataset_v3_manifest.jsonl]
"""
import os, sys, json, hashlib, argparse, glob

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PPDEEP_THR = 90

def sha256(fp):
    h = hashlib.sha256()
    with open(fp, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()

def load_known():
    known = set(); clusters_known = set()
    for v in ("v1", "v2"):
        p = os.path.join(REPO, "docs", f"dataset_{v}_manifest.jsonl")
        if not os.path.exists(p): continue
        for l in open(p):
            r = json.loads(l); known.add(r["sha256"])
            if r.get("cluster"): clusters_known.add(r["cluster"])
    return known, clusters_known

def is_forwarder(name):
    n = name.lower()
    return n.startswith("api-ms-win-") or n.startswith("ext-ms-")

def dry_run():
    """KHONG tai. Chieu so mau du kien theo (nguon x bin) dung PRIOR tu feat_cache (benign v2 da thu
    tung nguon). Target lay tu HOLDOUT_V3_PLAN.md. Bin chi biet SAU khi tai+phan tich -> day la UOC LUONG
    theo phan phoi lich su, khong phai so that."""
    import collections
    TARGET = {"nirsoft": 40, "scoop": 45, "portableapps": 25}  # HOLDOUT_V3_PLAN muc 1
    BINS = ["MSVC<=10", "MSVC 11-12", "MSVC 14", "GNU/MinGW", "Go", "Delphi", "khac"]
    cachep = os.path.expanduser("~/bfbg_benign_work/feat_cache.jsonl")
    prior = collections.defaultdict(collections.Counter)
    if os.path.exists(cachep):
        for l in open(cachep):
            d = json.loads(l)
            if d.get("label") == 0 and d.get("source") in ("nirsoft", "scoop", "windows11-eval-iso", "chocolatey"):
                prior[d["source"]][d.get("tbin")] += 1
    print("DRY-RUN (chua tai) — chieu holdout v3 theo prior bin tu feat_cache benign v2:")
    print(f"  (prior nguon co: { {k: sum(v.values()) for k,v in prior.items()} })")
    print(f"  portableapps: KHONG co prior -> dung phan phoi benign TONG.")
    tot_prior = collections.Counter()
    for v in prior.values(): tot_prior.update(v)
    def dist(src):
        c = prior.get(src) or tot_prior; n = sum(c.values())
        return {b: c.get(b, 0) / max(n, 1) for b in BINS}
    proj = collections.Counter(); hdr = f"{'nguon':14s}{'n':>5s}  " + " ".join(f"{b[:8]:>8s}" for b in BINS)
    print("  " + hdr)
    for src, n in TARGET.items():
        src_key = "windows11-eval-iso" if src == "iso" else src
        d = dist(src_key if src_key in prior else src)
        row = {b: n * d[b] for b in BINS}
        for b in BINS: proj[b] += row[b]
        print(f"  {src:14s}{n:5d}  " + " ".join(f"{row[b]:8.1f}" for b in BINS))
    N = sum(TARGET.values())
    print(f"  {'TONG(projected)':14s}{N:5d}  " + " ".join(f"{proj[b]:8.1f}" for b in BINS))
    msvc14 = proj['MSVC 14']; nonmsvc = N - msvc14
    print(f"  => du kien MSVC14≈{msvc14:.0f} ({100*msvc14/N:.0f}%), non-MSVC14≈{nonmsvc:.0f} ({100*nonmsvc/N:.0f}%).")
    print(f"  LUU Y: >=30 MSVC14 (muc tieu cho within-bin n_neg lon) {'DAT' if msvc14>=30 else 'CHUA DAT — can uu tien them app MSVC14'}.")
    print("  Day la UOC LUONG theo phan phoi lich su; bin that chi biet sau khi tai + pefile. Chua tai mau nao.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--indir", help="thu muc chua PE benign moi da thu (bat buoc tru khi --dry-run)")
    ap.add_argument("--out", default=os.path.join(REPO, "docs", "dataset_v3_manifest.jsonl"))
    ap.add_argument("--build-feats", action="store_true", help="(tuy) chi lam viec neu feature JSON da build")
    ap.add_argument("--dry-run", action="store_true", help="KHONG tai: chieu so mau du kien theo bin/nguon tu prior feat_cache")
    A = ap.parse_args()
    if A.dry_run:
        dry_run()
        return
    if not A.indir:
        ap.error("--indir bat buoc (tru khi --dry-run)")
    try:
        import ppdeep
    except Exception:
        ppdeep = None
        print("[WARN] ppdeep khong co -> bo buoc near-dup; cai: pip install ppdeep", file=sys.stderr)
    known, clusters_known = load_known()
    files = sorted(glob.glob(os.path.join(A.indir, "**", "*"), recursive=True))
    files = [f for f in files if os.path.isfile(f) and not is_forwarder(os.path.basename(f))]
    if not files:
        print(f"[EMPTY] khong co file trong {A.indir} -> chua tai. Manifest v3 chua tao.")
        return
    rows = []; seen = set(); fuzz = []  # (sha, hash) de gom cum
    featdir = os.path.join(REPO, "data", "features_graph")
    for fp in files:
        try: digest = sha256(fp)
        except Exception: continue
        if digest in known or digest in seen: continue
        seen.add(digest)
        nf = None
        jp = os.path.join(featdir, f"{digest}_static.json")
        if os.path.exists(jp):
            try: nf = json.load(open(jp)).get("num_functions")
            except Exception: nf = None
        fh = None
        if ppdeep:
            try: fh = ppdeep.hash(open(fp, "rb").read())
            except Exception: fh = None
        rows.append(dict(sha256=digest, label=0, source="holdout_v3", split="holdout_v3_benign",
                         orig_name=os.path.basename(fp), num_functions=nf, _fuzz=fh))
    # near-dup clustering (ppdeep): gan cluster id theo sha dai dien nho nhat; loai cum trung v1/v2
    if ppdeep:
        import itertools
        clustered = {}
        for i, a in enumerate(rows):
            if a["_fuzz"] is None: continue
            for b in rows[:i]:
                if b["_fuzz"] is None: continue
                try: sc = ppdeep.compare(a["_fuzz"], b["_fuzz"])
                except Exception: sc = 0
                if sc >= PPDEEP_THR:
                    root = clustered.get(b["sha256"], b["sha256"]); clustered[a["sha256"]] = root; break
        for r in rows:
            r["cluster"] = clustered.get(r["sha256"])  # None = singleton
        # bo 1 mau/cum (giu dai dien dau theo sha), va bo cum neu trung cum v1/v2 (khong the biet fuzz v1/v2 -> chi theo cluster id trung)
        kept = []; used_clusters = set()
        for r in sorted(rows, key=lambda x: x["sha256"]):
            c = r["cluster"]
            if c is None: kept.append(r); continue
            if c in used_clusters: continue
            used_clusters.add(c); kept.append(r)
        rows = kept
    for r in rows: r.pop("_fuzz", None)
    rows.sort(key=lambda x: x["sha256"])
    with open(A.out, "w") as f:
        for r in rows: f.write(json.dumps(r, sort_keys=True) + "\n")
    digest = hashlib.sha256(open(A.out, "rb").read()).hexdigest()
    print(f"v3 manifest: {len(rows)} benign -> {A.out}")
    print(f"SHA256(manifest)={digest}")
    pend = sum(1 for r in rows if r["num_functions"] is None)
    if pend: print(f"[NOTE] {pend} mau chua co feature JSON (num_functions=None) -> build truoc khi dung.")

if __name__ == "__main__":
    main()
