#!/usr/bin/env python3
"""Tra cuu VirusTotal theo sha256 (CHI lookup - tier free khong tai mau). Resumable.

- Key doc tu .env (VIRUSTOTAL_API_KEY) - KHONG BAO GIO in/commit.
- Rate-limit: --interval giay giua 2 lan (mac dinh 16s ~ <4/phut, duoi 240/gio).
- Budget: --budget lookup MOI toi da/lan chay (mac dinh 480 < 500/ngay). Resume lan sau.
- Luu THO: data/vt/raw/<sha>.json ; tom tat: data/vt/vt_summary.jsonl (1 dong/sha).
- 200=co; 404=khong thay; 429=cho roi thu lai (khong tinh budget); loi khac=ghi, tiep.
KHONG train, KHONG sua dataset. Chi tra + luu.
"""
import os, sys, json, time, argparse
import requests
REPO = "/home/dhgia/Work/Defi/BFBG-Transformer"
VT_RAW = os.path.join(REPO, "data/vt/raw")
VT_SUMMARY = os.path.join(REPO, "data/vt/vt_summary.jsonl")
API = "https://www.virustotal.com/api/v3/files/"


def load_key():
    for l in open(os.path.join(REPO, ".env")):
        if l.startswith("VIRUSTOTAL_API_KEY="):
            return l.strip().split("=", 1)[1]
    sys.exit("Khong tim thay VIRUSTOTAL_API_KEY trong .env")


def done_shas():
    s = set()
    if os.path.isfile(VT_SUMMARY):
        for l in open(VT_SUMMARY):
            l = l.strip()
            if l:
                try:
                    s.add(json.loads(l)["sha256"])
                except (json.JSONDecodeError, KeyError):
                    pass
    return s


def summarize(sha, tag, status, body):
    row = {"sha256": sha, "tag": tag, "http": status}
    if status == 200:
        a = body.get("data", {}).get("attributes", {})
        st = a.get("last_analysis_stats", {})
        ptc = a.get("popular_threat_classification", {}) or {}
        row.update(
            found=True,
            malicious=st.get("malicious"), suspicious=st.get("suspicious"),
            undetected=st.get("undetected"), harmless=st.get("harmless"),
            suggested_threat_label=ptc.get("suggested_threat_label"),
            popular_threat_name=[d.get("value") for d in ptc.get("popular_threat_name", [])],
            popular_threat_category=[d.get("value") for d in ptc.get("popular_threat_category", [])],
            meaningful_name=a.get("meaningful_name"), type_tag=a.get("type_tag"),
        )
    elif status == 404:
        row.update(found=False)
    else:
        row.update(found=None, note=str(body)[:200])
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tag", required=True, help="malware | benign (nhan vao summary)")
    ap.add_argument("--hashes-file", required=True, help="File, moi dong 1 sha256")
    ap.add_argument("--budget", type=int, default=480, help="So lookup MOI toi da/lan chay")
    ap.add_argument("--interval", type=float, default=16.0, help="Giay giua 2 lookup")
    args = ap.parse_args()

    key = load_key()
    os.makedirs(VT_RAW, exist_ok=True)
    os.makedirs(os.path.dirname(VT_SUMMARY), exist_ok=True)
    want = [l.strip().lower() for l in open(args.hashes_file) if l.strip()]
    done = done_shas()
    todo = [h for h in want if h not in done]
    print(f"tag={args.tag} | tong={len(want)} da_tra={len(want)-len(todo)} con={len(todo)} "
          f"| budget={args.budget} interval={args.interval}s")
    sess = requests.Session()
    sess.headers["x-apikey"] = key
    sf = open(VT_SUMMARY, "a")
    n = 0
    for sha in todo:
        if n >= args.budget:
            print(f"Het budget {args.budget}. Con {len(todo)-n} chua tra (chay lai de resume).")
            break
        # thu lai neu 429
        while True:
            try:
                r = sess.get(API + sha, timeout=30)
            except requests.RequestException as ex:
                print(f"  {sha[:12]} loi mang: {ex}; cho 30s")
                time.sleep(30); continue
            if r.status_code == 429:
                print(f"  {sha[:12]} 429 rate-limit; cho 60s")
                time.sleep(60); continue
            break
        try:
            body = r.json()
        except ValueError:
            body = r.text
        if r.status_code == 200 and isinstance(body, dict):
            with open(os.path.join(VT_RAW, f"{sha}.json"), "w") as rf:
                json.dump(body, rf)
        row = summarize(sha, args.tag, r.status_code, body)
        sf.write(json.dumps(row) + "\n"); sf.flush()
        n += 1
        mal = row.get("malicious")
        print(f"  [{n}/{args.budget}] {sha[:12]} http={r.status_code} "
              f"mal={mal} label={row.get('suggested_threat_label')}")
        time.sleep(args.interval)
    sf.close()
    print(f"Xong lan nay: tra moi {n}. Tong da tra = {len(done)+n}/{len(want)} ({args.tag}).")


if __name__ == "__main__":
    main()
