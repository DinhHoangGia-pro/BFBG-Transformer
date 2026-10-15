#!/usr/bin/env python3
"""Doi chieu ket qua VT (data/vt/vt_summary.jsonl). Chay duoc tren ket qua TUNG PHAN.

- malware: so khop nhan MalwareBazaar (theo dong family), lech, hay khong thay.
- benign v1-v3: ap NGUONG TIEN-DANG-KY malicious>=3 -> danh dau nghi ngo (KHONG xoa).
CHI bao cao. Khong sua dataset.
"""
import json, os
from collections import Counter, defaultdict
REPO = "/home/dhgia/Work/Defi/BFBG-Transformer"
SUMMARY = os.path.join(REPO, "data/vt/vt_summary.jsonl")
MANIFEST = os.path.join(REPO, "data/raw/pilot_v4_fetch_manifest.jsonl")
SUSPECT_THR = 3  # tien-dang-ky §7.2

# MB family -> token VT chap nhan (cung dong ma nguon)
FAM_TOKENS = {
    "Zeus":    {"zbot", "zeus"},
    "Gozi":    {"gozi", "ursnif", "isfb", "snifula", "dreambot"},
    "Zloader": {"zloader", "terdot", "deloader", "zbot", "zeus"},  # Zloader = dong Zeus
    "Ramnit":  {"ramnit", "nimnul"},
}


def load(p):
    r = []
    if os.path.isfile(p):
        for l in open(p):
            l = l.strip()
            if l:
                try:
                    r.append(json.loads(l))
                except json.JSONDecodeError:
                    pass
    return r


def main():
    rows = load(SUMMARY)
    by_sha = {r["sha256"]: r for r in rows}
    mb_fam = {}
    for r in load(MANIFEST):
        mb_fam[r["sha256"]] = r["family"]

    # ----- MALWARE consensus -----
    mal = [r for r in rows if r.get("tag") == "malware"]
    print(f"=== VT MALWARE CONSENSUS ({len(mal)} da tra / 614) ===")
    per = defaultdict(lambda: Counter())
    mismatch_examples = defaultdict(list)
    for r in mal:
        fam = mb_fam.get(r["sha256"], "?")
        if r.get("http") == 404 or not r.get("found"):
            per[fam]["khong_tren_VT"] += 1; continue
        toks = set(t.lower() for t in (r.get("popular_threat_name") or []))
        lab = (r.get("suggested_threat_label") or "").lower()
        acc = FAM_TOKENS.get(fam, set())
        hit = bool(toks & acc) or any(a in lab for a in acc)
        mal_n = r.get("malicious") or 0
        if hit:
            per[fam]["khop"] += 1
        elif mal_n >= 3:
            per[fam]["malware_khac_ho"] += 1
            if len(mismatch_examples[fam]) < 5:
                mismatch_examples[fam].append((r["sha256"][:10], lab, list(toks)[:3]))
        else:
            per[fam]["mal_thap/undetected"] += 1
    print(f"{'family':9} {'tra':>4} {'khop':>5} {'khac-ho':>8} {'mal<3':>6} {'ko-VT':>6}")
    tot = Counter()
    for fam in ("Zeus", "Gozi", "Zloader", "Ramnit"):
        c = per[fam]; n = sum(c.values())
        print(f"{fam:9} {n:4d} {c['khop']:5d} {c['malware_khac_ho']:8d} "
              f"{c['mal_thap/undetected']:6d} {c['khong_tren_VT']:6d}")
        tot.update(c)
    print(f"{'TONG':9} {sum(tot.values()):4d} {tot['khop']:5d} {tot['malware_khac_ho']:8d} "
          f"{tot['mal_thap/undetected']:6d} {tot['khong_tren_VT']:6d}")
    for fam, ex in mismatch_examples.items():
        if ex:
            print(f"  [{fam}] vi du khac-ho: {ex}")

    # ----- BENIGN screen -----
    ben = [r for r in rows if r.get("tag") == "benign"]
    if ben:
        print(f"\n=== VT BENIGN SCREEN ({len(ben)} da tra / 669; nguong nghi-ngo malicious>={SUSPECT_THR}) ===")
        suspect = [r for r in ben if (r.get("malicious") or 0) >= SUSPECT_THR]
        flag12 = [r for r in ben if 1 <= (r.get("malicious") or 0) < SUSPECT_THR]
        clean = [r for r in ben if (r.get("malicious") or 0) == 0 and r.get("found")]
        notfound = [r for r in ben if not r.get("found")]
        print(f"nghi-ngo(>={SUSPECT_THR}): {len(suspect)} | 1-2 engine: {len(flag12)} | "
              f"sach(0): {len(clean)} | khong-tren-VT: {len(notfound)}")
        for r in sorted(suspect, key=lambda x: -(x.get("malicious") or 0))[:30]:
            print(f"  SUSPECT {r['sha256'][:12]} mal={r.get('malicious')} "
                  f"label={r.get('suggested_threat_label')}")
        print("** Chi DANH DAU, KHONG xoa khoi v1/v2/v3 da khoa (bat bien). Dung cho ablation metric phu. **")
    else:
        print("\n(Chua tra benign - chay sau khi xong malware.)")


if __name__ == "__main__":
    main()
