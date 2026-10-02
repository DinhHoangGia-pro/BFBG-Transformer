"""
check_label_confidence.py
Port tu scripts/v1/audit_label_confidence.py + audit_label_confidence_v2.py.

Muc tin cay nhan = SO ENGINE DONG THUAN (vd so AV engine tren VirusTotal
gan nhan malicious), doc tu khoa --agreement-key trong JSON; chia tang
high/medium/low theo nguong --high-min/--medium-min. Mau thieu khoa nay
roi vao tang 'unknown'.

Bang chung muc lenh gom 2 loai, dem RIENG theo technique_id:
  - seed_edges      : quan he cap node
  - node_indicators : 1 lenh goi API don le

Phan 1 (tu v1): trong cac mau malicious, ty le mau KHONG co bang chung nao
  (nhan chi den tu nguon ngoai, mo hinh khong co bang chung muc lenh de
  hoc) - tach theo tung tang tin cay - va phan bo theo tung ky thuat.
Phan 2 (tu v2): ty le khop tung ky thuat tren CA HAI lop - ky thuat khop
  gan bang nhau o ca 2 lop thi khong con phan biet, la nhieu chu khong phai
  tin hieu.
Phan 3: moi lop, moi technique_id - bang chung nam o ham co boundary_flags
  RONG hay KHONG RONG (angr co the gop nham ham), so voi ty le call site API
  nam o ham bi gan co (lift). Tra loi: ty le fire co tap trung bat thuong o
  ham bi gan co OVERLAP/SPREAD khong. JSON thieu boundary_flags -> bo qua
  phan nay kem canh bao, khong in so lieu.
"""
import argparse
from collections import Counter

from _common import DATASET_CFG, KEY_LABEL, LABEL_NAMES, add_data_root_arg, evidence_by_boundary, \
    has_boundary_flags, iter_samples, list_sample_files, load_techniques, merge_boundary_stats, \
    print_boundary_table, print_caveat_warnings, require_evidence_fields, sample_techniques

TIERS = ['high', 'medium', 'low', 'unknown']
KINDS = ('edge', 'indicator', 'any')


def confidence_tier(data, agreement_key, high_min, medium_min):
    n = data.get(agreement_key)
    if n is None:
        return 'unknown'
    if n >= high_min:
        return 'high'
    if n >= medium_min:
        return 'medium'
    return 'low'


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_data_root_arg(parser)
    labeling = DATASET_CFG['labeling']
    parser.add_argument('--agreement-key', default=labeling['agreement_key'],
                        help="Khoa JSON chua so engine dong thuan nhan malicious")
    parser.add_argument('--high-min', type=int, default=labeling['confidence_tiers']['high_min'],
                        help="So engine toi thieu cho tang high")
    parser.add_argument('--medium-min', type=int, default=labeling['confidence_tiers']['medium_min'],
                        help="So engine toi thieu cho tang medium")
    args = parser.parse_args()

    samples = list(iter_samples(list_sample_files(args.data_root)))
    require_evidence_fields(samples)

    tier_total = Counter()
    tier_no_evidence = Counter()     # khong edge, khong indicator
    tier_indicator_only = Counter()  # chi co indicator
    tier_has_edge = Counter()        # co it nhat 1 seed edge

    stats = {label: {k: Counter() for k in KINDS} for label in (0, 1)}
    totals = Counter()
    n_unlabeled = 0
    boundary = {label: (Counter(), {}) for label in (0, 1)}
    n_missing_boundary = 0

    for _, data in samples:
        label = data.get(KEY_LABEL)
        if label not in (0, 1):
            n_unlabeled += 1
            continue
        by_edge, by_ind = sample_techniques(data)
        totals[label] += 1
        if has_boundary_flags(data):
            merge_boundary_stats(boundary[label], evidence_by_boundary(data))
        else:
            n_missing_boundary += 1
        for kind, techs in (('edge', by_edge), ('indicator', by_ind), ('any', by_edge | by_ind)):
            for t in techs:
                stats[label][kind][t] += 1

        if label != 1:
            continue
        tier = confidence_tier(data, args.agreement_key, args.high_min, args.medium_min)
        tier_total[tier] += 1
        if by_edge:
            tier_has_edge[tier] += 1
        elif by_ind:
            tier_indicator_only[tier] += 1
        else:
            tier_no_evidence[tier] += 1

    n_mal = totals[1]
    if n_unlabeled:
        print(f"(Bo qua {n_unlabeled} mau chua gan nhan)")
    if n_mal == 0:
        print("Khong co mau malicious nao.")
        return

    names = {t[0]: t[1] for t in load_techniques()}

    # === Phan 1 ===
    print(f"=== PHAN 1: do phu bang chung tren mau malicious, theo muc tin cay nhan "
          f"('{args.agreement_key}': high>={args.high_min}, medium>={args.medium_min}) ===")
    print(f"Tong mau malicious: {n_mal}\n")
    print(f"{'Tang':10s} {'N':>7s} {'Khong bang chung':>18s} {'Chi indicator':>16s} {'Co seed edge':>16s}")
    print("-" * 72)
    for tier in TIERS + ['TONG']:
        if tier == 'TONG':
            n, z, i, h = (n_mal, sum(tier_no_evidence.values()), sum(tier_indicator_only.values()),
                          sum(tier_has_edge.values()))
        else:
            n, z, i, h = tier_total[tier], tier_no_evidence[tier], tier_indicator_only[tier], tier_has_edge[tier]
        if n == 0:
            continue
        print(f"{tier:10s} {n:7d} {z:9d} ({z/n*100:5.1f}%) {i:7d} ({i/n*100:5.1f}%) {h:7d} ({h/n*100:5.1f}%)")

    print(f"\nPhan bo theo tung ky thuat tren mau malicious (1 mau co the co nhieu ky thuat):")
    for tid, count in stats[1]['any'].most_common():
        print(f"  {tid} {names.get(tid, '?')}: {count} mau "
              f"(seed edge: {stats[1]['edge'][tid]}, node indicator: {stats[1]['indicator'][tid]})")
    print_caveat_warnings(names)

    # === Phan 2 ===
    b, m = LABEL_NAMES[0], LABEL_NAMES[1]
    print(f"\n=== PHAN 2: ty le khop ky thuat tren ca hai lop (edge / indicator / bat ky) ===")
    print(f"Tong: {b}={totals[0]}, {m}={totals[1]}\n")
    print(f"{'Ky thuat':28s} {'Loai':10s} {b + ' %':>10s} {m + ' %':>12s} {'Chenh lech':>12s}")
    print("-" * 77)
    all_techs = set(stats[0]['any']) | set(stats[1]['any'])
    for tid in sorted(all_techs):
        for kind in KINDS:
            p_ben = stats[0][kind][tid] / totals[0] * 100 if totals[0] else 0
            p_mal = stats[1][kind][tid] / totals[1] * 100 if totals[1] else 0
            diff = p_mal - p_ben
            flag = "  <-- KHONG PHAN BIET, LA NHIEU" if abs(diff) < 15 and p_ben > 30 else ""
            label = f"{tid} {names.get(tid, '?')}" if kind == 'edge' else ""
            print(f"{label:28s} {kind:10s} {p_ben:9.1f}% {p_mal:11.1f}% {diff:+11.1f}%{flag}")
    print_caveat_warnings(names)


    # === Phan 3 ===
    print(f"\n=== PHAN 3: bang chung theo boundary_flags cua ham (clean = khong bi gan co) ===")
    if n_missing_boundary:
        print(f"[CANH BAO] {n_missing_boundary} mau thieu field boundary_flags - BO QUA phan nay (khong in so "
              f"lieu tren du lieu thieu). Dung lai src/bfbg/bfbg_builder.py de sinh lai JSON.")
        return
    for label in (1, 0):
        base, items = boundary[label]
        print_boundary_table(f"{LABEL_NAMES[label]} ({totals[label]} mau)", base, items, names)
    print_caveat_warnings(names)


if __name__ == '__main__':
    main()
