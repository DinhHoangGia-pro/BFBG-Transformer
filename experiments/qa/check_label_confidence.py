"""
check_label_confidence.py
Port tu scripts/v1/audit_label_confidence.py + audit_label_confidence_v2.py.

Muc tin cay nhan = SO ENGINE DONG THUAN (vd so AV engine tren VirusTotal
gan nhan malicious), doc tu khoa --agreement-key trong JSON; chia tang
high/medium/low theo nguong --high-min/--medium-min. Mau thieu khoa nay
roi vao tang 'unknown'.

Phan 1 (tu v1): trong cac mau malicious, ty le mau KHONG co seed edge nao
  (nhan chi den tu nguon ngoai, mo hinh khong co bang chung muc lenh de
  hoc) - tach theo tung tang tin cay - va phan bo theo tung luat seed.
Phan 2 (tu v2): ty le khop tung luat tren CA HAI lop - luat khop gan bang
  nhau o ca 2 lop thi khong con phan biet, la nhieu chu khong phai tin hieu.
"""
import argparse
from collections import Counter

from _common import DATASET_CFG, KEY_LABEL, LABEL_NAMES, add_data_root_arg, iter_samples, list_sample_files, \
    seed_rules, total_seed_edges

TIERS = ['high', 'medium', 'low', 'unknown']


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

    tier_total = Counter()
    tier_zero_seed = Counter()
    tier_has_seed = Counter()
    mal_rule_counter = Counter()

    rule_stats = {0: Counter(), 1: Counter()}
    totals = {0: 0, 1: 0}

    for _, data in iter_samples(list_sample_files(args.data_root)):
        label = data.get(KEY_LABEL, 0)
        rules_seen = seed_rules(data)
        totals[label] += 1
        for r in rules_seen:
            rule_stats[label][r] += 1

        if label != 1:
            continue
        tier = confidence_tier(data, args.agreement_key, args.high_min, args.medium_min)
        tier_total[tier] += 1
        if total_seed_edges(data) == 0:
            tier_zero_seed[tier] += 1
        else:
            tier_has_seed[tier] += 1
        for r in rules_seen:
            mal_rule_counter[r] += 1

    n_mal = sum(tier_total.values())
    if n_mal == 0:
        print("Khong co mau malicious nao.")
        return

    # === Phan 1 ===
    print(f"=== PHAN 1: do phu seed edge tren mau malicious, theo muc tin cay nhan "
          f"('{args.agreement_key}': high>={args.high_min}, medium>={args.medium_min}) ===")
    print(f"Tong mau malicious: {n_mal}\n")
    print(f"{'Tang':10s} {'N':>7s} {'Khong seed':>16s} {'Co seed':>16s}")
    print("-" * 52)
    for tier in TIERS + ['TONG']:
        if tier == 'TONG':
            n, z, h = n_mal, sum(tier_zero_seed.values()), sum(tier_has_seed.values())
        else:
            n, z, h = tier_total[tier], tier_zero_seed[tier], tier_has_seed[tier]
        if n == 0:
            continue
        print(f"{tier:10s} {n:7d} {z:7d} ({z/n*100:5.1f}%) {h:7d} ({h/n*100:5.1f}%)")

    print(f"\nPhan bo theo tung luat (1 hop dong co the co nhieu luat):")
    for rule, count in mal_rule_counter.most_common():
        print(f"  {rule}: {count} mau")

    # === Phan 2 ===
    b, m = LABEL_NAMES[0], LABEL_NAMES[1]
    print(f"\n=== PHAN 2: ty le khop luat tren ca hai lop ===")
    print(f"Tong: {b}={totals[0]}, {m}={totals[1]}\n")
    print(f"{'Luat':40s} {b + ' %':>10s} {m + ' %':>12s} {'Chenh lech':>12s}")
    print("-" * 77)
    all_rules = set(rule_stats[0]) | set(rule_stats[1])
    for rule in sorted(all_rules):
        p_ben = rule_stats[0][rule] / totals[0] * 100 if totals[0] else 0
        p_mal = rule_stats[1][rule] / totals[1] * 100 if totals[1] else 0
        diff = p_mal - p_ben
        flag = "  <-- KHONG PHAN BIET, LA NHIEU" if abs(diff) < 15 and p_ben > 30 else ""
        print(f"{rule:40s} {p_ben:9.1f}% {p_mal:11.1f}% {diff:+11.1f}%{flag}")


if __name__ == '__main__':
    main()
