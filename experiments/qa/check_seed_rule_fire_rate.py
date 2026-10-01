"""
check_seed_rule_fire_rate.py
Dem ty le mau THUC SU kich hoat (fire) moi luat seed tren toan bo du lieu
duong (malicious), canh bao luat nao fire < --min-fire-rate (mac dinh 1%).

Ly do ton tai: ban EVM cu, luat reentrancy_call_before_sstore chi khop
4/5797 hop dong (0.07%), tx_origin_authorization khop 0 hop dong - luat
nhin dung tren ly thuyet nhung gan nhu khong bao gio khop du lieu that
(xem docs/LESSONS_FROM_EVM_CODEBASE.md). Chay script nay ngay sau moi lan
trich xuat/doi bo luat.

Danh sach luat lay tu src/semantic/seed_rules_attck.py (ten luat - rule_name
- cua ATTACK_SEED_RULES; phan tu thu 3 cua moi seed edge trong JSON phai la
rule_name nay) - BAT BUOC de bat duoc luat fire 0% (luat khong
bao gio xuat hien trong du lieu thi khong the suy ra tu du lieu). Co the
ghi de bang --rules.

Kem theo (gop tu scripts/v1/audit_extraction_quality.py): ty le mau duong
khong co seed edge nao, phan bo so seed edge/mau, ty le mau bi cat unit.
"""
import argparse
from collections import Counter

from _common import DATASET_CFG, KEY_LABEL, MAX_UNITS, LABEL_NAMES, add_data_root_arg, iter_samples, list_sample_files, \
    seed_rules, total_seed_edges, units


def load_rule_names():
    """Tra ve danh sach luat tu bang ATT&CK, hoac None neu module chua co."""
    try:
        from src.semantic import seed_rules_attck
    except ImportError:
        return None
    return [rule.name for rule in seed_rules_attck.ATTACK_SEED_RULES]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_data_root_arg(parser)
    parser.add_argument('--rules', nargs='*', default=None,
                        help="Danh sach luat (ghi de danh sach tu seed_rules_attck.py)")
    parser.add_argument('--min-fire-rate', type=float, default=DATASET_CFG['qa']['min_fire_rate'],
                        help="Nguong canh bao ty le fire tren mau duong (mac dinh 0.01 = 1%%)")
    parser.add_argument('--max-units', type=int, default=MAX_UNITS,
                        help="Nguong cat so unit moi mau (mac dinh: training.max_functions_per_sample)")
    args = parser.parse_args()

    rule_names = args.rules or load_rule_names()

    fire = {0: Counter(), 1: Counter()}
    totals = Counter()
    n_pos_zero_seed = 0
    seed_count_dist = Counter()
    n_truncated = 0

    for _, data in iter_samples(list_sample_files(args.data_root)):
        label = data.get(KEY_LABEL, 0)
        totals[label] += 1
        for r in seed_rules(data):
            fire[label][r] += 1
        if len(units(data)) > args.max_units:
            n_truncated += 1
        if label == 1:
            n_seed = total_seed_edges(data)
            seed_count_dist[min(n_seed, 20)] += 1
            if n_seed == 0:
                n_pos_zero_seed += 1

    n_pos, n_neg = totals[1], totals[0]
    n_all = n_pos + n_neg
    print(f"Tong mau: {n_all} | {LABEL_NAMES[1]}={n_pos} | {LABEL_NAMES[0]}={n_neg}")
    if n_pos == 0:
        print("Khong co mau duong nao - khong the tinh fire rate.")
        return

    if rule_names is None:
        rule_names = sorted(set(fire[0]) | set(fire[1]))
        print("\n[CANH BAO] Chua co danh sach luat tu src/semantic/seed_rules_attck.py va khong truyen "
              "--rules: chi xet cac luat XUAT HIEN trong du lieu, luat fire 0% se KHONG bi phat hien.")
    unknown_rules = (set(fire[0]) | set(fire[1])) - set(rule_names)

    print(f"\n=== Ty le fire cua tung luat seed (nguong canh bao: {args.min_fire_rate*100:.2f}% mau duong) ===")
    print(f"{'Luat':40s} {'Fire/duong':>14s} {LABEL_NAMES[1] + ' %':>12s} {LABEL_NAMES[0] + ' %':>10s}")
    print("-" * 80)
    low_rules = []
    for rule in sorted(rule_names, key=lambda r: fire[1][r]):
        rate = fire[1][rule] / n_pos
        rate_neg = fire[0][rule] / n_neg * 100 if n_neg else 0.0
        flag = ""
        if rate < args.min_fire_rate:
            flag = "  <-- GAN NHU KHONG BAO GIO KHOP"
            low_rules.append((rule, fire[1][rule], rate))
        print(f"{rule:40s} {fire[1][rule]:6d}/{n_pos:<7d} {rate*100:11.2f}% {rate_neg:9.2f}%{flag}")

    if unknown_rules:
        print(f"\n[CANH BAO] Luat xuat hien trong du lieu nhung KHONG co trong bang luat: {sorted(unknown_rules)}")

    if low_rules:
        print(f"\n[CANH BAO] {len(low_rules)}/{len(rule_names)} luat fire < {args.min_fire_rate*100:.2f}% mau duong:")
        for rule, count, rate in low_rules:
            print(f"  - {rule}: {count}/{n_pos} ({rate*100:.2f}%)")
        print("  Kiem tra lai dieu kien khop cua luat voi IR/lenh that sinh ra boi compiler "
              "(vd yeu cau 2 lenh lien ke tuyet doi trong khi compiler chen lenh trung gian).")
    else:
        print(f"\nOK: moi luat deu fire >= {args.min_fire_rate*100:.2f}% mau duong.")

    print(f"\n=== Do phu seed tren mau duong ===")
    print(f"KHONG co seed edge nao: {n_pos_zero_seed}/{n_pos} ({n_pos_zero_seed/n_pos*100:.1f}%)")
    print("Phan bo so seed edge/mau (gop >=20):")
    for n_edges, count in sorted(seed_count_dist.items())[:15]:
        print(f"  {n_edges} edges: {count} mau")
    print(f"\nMau bi cat (> {args.max_units} unit): {n_truncated}/{n_all} ({n_truncated/n_all*100:.1f}%)")


if __name__ == '__main__':
    main()
