"""
check_seed_rule_fire_rate.py
Dem ty le mau THUC SU kich hoat (fire) moi ky thuat seed ATT&CK tren toan
bo du lieu duong (malicious), tach RIENG hai loai bang chung:
  - seed_edges      : quan he cap node (>=2 API trong cua so / chuoi T1055)
  - node_indicators : 1 lenh goi API don le du lam bang chung
va canh bao ky thuat nao fire (edge HOAC indicator) < --min-fire-rate
(mac dinh 1%).

cross_function_seed_edges (khop chain lien ham 1-hop, Phuong an B -
docs/LESSONS_LEARNED.md muc 2) duoc dem trong bang RIENG, KHONG cong vao
cac cot edge/indicator/bat ky o tren. JSON thieu field nay -> bao loi, dung.

Ly do ton tai: ban EVM cu, luat reentrancy_call_before_sstore chi khop
4/5797 hop dong (0.07%), tx_origin_authorization khop 0 hop dong - luat
nhin dung tren ly thuyet nhung gan nhu khong bao gio khop du lieu that
(xem docs/LESSONS_FROM_EVM_CODEBASE.md). Chay script nay ngay sau moi lan
trich xuat/doi bo luat.

Danh sach ky thuat lay tu ATTACK_SEED_RULES trong
src/semantic/seed_rules_attck.py - BAT BUOC de bat duoc ky thuat fire 0%
(ky thuat khong bao gio xuat hien trong du lieu thi khong the suy ra tu
du lieu). Co the ghi de bang --techniques.

SCHEMA BAT BUOC: moi ham trong JSON phai co ca 'seed_edges' lan
'node_indicators' (src/bfbg/bfbg_builder.py). Thieu field -> BAO LOI va
DUNG, khong in so lieu: neu khong, ky thuat 1-lenh-goi (T1547/T1497/T1071)
se bi bao fire thap GIA do thieu du lieu chu khong phai do luat yeu.

Kem theo (gop tu scripts/v1/audit_extraction_quality.py): ty le mau duong
khong co bang chung nao, phan bo so seed edge/mau, ty le mau bi cat unit.
"""
import argparse
import sys
from collections import Counter

from _common import DATASET_CFG, KEY_LABEL, LABEL_NAMES, MAX_UNITS, add_data_root_arg, iter_samples, \
    list_sample_files, load_techniques, require_evidence_fields, sample_techniques, \
    total_seed_edges, units

KINDS = ('edge', 'indicator', 'any')
KEY_CROSS = 'cross_function_seed_edges'   # cap file JSON, src/bfbg/bfbg_builder.py


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_data_root_arg(parser)
    parser.add_argument('--techniques', nargs='*', default=None,
                        help="Danh sach technique_id (ghi de bang luat trong seed_rules_attck.py)")
    parser.add_argument('--min-fire-rate', type=float, default=DATASET_CFG['qa']['min_fire_rate'],
                        help="Nguong canh bao ty le fire tren mau duong (mac dinh 0.01 = 1%%)")
    parser.add_argument('--max-units', type=int, default=MAX_UNITS,
                        help="Nguong cat so unit moi mau (mac dinh: training.max_functions_per_sample)")
    args = parser.parse_args()

    techniques = load_techniques()
    if args.techniques:
        known = {t[0]: t for t in techniques}
        techniques = [known.get(t, (t, '?', True)) for t in args.techniques]

    samples = list(iter_samples(list_sample_files(args.data_root)))

    require_evidence_fields(samples)   # thieu field -> bao loi va dung, khong in so lieu
    missing_cross = [fp for fp, d in samples if KEY_CROSS not in d]
    if missing_cross:
        print(f"[LOI] {len(missing_cross)}/{len(samples)} file JSON thieu field '{KEY_CROSS}' - KHONG tinh so lieu. "
              f"Dung lai src/bfbg/bfbg_builder.py de sinh lai JSON.", file=sys.stderr)
        for fp in missing_cross[:10]:
            print(f"  {fp}", file=sys.stderr)
        sys.exit(2)
    cross_samples = {label: Counter() for label in (0, 1)}   # technique -> so mau co >=1 canh lien ham
    cross_edges = {label: Counter() for label in (0, 1)}     # technique -> tong so canh lien ham

    fire = {label: {k: Counter() for k in KINDS} for label in (0, 1)}
    totals = Counter()
    n_pos_no_evidence = 0
    seed_count_dist = Counter()
    n_truncated = 0
    n_unlabeled = 0

    for _, data in samples:
        label = data.get(KEY_LABEL)
        if label not in (0, 1):
            n_unlabeled += 1
            continue
        totals[label] += 1
        by_edge, by_ind = sample_techniques(data)
        for t in by_edge:
            fire[label]['edge'][t] += 1
        for t in by_ind:
            fire[label]['indicator'][t] += 1
        for t in by_edge | by_ind:
            fire[label]['any'][t] += 1
        cross = Counter(e['technique_id'] for e in data[KEY_CROSS])
        cross_edges[label].update(cross)
        cross_samples[label].update(set(cross))
        if len(units(data)) > args.max_units:
            n_truncated += 1
        if label == 1:
            seed_count_dist[min(total_seed_edges(data), 20)] += 1
            if not (by_edge or by_ind):
                n_pos_no_evidence += 1

    n_pos, n_neg = totals[1], totals[0]
    n_all = n_pos + n_neg
    print(f"Tong mau: {len(samples)} | {LABEL_NAMES[1]}={n_pos} | {LABEL_NAMES[0]}={n_neg} | chua gan nhan={n_unlabeled}")
    if n_pos == 0:
        print("Khong co mau duong nao - khong the tinh fire rate.")
        return

    technique_ids = {t[0] for t in techniques}
    seen = set(fire[0]['any']) | set(fire[1]['any'])
    unknown = seen - technique_ids

    def pct(label, kind, t):
        n = totals[label]
        return fire[label][kind][t] / n * 100 if n else 0.0

    print(f"\n=== Ty le fire theo technique_id (nguong canh bao: {args.min_fire_rate*100:.2f}% mau duong, "
          f"tinh tren edge HOAC indicator) ===")
    print(f"{'Technique':10s} {'Luat':20s} {'Edge %':>9s} {'Indic. %':>9s} {'Bat ky':>14s} {LABEL_NAMES[0] + ' %':>10s}")
    print("-" * 80)
    low = []
    for tid, name, has_ind in sorted(techniques, key=lambda t: fire[1]['any'][t[0]]):
        any_count = fire[1]['any'][tid]
        rate = any_count / n_pos
        ind_col = f"{pct(1, 'indicator', tid):8.2f}%" if has_ind else f"{'-':>9s}"
        flag = ""
        if rate < args.min_fire_rate:
            flag = "  <-- GAN NHU KHONG BAO GIO KHOP"
            low.append((tid, name, any_count, rate))
        print(f"{tid:10s} {name:20s} {pct(1, 'edge', tid):8.2f}% {ind_col} "
              f"{any_count:5d} ({rate*100:5.2f}%) {pct(0, 'any', tid):9.2f}%{flag}")
    print("('-' = luat khong sinh node_indicator theo thiet ke, vd T1055)")

    if unknown:
        print(f"\n[CANH BAO] technique_id xuat hien trong du lieu nhung KHONG co trong bang luat: {sorted(unknown)}")

    if low:
        print(f"\n[CANH BAO] {len(low)}/{len(techniques)} ky thuat fire < {args.min_fire_rate*100:.2f}% mau duong:")
        for tid, name, count, rate in low:
            print(f"  - {tid} {name}: {count}/{n_pos} ({rate*100:.2f}%)")
        print("  Kiem tra lai dieu kien khop cua luat voi loi goi API that (chuan hoa ten, cua so, "
              "pham vi 1 ham, bien the API A/W/Ex/Nt*).")
    else:
        print(f"\nOK: moi ky thuat deu fire >= {args.min_fire_rate*100:.2f}% mau duong.")

    print(f"\n=== cross_function_seed_edges (lien ham 1-hop) - TACH RIENG, KHONG tinh vao bang tren ===")
    print(f"{'Technique':10s} {'Luat':20s} {LABEL_NAMES[1] + ' mau':>18s} {'canh':>6s} {LABEL_NAMES[0] + ' mau':>18s} {'canh':>6s}")
    print("-" * 84)
    for tid, name, _ in techniques:
        m, b = cross_samples[1][tid], cross_samples[0][tid]
        m_pct = f"{m}/{n_pos} ({m / n_pos * 100:5.1f}%)"
        b_pct = f"{b}/{n_neg} ({b / n_neg * 100:5.1f}%)" if n_neg else "-"
        print(f"{tid:10s} {name:20s} {m_pct:>18s} {cross_edges[1][tid]:6d} {b_pct:>18s} {cross_edges[0][tid]:6d}")

    print(f"\n=== Do phu bang chung tren mau duong ===")
    print(f"KHONG co seed edge lan node indicator nao: {n_pos_no_evidence}/{n_pos} "
          f"({n_pos_no_evidence/n_pos*100:.1f}%)")
    print("Phan bo so seed edge/mau (gop >=20):")
    for n_edges, count in sorted(seed_count_dist.items())[:15]:
        print(f"  {n_edges} edges: {count} mau")
    print(f"\nMau bi cat (> {args.max_units} unit): {n_truncated}/{n_all} ({n_truncated/n_all*100:.1f}%)")


if __name__ == '__main__':
    main()
