"""
check_seed_edge_position_bias.py
Port tu scripts/v1/check_seed_edge_position_bias.py.

Kiem tra: trong cac mau malicious bi cat (> --max-units unit), cac unit
(ham/block) CO bang chung (seed edge hoac node indicator) nam o vi tri thu
bao nhieu trong binary (rank theo dia chi) - neu da so nam SAU vi tri cat,
xac nhan thien vi cat nham noi dung quan trong.

Tach rieng theo technique_id va theo loai bang chung (seed_edges /
node_indicators); "MAT HET" = moi bang chung cua ky thuat do trong mau
deu nam sau vi tri cat, tuc mo hinh se khong thay ky thuat nay chut nao.
"""
import argparse
from collections import Counter

from _common import KEY_LABEL, MAX_UNITS, add_data_root_arg, iter_samples, list_sample_files, load_techniques, \
    require_evidence_fields, unit_evidence, unit_position, units

KINDS = ('edge', 'indicator', 'any')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_data_root_arg(parser)
    parser.add_argument('--max-units', type=int, default=MAX_UNITS,
                        help="Nguong cat so unit moi mau (mac dinh: training.max_functions_per_sample)")
    args = parser.parse_args()
    cutoff = args.max_units

    samples = list(iter_samples(list_sample_files(args.data_root)))
    require_evidence_fields(samples)

    position_of_evidence = {k: Counter() for k in KINDS}   # rank -> so unit co bang chung loai k
    n_with = {k: Counter() for k in KINDS}       # technique -> so mau (bi cat) co bang chung
    n_beyond = {k: Counter() for k in KINDS}     # technique -> so mau co it nhat 1 bang chung sau vi tri cat
    n_lost = {k: Counter() for k in KINDS}       # technique -> so mau MAT HET bang chung khi cat
    n_samples_evidence_total = 0
    n_samples_evidence_beyond_cutoff = 0

    for _, data in samples:
        if data.get(KEY_LABEL) != 1:
            continue

        intra = units(data)
        if len(intra) <= cutoff:
            continue  # chi xet mau THAT SU bi cat

        ranks = {k: {} for k in KINDS}   # kind -> technique -> [rank cua unit co bang chung]
        for rank, ukey in enumerate(sorted(intra.keys(), key=unit_position)):
            by_edge, by_ind = unit_evidence(intra[ukey])
            for kind, techs in (('edge', set(by_edge)), ('indicator', set(by_ind)),
                                ('any', set(by_edge) | set(by_ind))):
                if techs:
                    position_of_evidence[kind][min(rank, 200)] += 1
                for t in techs:
                    ranks[kind].setdefault(t, []).append(rank)

        for kind in KINDS:
            for t, rs in ranks[kind].items():
                n_with[kind][t] += 1
                if max(rs) >= cutoff:
                    n_beyond[kind][t] += 1
                if min(rs) >= cutoff:
                    n_lost[kind][t] += 1

        all_ranks = [r for rs in ranks['any'].values() for r in rs]
        if all_ranks:
            n_samples_evidence_total += 1
            if max(all_ranks) >= cutoff:
                n_samples_evidence_beyond_cutoff += 1

    print(f"So mau malicious BI CAT (>{cutoff} unit) va CO bang chung (seed edge hoac node indicator): "
          f"{n_samples_evidence_total}")
    print(f"Trong so do, so mau co BANG CHUNG NAM SAU vi tri cat (rank >= {cutoff}): "
          f"{n_samples_evidence_beyond_cutoff} "
          f"({n_samples_evidence_beyond_cutoff/max(n_samples_evidence_total, 1)*100:.1f}%)")

    names = {t[0]: t[1] for t in load_techniques()}
    techs = sorted(set(names) | set(n_with['any']))
    print(f"\n=== Theo technique_id (mau bi cat) ===")
    print(f"{'Ky thuat':28s} {'Loai':10s} {'Co':>6s} {'Co sau cat':>11s} {'MAT HET':>9s}")
    print("-" * 70)
    for t in techs:
        for kind in KINDS:
            label = f"{t} {names.get(t, '?')}" if kind == 'edge' else ""
            print(f"{label:28s} {kind:10s} {n_with[kind][t]:6d} {n_beyond[kind][t]:11d} {n_lost[kind][t]:9d}")

    for kind in KINDS:
        dist = sorted(position_of_evidence[kind].items())
        if not dist:
            continue
        print(f"\nPhan bo vi tri block trong binary (rank theo dia chi) cua unit co bang chung loai '{kind}':")
        for rank, count in dist[:10]:
            marker = " <-- SE BI CAT" if rank >= cutoff else ""
            print(f"  rank {rank}: {count} lan{marker}")
        if len(dist) > 10:
            print("...")
            for rank, count in dist[-10:]:
                marker = " <-- SE BI CAT" if rank >= cutoff else ""
                print(f"  rank {rank}: {count} lan{marker}")


if __name__ == '__main__':
    main()
