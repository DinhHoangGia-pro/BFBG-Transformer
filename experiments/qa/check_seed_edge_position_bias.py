"""
check_seed_edge_position_bias.py
Port tu scripts/v1/check_seed_edge_position_bias.py.

Kiem tra: trong cac mau malicious bi cat (> --max-units unit), cac unit
(ham/block) CO seed edge (bang chung malicious) nam o vi tri thu bao nhieu
trong binary (rank theo dia chi) - neu da so nam SAU vi tri cat, xac nhan
thien vi cat nham noi dung quan trong.
"""
import argparse
from collections import Counter

from _common import KEY_LABEL, MAX_UNITS, add_data_root_arg, iter_samples, list_sample_files, seed_edges, \
    unit_position, units


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_data_root_arg(parser)
    parser.add_argument('--max-units', type=int, default=MAX_UNITS,
                        help="Nguong cat so unit moi mau (mac dinh: training.max_functions_per_sample)")
    args = parser.parse_args()
    cutoff = args.max_units

    position_of_evidence = Counter()  # vi tri (rank theo dia chi) cua unit co seed edge
    n_samples_evidence_beyond_cutoff = 0
    n_samples_evidence_total = 0

    for _, data in iter_samples(list_sample_files(args.data_root)):
        if data.get(KEY_LABEL, 0) != 1:
            continue

        intra = units(data)
        if len(intra) <= cutoff:
            continue  # chi xet mau THAT SU bi cat

        sorted_keys = sorted(intra.keys(), key=unit_position)

        has_evidence = False
        evidence_beyond_cutoff = False
        for rank, ukey in enumerate(sorted_keys):
            if len(seed_edges(intra[ukey])) > 0:
                has_evidence = True
                position_of_evidence[min(rank, 200)] += 1
                if rank >= cutoff:
                    evidence_beyond_cutoff = True

        if has_evidence:
            n_samples_evidence_total += 1
            if evidence_beyond_cutoff:
                n_samples_evidence_beyond_cutoff += 1

    print(f"So mau malicious BI CAT (>{cutoff} unit) va CO seed edge: {n_samples_evidence_total}")
    print(f"Trong so do, so mau co BANG CHUNG NAM SAU vi tri cat (rank >= {cutoff}): "
          f"{n_samples_evidence_beyond_cutoff} "
          f"({n_samples_evidence_beyond_cutoff/max(n_samples_evidence_total, 1)*100:.1f}%)")
    print(f"\nPhan bo vi tri block trong binary (rank theo dia chi) cua unit co seed edge (10 gia tri dau):")
    for rank, count in sorted(position_of_evidence.items())[:10]:
        marker = " <-- SE BI CAT" if rank >= cutoff else ""
        print(f"  rank {rank}: {count} lan{marker}")
    print("...")
    for rank, count in sorted(position_of_evidence.items())[-10:]:
        marker = " <-- SE BI CAT" if rank >= cutoff else ""
        print(f"  rank {rank}: {count} lan{marker}")


if __name__ == '__main__':
    main()
