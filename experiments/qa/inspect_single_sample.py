"""
inspect_single_sample.py
Port tu scripts/v1/inspect_single_contract_funcs.py.

Xem chi tiet 1 mau - kiem tra xem heuristic tach unit (ham/block) co qua
nhay (over-segmenting) khong: kich thuoc tung unit, so unit rat nho.

Chon mau bang --sample (duong dan hoac sample_id), hoac mau dau tien co
dung --num-units unit.
"""
import argparse
import json
import os

from collections import Counter

from _common import KEY_NODES, KEY_UNITS, add_data_root_arg, iter_samples, list_sample_files, load_techniques, \
    require_evidence_fields, sample_id, unit_evidence, unit_position, units


def find_sample(args):
    if args.sample:
        fp = args.sample if os.path.isfile(args.sample) else next(
            (f for f in list_sample_files(args.data_root) if sample_id(f) == args.sample), None)
        if fp is None:
            raise SystemExit(f"Khong tim thay mau {args.sample} trong {args.data_root}")
        with open(fp) as f:
            return fp, json.load(f)
    for fp, data in iter_samples(list_sample_files(args.data_root)):
        if len(units(data)) == args.num_units:
            return fp, data
    raise SystemExit(f"Khong co mau nao co dung {args.num_units} unit")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_data_root_arg(parser)
    parser.add_argument('--sample', default=None, help="Duong dan file JSON hoac sample_id")
    parser.add_argument('--num-units', type=int, default=100, help="Chon mau dau tien co dung N unit")
    parser.add_argument('--show', type=int, default=15, help="So unit dau tien in ra")
    parser.add_argument('--tiny-max-nodes', type=int, default=3, help="Unit <= N node bi coi la nghi ngo")
    args = parser.parse_args()

    fp, data = find_sample(args)
    require_evidence_fields([(fp, data)])
    intra = units(data)
    print(f"File mau: {fp}")
    print(f"sample_id: {sample_id(fp)}")
    for k, v in data.items():
        if k != KEY_UNITS and isinstance(v, (str, int, float, bool)):
            print(f"{k}: {v}")
    print(f"so unit: {len(intra)}")
    if not intra:
        return

    unit_sizes = sorted(((k, len(v.get(KEY_NODES, []))) for k, v in intra.items()),
                        key=lambda x: unit_position(x[0]))
    print(f"\n{args.show} unit dau tien theo vi tri trong binary (ten, so node ben trong):")
    for name, size in unit_sizes[:args.show]:
        print(f"  {name}: {size} node")

    sizes_only = [s for _, s in unit_sizes]
    print(f"\nThong ke kich thuoc: min={min(sizes_only)}, max={max(sizes_only)}, "
          f"trung binh={sum(sizes_only)/len(sizes_only):.1f}")
    print(f"So unit co <={args.tiny_max_nodes} node (rat nghi ngo la unit gia do heuristic tach): "
          f"{sum(1 for s in sizes_only if s <= args.tiny_max_nodes)}/{len(sizes_only)}")

    # === Bang chung seed theo technique_id (seed_edges va node_indicators tach rieng) ===
    names = {t[0]: t[1] for t in load_techniques()}
    total_edge, total_ind = Counter(), Counter()
    units_with_evidence = []
    for k in sorted(intra, key=unit_position):
        by_edge, by_ind = unit_evidence(intra[k])
        total_edge.update(by_edge)
        total_ind.update(by_ind)
        if by_edge or by_ind:
            units_with_evidence.append((k, intra[k].get('name', ''), by_edge, by_ind))

    print(f"\nBang chung seed theo ky thuat (so seed edge / so node indicator):")
    for t in sorted(set(names) | set(total_edge) | set(total_ind)):
        print(f"  {t} {names.get(t, '?'):20s} edge={total_edge[t]:4d}  indicator={total_ind[t]:4d}")
    print(f"\nUnit co bang chung: {len(units_with_evidence)}/{len(intra)}")
    for k, name, by_edge, by_ind in units_with_evidence[:args.show]:
        print(f"  {k} {name}: edge={dict(by_edge)} indicator={dict(by_ind)}")


if __name__ == '__main__':
    main()
