"""
check_function_boundary_anomalies.py
Phat hien ham angr GOP NHAM (nhieu doan code o xa nhau bi tinh chung 1 ham,
vd tail-call `jmp` toi code cua ham khac) - chieu nguoc lai cua
scripts/v1/inspect_single_contract_funcs.py ban EVM (tach nham JUMPDEST
thanh qua nhieu "ham" nho). Quan trong vi luat seed ATT&CK chi khop TRONG
1 HAM: ranh gioi ham sai thi pham vi khop sai.

Voi moi ham trong JSON BFBG (can field blocks[].size - src/bfbg/bfbg_builder.py):
  spread    = (dia chi cuoi cua block cuoi) - (dia chi block dau), byte
  coverage  = tong byte cac block / spread (ham lien mach ~ 1.0)
  segment   = day block lien mach (khe <= --gap-tol byte, cho padding can le)
Co bat thuong:
  SPREAD     spread >= --min-spread va coverage < --max-coverage
             (spread qua lon so voi luong code that)
  FAR_UNLINK co segment cach segment khac > --far-gap byte ma KHONG co canh
             CFG (jump/fallthrough) nao tu segment khac di vao no
  OVERLAP    segment chua dia chi bat dau cua MOT HAM KHAC trong cung mau
Cot 'shared' = so block cua ham nay cung nam trong ham khac (chi de tham
khao, khong tinh la co).
"""
import argparse
import bisect

from _common import add_data_root_arg, iter_samples, list_sample_files, sample_id, units


def split_segments(blocks, gap_tol):
    """blocks sap theo dia chi -> list segment, moi segment = list block."""
    segments = []
    end = None
    for b in blocks:
        if end is None or b['addr'] > end + gap_tol:
            segments.append([b])
        else:
            segments[-1].append(b)
        end = max(end or 0, b['addr'] + b['size'])
    return segments


def analyze_function(unit, other_entries, block_owners, args):
    blocks = sorted(unit['blocks'], key=lambda b: b['addr'])
    if not blocks or any('size' not in b for b in blocks):
        return None
    start = blocks[0]['addr']
    end = max(b['addr'] + b['size'] for b in blocks)
    spread = end - start
    code_bytes = sum(b['size'] for b in blocks)
    coverage = code_bytes / spread if spread else 1.0
    n_insns = sum(b['num_insns'] for b in blocks)

    segments = split_segments(blocks, args.gap_tol)
    seg_of_block = {b['addr']: i for i, seg in enumerate(segments) for b in seg}
    # node idx -> dia chi block (de map canh CFG cap lenh ve cap segment)
    starts = sorted((b['first_idx'], b['addr']) for b in blocks)
    first_idx = [s[0] for s in starts]

    def seg_of_node(idx):
        return seg_of_block[starts[bisect.bisect_right(first_idx, idx) - 1][1]]

    incoming = {i: set() for i in range(len(segments))}
    for u, v in unit.get('edges_cfg', []):
        su, sv = seg_of_node(u), seg_of_node(v)
        if su != sv:
            incoming[sv].add(su)

    entry_seg = seg_of_block.get(unit['addr'], 0)
    flags = []
    if spread >= args.min_spread and coverage < args.max_coverage:
        flags.append('SPREAD')

    far_unlinked = []
    for i in range(1, len(segments)):
        gap = segments[i][0]['addr'] - max(b['addr'] + b['size'] for b in segments[i - 1])
        if gap > args.far_gap and i != entry_seg and not incoming[i]:
            far_unlinked.append(segments[i][0]['addr'])
    if far_unlinked:
        flags.append('FAR_UNLINK')

    overlapped = sorted({e for seg in segments for e in other_entries
                         if seg[0]['addr'] <= e < max(b['addr'] + b['size'] for b in seg)})
    if overlapped:
        flags.append('OVERLAP')

    shared = sum(1 for b in blocks if len(block_owners.get(b['addr'], ())) > 1)
    seg_ranges = [(seg[0]['addr'], max(b['addr'] + b['size'] for b in seg)) for seg in segments]
    return {
        'addr': unit['addr'], 'name': unit.get('name', ''), 'n_insns': n_insns, 'n_blocks': len(blocks),
        'spread': spread, 'coverage': coverage, 'segments': seg_ranges, 'far_unlinked': far_unlinked,
        'overlapped': overlapped, 'shared': shared, 'flags': flags,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_data_root_arg(parser)
    parser.add_argument('--min-spread', type=int, default=4096, help="Spread toi thieu (byte) de xet co SPREAD")
    parser.add_argument('--max-coverage', type=float, default=0.5, help="Coverage duoi nguong nay -> SPREAD")
    parser.add_argument('--far-gap', type=int, default=1024, help="Khe (byte) giua 2 segment coi la 'xa'")
    parser.add_argument('--gap-tol', type=int, default=16, help="Khe (byte) van coi la lien mach (padding)")
    parser.add_argument('--top', type=int, default=20, help="So ham bat thuong in ra moi mau")
    args = parser.parse_args()

    for fp, data in iter_samples(list_sample_files(args.data_root)):
        intra = units(data)
        entries = {u['addr'] for u in intra.values()}
        block_owners = {}
        for u in intra.values():
            for b in u.get('blocks', []):
                block_owners.setdefault(b['addr'], set()).add(u['addr'])

        results = []
        n_skipped = 0
        for u in intra.values():
            r = analyze_function(u, entries - {u['addr']}, block_owners, args)
            if r is None:
                n_skipped += 1
            else:
                results.append(r)
        anomalies = sorted((r for r in results if r['flags']), key=lambda r: -r['spread'])

        counts = {f: sum(f in r['flags'] for r in results) for f in ('SPREAD', 'FAR_UNLINK', 'OVERLAP')}
        print(f"=== {sample_id(fp)[:16]}... ({data.get('arch', '?')}): {len(results)} ham, "
              f"bat thuong={len(anomalies)} {counts}" + (f", bo qua {n_skipped} (thieu blocks.size)" if n_skipped else ""))
        if not anomalies:
            continue
        print(f"  {'dia chi':>10s} {'ten':28s} {'lenh':>5s} {'spread':>8s} {'cover':>6s} {'seg':>4s} "
              f"{'shared':>6s}  co / chi tiet")
        for r in anomalies[:args.top]:
            detail = []
            if r['far_unlinked']:
                detail.append("seg xa khong canh vao: " + ", ".join(f"{a:#x}" for a in r['far_unlinked']))
            if r['overlapped']:
                detail.append("chua entry ham khac: " + ", ".join(f"{a:#x}" for a in r['overlapped']))
            segs = " ".join(f"[{s:#x}-{e:#x})" for s, e in r['segments'][:4]) + (" ..." if len(r['segments']) > 4 else "")
            print(f"  {r['addr']:#10x} {r['name'][:28]:28s} {r['n_insns']:5d} {r['spread']:8d} {r['coverage']:6.2f} "
                  f"{len(r['segments']):4d} {r['shared']:6d}  {','.join(r['flags'])}")
            print(f"  {'':10s} segment: {segs}" + ("  | " + "; ".join(detail) if detail else ""))
        if len(anomalies) > args.top:
            print(f"  ... va {len(anomalies) - args.top} ham khac")


if __name__ == '__main__':
    main()
