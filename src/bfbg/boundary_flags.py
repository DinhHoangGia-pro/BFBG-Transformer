"""
boundary_flags.py
=================
Co danh dau ham angr co the GOP NHAM (nhieu doan code o xa bi tinh chung 1
ham, vd `jmp` toi code cua ham khac bi coi la chuyen tiep noi ham). Dung
chung cho:
  - src/bfbg/bfbg_builder.py: ghi func["boundary_flags"] vao JSON
  - experiments/qa/check_function_boundary_anomalies.py: in chi tiet

Dau vao la dict ham theo schema JSON BFBG (can blocks[].addr/size/
first_idx/num_insns, edges_cfg, addr).

  spread    = (dia chi cuoi cua block cuoi) - (dia chi block dau), byte
  coverage  = tong byte cac block / spread (ham lien mach ~ 1.0)
  segment   = day block lien mach (khe <= gap_tol byte, cho padding can le)
Co:
  SPREAD     spread >= min_spread va coverage < max_coverage
  FAR_UNLINK co segment cach segment truoc > far_gap byte ma KHONG co canh
             CFG nao tu segment khac di vao
  OVERLAP    segment chua dia chi bat dau cua MOT HAM KHAC trong cung mau
Nguong mac dinh doc tu configs/dataset.yaml -> boundary_flags.
"""

import bisect

FLAG_NAMES = ('SPREAD', 'FAR_UNLINK', 'OVERLAP')


def default_params():
    from src.utils.path_resolver import load_config
    return dict(load_config('dataset')['boundary_flags'])


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


def analyze_function(func, other_entries, block_owners, params):
    """Chi tiet ranh gioi 1 ham, hoac None neu thieu blocks[].size."""
    blocks = sorted(func['blocks'], key=lambda b: b['addr'])
    if not blocks or any('size' not in b for b in blocks):
        return None
    start = blocks[0]['addr']
    end = max(b['addr'] + b['size'] for b in blocks)
    spread = end - start
    code_bytes = sum(b['size'] for b in blocks)
    coverage = code_bytes / spread if spread else 1.0
    n_insns = sum(b['num_insns'] for b in blocks)

    segments = split_segments(blocks, params['gap_tol'])
    seg_of_block = {b['addr']: i for i, seg in enumerate(segments) for b in seg}
    # node idx -> dia chi block (de map canh CFG cap lenh ve cap segment)
    starts = sorted((b['first_idx'], b['addr']) for b in blocks)
    first_idx = [s[0] for s in starts]

    def seg_of_node(idx):
        return seg_of_block[starts[bisect.bisect_right(first_idx, idx) - 1][1]]

    incoming = {i: set() for i in range(len(segments))}
    for u, v in func.get('edges_cfg', []):
        su, sv = seg_of_node(u), seg_of_node(v)
        if su != sv:
            incoming[sv].add(su)

    entry_seg = seg_of_block.get(func['addr'], 0)
    flags = []
    if spread >= params['min_spread'] and coverage < params['max_coverage']:
        flags.append('SPREAD')

    far_unlinked = []
    for i in range(1, len(segments)):
        gap = segments[i][0]['addr'] - max(b['addr'] + b['size'] for b in segments[i - 1])
        if gap > params['far_gap'] and i != entry_seg and not incoming[i]:
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
        'addr': func['addr'], 'name': func.get('name', ''), 'n_insns': n_insns, 'n_blocks': len(blocks),
        'spread': spread, 'coverage': coverage, 'segments': seg_ranges, 'far_unlinked': far_unlinked,
        'overlapped': overlapped, 'shared': shared, 'flags': flags,
    }


def analyze_sample(funcs, params=None):
    """funcs: {key: dict ham} cua 1 mau -> {key: ket qua analyze_function (hoac None)}."""
    params = params or default_params()
    entries = {f['addr'] for f in funcs.values()}
    block_owners = {}
    for f in funcs.values():
        for b in f.get('blocks', []):
            block_owners.setdefault(b['addr'], set()).add(f['addr'])
    return {k: analyze_function(f, entries - {f['addr']}, block_owners, params) for k, f in funcs.items()}
