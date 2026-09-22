"""
check_seed_edge_position_bias.py
Kiem tra: trong cac hop dong bi cat (>50 ham), cac ham CO seed_sem_edges
(bang chung vulnerable) nam o vi tri PC thu bao nhieu - neu da so nam
SAU vi tri 50, xac nhan dung thien vi cat nham noi dung quan trong.
"""
import json
import glob
import os
from collections import Counter

DATA_ROOT = os.environ.get('HIN_DIR_DEFI', '.') + '/data/features_graph'
MAX_FUNCS_PER_PROG = 50

position_of_evidence = Counter()  # vi tri (rank theo PC) cua ham co seed edge
n_contracts_checked = 0
n_contracts_evidence_beyond_cutoff = 0
n_contracts_evidence_total = 0

for fp in glob.glob(os.path.join(DATA_ROOT, '*.json')):
    try:
        with open(fp) as f:
            data = json.load(f)
    except Exception:
        continue

    if data.get('label', 0) != 1:
        continue

    intra = data.get('intra_procedural_graphs', {})
    if len(intra) <= MAX_FUNCS_PER_PROG:
        continue  # chi xet hop dong THAT SU bi cat

    n_contracts_checked += 1
    sorted_keys = sorted(intra.keys(), key=lambda k: int(k.split('_')[1]))

    has_evidence = False
    evidence_beyond_cutoff = False
    for rank, fkey in enumerate(sorted_keys):
        n_seed = len(intra[fkey].get('seed_sem_edges', []))
        if n_seed > 0:
            has_evidence = True
            position_of_evidence[min(rank, 200)] += 1
            if rank >= MAX_FUNCS_PER_PROG:
                evidence_beyond_cutoff = True

    if has_evidence:
        n_contracts_evidence_total += 1
        if evidence_beyond_cutoff:
            n_contracts_evidence_beyond_cutoff += 1

print(f"So hop dong vulnerable BI CAT (>{MAX_FUNCS_PER_PROG} ham) va CO seed_sem_edges: {n_contracts_evidence_total}")
print(f"Trong so do, so hop dong co BANG CHUNG NAM SAU vi tri cat (rank >= {MAX_FUNCS_PER_PROG}): "
      f"{n_contracts_evidence_beyond_cutoff} ({n_contracts_evidence_beyond_cutoff/max(n_contracts_evidence_total,1)*100:.1f}%)")
print(f"\nPhan bo vi tri (rank theo PC) cua ham co seed_sem_edges (10 gia tri dau):")
for rank, count in sorted(position_of_evidence.items())[:10]:
    marker = " <-- SE BI CAT" if rank >= MAX_FUNCS_PER_PROG else ""
    print(f"  rank {rank}: {count} lan{marker}")
print("...")
for rank, count in sorted(position_of_evidence.items())[-10:]:
    marker = " <-- SE BI CAT" if rank >= MAX_FUNCS_PER_PROG else ""
    print(f"  rank {rank}: {count} lan{marker}")
