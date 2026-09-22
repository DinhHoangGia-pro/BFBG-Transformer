"""
audit_extraction_quality.py
Kiem tra 2 nghi van ve chat luong dac trung tren TOAN BO du lieu da trich
xuat san (10.513 file), khong can train lai.
"""
import os
import json
import glob
from collections import Counter

DATA_ROOT = os.environ.get('HIN_DIR_DEFI', '.') + '/data/features_graph'
files = glob.glob(os.path.join(DATA_ROOT, '*.json'))
print(f"Quet {len(files)} file...")

MAX_FUNCS_PER_PROG = 50

n_truncated = 0
n_total = 0
func_count_dist = Counter()

n_vuln_total = 0
n_vuln_with_seed_edges = 0
n_vuln_zero_seed_edges = 0
seed_edge_count_dist = Counter()

for fp in files:
    try:
        with open(fp) as f:
            data = json.load(f)
    except Exception:
        continue

    n_total += 1
    intra = data.get('intra_procedural_graphs', {})
    n_funcs = len(intra)
    func_count_dist[min(n_funcs, 100)] += 1  # gop tat ca >=100 vao 1 bucket

    if n_funcs > MAX_FUNCS_PER_PROG:
        n_truncated += 1

    label = data.get('label', 0)
    if label == 1:
        n_vuln_total += 1
        total_seed_edges = sum(len(g.get('seed_sem_edges', [])) for g in intra.values())
        seed_edge_count_dist[min(total_seed_edges, 20)] += 1
        if total_seed_edges > 0:
            n_vuln_with_seed_edges += 1
        else:
            n_vuln_zero_seed_edges += 1

print(f"\n=== NGHI VAN 1: MAX_FUNCS_PER_PROG=50 co cat mat ham khong ===")
print(f"Tong so hop dong: {n_total}")
print(f"So hop dong co >50 ham (BI CAT BOT): {n_truncated} ({n_truncated/n_total*100:.1f}%)")
print(f"Phan bo so ham/hop dong (10 gia tri pho bien nhat):")
for n_funcs, count in func_count_dist.most_common(10):
    print(f"  {n_funcs} ham: {count} hop dong")

print(f"\n=== NGHI VAN 2: seed_sem_edges co rong o hop dong vulnerable khong ===")
print(f"Tong so hop dong vulnerable: {n_vuln_total}")
print(f"Co it nhat 1 seed_sem_edge: {n_vuln_with_seed_edges} ({n_vuln_with_seed_edges/n_vuln_total*100:.1f}%)")
print(f"KHONG CO seed_sem_edge nao (RONG): {n_vuln_zero_seed_edges} ({n_vuln_zero_seed_edges/n_vuln_total*100:.1f}%)")
print(f"Phan bo so seed_sem_edges/hop dong:")
for n_edges, count in sorted(seed_edge_count_dist.items())[:15]:
    print(f"  {n_edges} edges: {count} hop dong")
