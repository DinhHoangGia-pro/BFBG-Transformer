"""
audit_label_confidence_v2.py
Kiem tra ty le khop luat tren CA HAI lop (vulnerable va safe) - neu 1 luat
khop ty le gan bang nhau o ca 2 lop, no KHONG con tinh phan biet, la nhieu
chu khong phai tin hieu.
"""
import json
import glob
import os
from collections import Counter

DATA_ROOT = os.environ.get('HIN_DIR_DEFI', '.') + '/data/features_graph'

stats = {0: Counter(), 1: Counter()}
totals = {0: 0, 1: 0}

for fp in glob.glob(os.path.join(DATA_ROOT, '*.json')):
    try:
        with open(fp) as f:
            data = json.load(f)
    except Exception:
        continue
    label = data.get('label', 0)
    totals[label] += 1

    intra = data.get('intra_procedural_graphs', {})
    rules_seen = set()
    for g in intra.values():
        for edge in g.get('seed_sem_edges', []):
            if len(edge) >= 3:
                rules_seen.add(edge[2])
    for r in rules_seen:
        stats[label][r] += 1

print(f"Tong: safe={totals[0]}, vulnerable={totals[1]}\n")
print(f"{'Luat':40s} {'Safe %':>10s} {'Vuln %':>10s} {'Chenh lech':>12s}")
print("-" * 75)
all_rules = set(stats[0].keys()) | set(stats[1].keys())
for rule in sorted(all_rules):
    p_safe = stats[0][rule] / totals[0] * 100 if totals[0] else 0
    p_vuln = stats[1][rule] / totals[1] * 100 if totals[1] else 0
    diff = p_vuln - p_safe
    flag = "  <-- KHONG PHAN BIET, LA NHIEU" if abs(diff) < 15 and p_safe > 30 else ""
    print(f"{rule:40s} {p_safe:9.1f}% {p_vuln:9.1f}% {diff:+11.1f}%{flag}")
