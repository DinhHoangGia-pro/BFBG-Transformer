"""
audit_label_confidence.py
Do ty le nhan "vulnerable" dang dua tren detector CONFIDENCE THAP
(Informational/Low) thay vi detector dang tin (High/Medium) - day la
nguon nghi ngo lon nhat cho tran ~0.75-0.80 da quan sat duoc.
"""
import json
import glob
import os
from collections import Counter

DATA_ROOT = os.environ.get('HIN_DIR_DEFI', '.') + '/data/features_graph'

# Do CHINH XAC tu bang audit slither --list-detectors da lay truoc do
HIGH_MEDIUM_CONFIDENCE_RULES = {
    "reentrancy_call_before_sstore",       # kh
    "unchecked_external_call_return",
    "integer_overflow_arith_to_storage",
    "tx_origin_authorization",
    "timestamp_dependence",
}

n_vuln = 0
n_zero_seed = 0
n_has_seed = 0
seed_rule_counter = Counter()

for fp in glob.glob(os.path.join(DATA_ROOT, '*.json')):
    try:
        with open(fp) as f:
            data = json.load(f)
    except Exception:
        continue
    if data.get('label', 0) != 1:
        continue
    n_vuln += 1

    intra = data.get('intra_procedural_graphs', {})
    total_seeds = 0
    rules_seen = set()
    for g in intra.values():
        for edge in g.get('seed_sem_edges', []):
            total_seeds += 1
            if len(edge) >= 3:
                rules_seen.add(edge[2])
    for r in rules_seen:
        seed_rule_counter[r] += 1

    if total_seeds == 0:
        n_zero_seed += 1
    else:
        n_has_seed += 1

print(f"Tong hop dong vulnerable: {n_vuln}")
print(f"KHONG co seed_sem_edges (nhan chi den tu Slither, mo hinh khong co bang chung opcode-level de hoc): "
      f"{n_zero_seed} ({n_zero_seed/n_vuln*100:.1f}%)")
print(f"CO seed_sem_edges: {n_has_seed} ({n_has_seed/n_vuln*100:.1f}%)")
print(f"\nPhan bo theo tung luat (1 hop dong co the co nhieu luat):")
for rule, count in seed_rule_counter.most_common():
    print(f"  {rule}: {count} hop dong")
