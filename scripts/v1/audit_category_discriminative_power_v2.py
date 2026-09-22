"""
audit_category_discriminative_power_v2.py
Chay Random Forest RIENG cho tung category (vulnerable-cua-category-do vs
safe) de biet CHINH XAC category nao dang keo chat luong xuong, thay vi
gop chung 5 loai nhu baseline truoc.

CHAY O THU MUC scripts/ (noi co data/features_graph/), KHONG PHAI
download_dataset/ - vi can doc file JSON da trich xuat dac trung, khong
phai slither_progress.jsonl.
"""
import os
import json
import glob
import numpy as np
from collections import defaultdict
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_recall_fscore_support

DATA_ROOT = os.environ.get('HIN_DIR_DEFI', '.') + '/data/features_graph'
RANDOM_STATE = 42

TARGET_CATEGORIES = {"reentrancy", "unchecked-calls", "access-control",
                      "arithmetic", "timestamp-dependence"}

DETECTOR_TO_CATEGORY = {
    "suicidal": "access-control", "arbitrary-send-eth": "access-control",
    "arbitrary-send-erc20": "access-control", "arbitrary-send-erc20-permit": "access-control",
    "unused-return": "unchecked-calls", "unchecked-lowlevel": "unchecked-calls",
    "controlled-array-length": "access-control", "tx-origin": "access-control",
    "divide-before-multiply": "arithmetic", "controlled-delegatecall": "access-control",
    "reentrancy-no-eth": "reentrancy", "reentrancy-eth": "reentrancy",
    "reentrancy-unlimited-gas": "reentrancy", "reentrancy-balance": "reentrancy",
    "unprotected-upgrade": "access-control", "unchecked-send": "locked-ether",
    "unchecked-transfer": "unchecked-calls", "timestamp": "timestamp-dependence",
}

# ===== Doc lai slither_progress.jsonl de biet dia chi nao thuoc category nao =====
# Duong dan tro nguoc ve download_dataset/ - sua neu ban dat o cho khac
SLITHER_PROGRESS = os.path.expanduser("~/Work/Defi/Defi_analysis/download_dataset/slither_progress.jsonl")

addr_to_cats = {}
addr_is_safe = set()
with open(SLITHER_PROGRESS) as f:
    for line in f:
        row = json.loads(line)
        if row["error"]:
            continue
        cats = {DETECTOR_TO_CATEGORY.get(d, "ignore") for d in row["detectors"]}
        real = cats & TARGET_CATEGORIES
        if real:
            addr_to_cats[row["address"]] = real
        elif not (cats - {"ignore"}):
            addr_is_safe.add(row["address"])

print(f"Da nap {len(addr_to_cats)} dia chi vulnerable, {len(addr_is_safe)} dia chi safe tu slither_progress.jsonl")

# ===== Doc feature tu file JSON da trich xuat (data/features_graph/) =====
def extract_features(data):
    intra = data.get('intra_procedural_graphs', {})
    total_nodes = sum(len(g.get('nodes', [])) for g in intra.values())
    total_edges_seq = sum(len(g.get('edges_seq', [])) for g in intra.values())
    total_seed_edges = sum(len(g.get('seed_sem_edges', [])) for g in intra.values())
    inter_edges = data.get('inter_procedural_call_graph', {}).get('num_edges', 0)
    return [
        data.get('mean_entropy', 0.0), data.get('max_entropy', 0.0),
        data.get('min_entropy', 0.0), float(data.get('has_any_external_call', 0)),
        data.get('bytecode_length', 0), data.get('num_functions_detected', 0),
        total_nodes, total_edges_seq, total_seed_edges, inter_edges,
    ]

features_by_addr = {}
for fp in glob.glob(os.path.join(DATA_ROOT, '*.json')):
    addr = os.path.basename(fp).replace('_static.json', '')
    try:
        with open(fp) as f:
            data = json.load(f)
        features_by_addr[addr] = extract_features(data)
    except Exception:
        continue

print(f"Da nap feature cho {len(features_by_addr)} dia chi tu {DATA_ROOT}\n")

# ===== Chay Random Forest RIENG cho tung category =====
safe_addrs = [a for a in addr_is_safe if a in features_by_addr]
print(f"{'Category':22s} {'N':>6s} {'Acc':>8s} {'F1':>8s}   Ket luan")
print("-" * 70)

for cat in sorted(TARGET_CATEGORIES):
    vuln_addrs = [a for a, cats in addr_to_cats.items()
                  if cat in cats and a in features_by_addr]
    n = min(len(vuln_addrs), len(safe_addrs))
    if n < 50:
        print(f"{cat:22s} qua it mau ({n}), bo qua")
        continue

    rng = np.random.RandomState(RANDOM_STATE)
    v_sample = rng.choice(vuln_addrs, n, replace=False)
    s_sample = rng.choice(safe_addrs, n, replace=False)

    X = [features_by_addr[a] for a in v_sample] + [features_by_addr[a] for a in s_sample]
    y = [1] * n + [0] * n
    X, y = np.array(X), np.array(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y)

    model = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE)
    model.fit(X_train, y_train)
    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    f1 = f1_score(y_test, preds)

    flag = ""
    if acc < 0.65:
        flag = "<-- YEU, category nay dang keo chat luong xuong"
    elif acc > 0.85:
        flag = "<-- MANH, tin hieu tot"
    print(f"{cat:22s} {n:6d} {acc:8.4f} {f1:8.4f}   {flag}")
