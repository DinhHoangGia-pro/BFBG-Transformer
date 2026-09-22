"""
baseline_simple_features.py
Baseline don gian nhat co the: chi dung feature thong ke (entropy,
bytecode_length, num_functions, has_external_call) qua Logistic Regression
va Random Forest - KHONG dung do thi, KHONG dung GNN, KHONG dung
seed_sem_edges. Neu baseline nay cung chi dat ~0.75-0.80, day la bang
chung tran nam o CHAT LUONG NHAN, khong phai kien truc/feature engineering.

pip install scikit-learn (da co san tu truoc)
"""
import os
import json
import glob
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report

DATA_ROOT = os.environ.get('HIN_DIR_DEFI', '.') + '/data/features_graph'
RANDOM_STATE = 42

X, y = [], []
files = glob.glob(os.path.join(DATA_ROOT, '*.json'))
print(f"Quet {len(files)} file...")

for fp in files:
    try:
        with open(fp) as f:
            data = json.load(f)
    except Exception:
        continue

    label = data.get('label', 0)
    intra = data.get('intra_procedural_graphs', {})

    # Feature bo sung: tong so node/edge tren toan hop dong (khong can
    # duyet do thi phuc tap, chi cong don so luong - van la "thong ke don
    # gian", khong phai hoc bieu dien do thi)
    total_nodes = sum(len(g.get('nodes', [])) for g in intra.values())
    total_edges_seq = sum(len(g.get('edges_seq', [])) for g in intra.values())
    total_seed_edges = sum(len(g.get('seed_sem_edges', [])) for g in intra.values())
    inter_edges = data.get('inter_procedural_call_graph', {}).get('num_edges', 0)

    features = [
        data.get('mean_entropy', 0.0),
        data.get('max_entropy', 0.0),
        data.get('min_entropy', 0.0),
        float(data.get('has_any_external_call', 0)),
        data.get('bytecode_length', 0),
        data.get('num_functions_detected', 0),
        total_nodes,
        total_edges_seq,
        total_seed_edges,
        inter_edges,
    ]
    X.append(features)
    y.append(label)

X = np.array(X, dtype=np.float64)
y = np.array(y, dtype=np.int64)
print(f"Tong mau: {len(y)} | Vulnerable: {sum(y)} | Safe: {len(y)-sum(y)}")

# Can bang 1:1 giong het logic get_balanced_file_paths() de so sanh cong bang
idx_0 = np.where(y == 0)[0]
idx_1 = np.where(y == 1)[0]
n = min(len(idx_0), len(idx_1))
rng = np.random.RandomState(RANDOM_STATE)
chosen_0 = rng.choice(idx_0, n, replace=False)
chosen_1 = rng.choice(idx_1, n, replace=False)
chosen = np.concatenate([chosen_0, chosen_1])
rng.shuffle(chosen)
X, y = X[chosen], y[chosen]
print(f"Sau can bang: {len(y)} mau ({n}/{n})")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y)

scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)

print(f"\nTrain = {len(y_train)} | Test = {len(y_test)}")

for name, model in [
    ("Logistic Regression", LogisticRegression(max_iter=1000, random_state=RANDOM_STATE)),
    ("Random Forest (100 trees)", RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE)),
]:
    model.fit(X_train_s if "Logistic" in name else X_train, y_train)
    preds = model.predict(X_test_s if "Logistic" in name else X_test)
    acc = accuracy_score(y_test, preds)
    p, r, f1, _ = precision_recall_fscore_support(y_test, preds, average='binary', zero_division=0)
    print(f"\n=== {name} ===")
    print(f"Acc={acc:.4f} P={p:.4f} R={r:.4f} F1={f1:.4f}")

    if "Random Forest" in name:
        importances = model.feature_importances_
        feat_names = ["mean_entropy", "max_entropy", "min_entropy", "has_external_call",
                      "bytecode_length", "num_functions", "total_nodes", "total_edges_seq",
                      "total_seed_edges", "inter_edges"]
        print("Feature importance:")
        for fname, imp in sorted(zip(feat_names, importances), key=lambda x: -x[1]):
            print(f"  {fname}: {imp:.4f}")
