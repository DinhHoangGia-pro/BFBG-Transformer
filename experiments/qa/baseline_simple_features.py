"""
baseline_simple_features.py
Port tu scripts/v1/baseline_simple_features.py.

Baseline don gian nhat co the: chi dung feature thong ke qua Logistic
Regression va Random Forest - KHONG dung do thi, KHONG dung GNN. Neu
baseline nay dat gan bang mo hinh chinh, tran nam o CHAT LUONG NHAN, khong
phai kien truc/feature engineering.

Feature set la PLACEHOLDER (entropy, kich thuoc, so API-call, so dem
node/edge) dinh nghia o _common.SIMPLE_FEATURES - dien lai sau khi co
pipeline PE.
"""
import argparse

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from _common import KEY_LABEL, LABEL_NAMES, RANDOM_STATE, SIMPLE_FEATURE_NAMES, add_data_root_arg, \
    iter_samples, list_sample_files, simple_features


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_data_root_arg(parser)
    args = parser.parse_args()

    files = list_sample_files(args.data_root)
    print(f"Quet {len(files)} file...")

    X, y = [], []
    for _, data in iter_samples(files):
        X.append(simple_features(data))
        y.append(data.get(KEY_LABEL, 0))

    X = np.array(X, dtype=np.float64)
    y = np.array(y, dtype=np.int64)
    print(f"Tong mau: {len(y)} | {LABEL_NAMES[1]}: {sum(y)} | {LABEL_NAMES[0]}: {len(y)-sum(y)}")

    # Can bang 1:1 giong logic balanced_split() de so sanh cong bang
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
            print("Feature importance:")
            for fname, imp in sorted(zip(SIMPLE_FEATURE_NAMES, model.feature_importances_), key=lambda x: -x[1]):
                print(f"  {fname}: {imp:.4f}")


if __name__ == '__main__':
    main()
