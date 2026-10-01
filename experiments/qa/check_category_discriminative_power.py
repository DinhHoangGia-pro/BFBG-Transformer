"""
check_category_discriminative_power.py
Port tu scripts/v1/audit_category_discriminative_power_v2.py.

Chay Random Forest RIENG cho tung nhom/family (malicious-thuoc-nhom-do vs
benign) de biet CHINH XAC nhom nao dang keo chat luong xuong, thay vi gop
chung tat ca.

Nhan nhom doc tu --groups-file (JSONL), moi dong:
    {"sample_id": "...", "groups": ["family_a", ...], "error": false}
  - "groups" rong  -> mau benign
  - "error" true   -> bo qua
sample_id khop voi ten file JSON dac trung (bo hau to _static.json).
Nhom co the sinh tu VirusTotal + AVClass (family) hoac ATT&CK tactic.

Kem theo: voi moi nhom (va benign), moi technique_id - bang chung nam o ham
co boundary_flags RONG hay KHONG RONG, so voi ty le call site API o ham bi
gan co (lift) - xem fire co tap trung bat thuong o ham angr co the gop nham
(OVERLAP/SPREAD) cua rieng nhom nao khong. JSON thieu boundary_flags -> bo
qua phan nay kem canh bao.
"""
import argparse
import json

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split

from collections import Counter

from _common import RANDOM_STATE, add_data_root_arg, evidence_by_boundary, has_boundary_flags, iter_samples, \
    list_sample_files, load_techniques, merge_boundary_stats, print_boundary_table, sample_id, simple_features


def load_groups(groups_file, target_groups):
    id_to_groups, benign_ids = {}, set()
    with open(groups_file) as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("error"):
                continue
            groups = set(row.get("groups") or [])
            if not groups:
                benign_ids.add(row["sample_id"])
                continue
            real = groups & target_groups if target_groups else groups
            if real:
                id_to_groups[row["sample_id"]] = real
    return id_to_groups, benign_ids


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_data_root_arg(parser)
    parser.add_argument('--groups-file', required=True, help="JSONL anh xa sample_id -> danh sach nhom")
    parser.add_argument('--groups', nargs='*', default=None,
                        help="Chi xet cac nhom nay (mac dinh: moi nhom xuat hien trong groups-file)")
    parser.add_argument('--min-samples', type=int, default=50, help="Bo qua nhom co it hon N mau moi lop")
    args = parser.parse_args()

    target_groups = set(args.groups) if args.groups else None
    id_to_groups, benign_ids = load_groups(args.groups_file, target_groups)
    print(f"Da nap {len(id_to_groups)} mau malicious, {len(benign_ids)} mau benign tu {args.groups_file}")

    features_by_id, boundary_by_id = {}, {}
    n_missing_boundary = 0
    for fp, data in iter_samples(list_sample_files(args.data_root)):
        sid = sample_id(fp)
        features_by_id[sid] = simple_features(data)
        if has_boundary_flags(data):
            boundary_by_id[sid] = evidence_by_boundary(data)
        else:
            n_missing_boundary += 1
    print(f"Da nap feature cho {len(features_by_id)} mau tu {args.data_root}\n")

    all_groups = target_groups or set().union(set(), *id_to_groups.values())
    # sorted(): thu tu duyet set chuoi doi giua cac lan chay (hash randomization) -> lay mau khong tai lap
    benign_avail = sorted(s for s in benign_ids if s in features_by_id)
    print(f"{'Nhom':22s} {'N':>6s} {'Acc':>8s} {'F1':>8s}   Ket luan")
    print("-" * 70)

    for group in sorted(all_groups):
        mal_avail = sorted(s for s, gs in id_to_groups.items() if group in gs and s in features_by_id)
        n = min(len(mal_avail), len(benign_avail))
        if n < args.min_samples:
            print(f"{group:22s} qua it mau ({n}), bo qua")
            continue

        rng = np.random.RandomState(RANDOM_STATE)
        m_sample = rng.choice(mal_avail, n, replace=False)
        b_sample = rng.choice(benign_avail, n, replace=False)

        X = np.array([features_by_id[s] for s in m_sample] + [features_by_id[s] for s in b_sample])
        y = np.array([1] * n + [0] * n)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y)

        model = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE)
        model.fit(X_train, y_train)
        preds = model.predict(X_test)
        acc = accuracy_score(y_test, preds)
        f1 = f1_score(y_test, preds)

        flag = ""
        if acc < 0.65:
            flag = "<-- YEU, nhom nay dang keo chat luong xuong"
        elif acc > 0.85:
            flag = "<-- MANH, tin hieu tot"
        print(f"{group:22s} {n:6d} {acc:8.4f} {f1:8.4f}   {flag}")


    print(f"\n=== Bang chung theo boundary_flags cua ham, tung nhom (clean = khong bi gan co) ===")
    if n_missing_boundary:
        print(f"[CANH BAO] {n_missing_boundary} mau thieu field boundary_flags - BO QUA phan nay (khong in so "
              f"lieu tren du lieu thieu). Dung lai src/bfbg/bfbg_builder.py de sinh lai JSON.")
        return
    names = {t[0]: t[1] for t in load_techniques()}
    members = {g: [s for s, gs in id_to_groups.items() if g in gs] for g in sorted(all_groups)}
    members['(benign)'] = sorted(benign_ids)
    for group, sids in members.items():
        sids = [s for s in sids if s in boundary_by_id]
        if not sids:
            continue
        acc = (Counter(), {})
        for s in sids:
            merge_boundary_stats(acc, boundary_by_id[s])
        print_boundary_table(f"{group} ({len(sids)} mau)", acc[0], acc[1], names)


if __name__ == '__main__':
    main()
