"""
check_split_balance.py
Port tu scripts/v1/check_split_balance.py.

Kiem tra tap train/test hien tai co that su lech khong (dem nhan theo tung
tap), truoc khi ket luan day la nguyen nhan gay plateau accuracy.

--group-key (tuy chon): khoa JSON dung de nhom mau (vd campaign,
compile_timestamp). Khi co, in them phan bo nhom trong tung tap va so nhom
xuat hien o CA train lan test (ro ri giua 2 tap).
"""
import argparse
import json
from collections import Counter

from _common import DATASET_CFG, LABEL_NAMES, add_data_root_arg, balanced_split, read_label_fast


def count_labels(file_list, name):
    n0, n1 = 0, 0
    for fp in file_list:
        label = read_label_fast(fp)
        if label == 0:
            n0 += 1
        elif label is not None:
            n1 += 1
    total = n0 + n1
    print(f"{name}: {LABEL_NAMES[0]}={n0} ({n0/total*100:.1f}%) | {LABEL_NAMES[1]}={n1} ({n1/total*100:.1f}%)")


def count_groups(file_list, group_key):
    groups = Counter()
    for fp in file_list:
        try:
            with open(fp) as f:
                groups[json.load(f).get(group_key)] += 1
        except Exception:
            continue
    return groups


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_data_root_arg(parser)
    parser.add_argument('--split-ratio', type=float, default=DATASET_CFG['split']['train_ratio'])
    parser.add_argument('--group-key', default=DATASET_CFG['split']['group_key'], help="Khoa JSON de nhom mau (campaign, compile_timestamp...)")
    parser.add_argument('--top', type=int, default=10, help="So nhom pho bien nhat in ra moi tap")
    args = parser.parse_args()

    train_files, test_files = balanced_split(args.data_root, split_ratio=args.split_ratio)
    print(f"Train = {len(train_files)} | Test = {len(test_files)}")

    count_labels(train_files, "Train")
    count_labels(test_files, "Test")

    if args.group_key:
        train_groups = count_groups(train_files, args.group_key)
        test_groups = count_groups(test_files, args.group_key)
        for name, groups in (("Train", train_groups), ("Test", test_groups)):
            print(f"\n{name}: {len(groups)} nhom '{args.group_key}' (thieu khoa: {groups.get(None, 0)} mau)")
            for g, c in groups.most_common(args.top):
                print(f"  {g}: {c}")
        shared = (set(train_groups) & set(test_groups)) - {None}
        n_test_shared = sum(test_groups[g] for g in shared)
        print(f"\nNhom xuat hien o CA train lan test: {len(shared)} "
              f"(chiem {n_test_shared}/{len(test_files)} mau test)")


if __name__ == '__main__':
    main()
