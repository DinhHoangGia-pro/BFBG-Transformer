"""
check_split_balance.py
Kiem tra that tap train/test hien tai co that su lech khong, truoc khi
ket luan day la nguyen nhan gay plateau accuracy.
"""
import sys
sys.path.insert(0, '.')
from train_tcfbg_defi import get_balanced_file_paths, DATA_ROOT
import json

train_files, test_files = get_balanced_file_paths(DATA_ROOT, split_ratio=0.8)

def count_labels(file_list, name):
    n0, n1 = 0, 0
    for fp in file_list:
        with open(fp) as f:
            for line in f:
                if '"label"' in line:
                    label = int(''.join(c for c in line if c.isdigit()))
                    if label == 0: n0 += 1
                    else: n1 += 1
                    break
    print(f"{name}: benign={n0} ({n0/(n0+n1)*100:.1f}%) | vulnerable={n1} ({n1/(n0+n1)*100:.1f}%)")

count_labels(train_files, "Train")
count_labels(test_files, "Test")
