"""
_common.py
Phan dung chung cho cac script QA trong experiments/qa/: duong dan du lieu,
ten khoa trong JSON dac trung, doc mau, chia train/test can bang.

Ten khoa mac dinh GIU NGUYEN schema JSON hien tai (output cua extractor cu)
de ket qua chay lai so sanh duoc voi scripts/v1/. Khi pipeline PE co schema
moi, chi can sua cac hang so KEY_* va SIMPLE_FEATURES o day.

Duong dan, seed va nguong mac dinh doc tu configs/*.yaml (qua
src/utils/path_resolver.py); tham so dong lenh ghi de khi can.
"""
import glob
import json
import os
import re
import sys

import numpy as np
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from src.utils.path_resolver import get_path, get_seed, load_config  # noqa: E402

DEFAULT_DATA_ROOT = get_path('features_dir')
SAMPLE_SUFFIX = '_static.json'
RANDOM_STATE = get_seed()

DATASET_CFG = load_config('dataset')
MAX_UNITS = load_config('model')['training']['max_functions_per_sample']

# === Schema JSON dac trung ===
KEY_LABEL = 'label'
KEY_UNITS = 'intra_procedural_graphs'          # {unit_key: do thi noi ham/block}
KEY_NODES = 'nodes'
KEY_EDGES_SEQ = 'edges_seq'
KEY_SEED_EDGES = 'seed_sem_edges'              # [src, dst, rule_name] tu bo luat seed
KEY_CALL_GRAPH = 'inter_procedural_call_graph'

LABEL_NAMES = {0: 'benign', 1: 'malicious'}

# === Feature thong ke don gian (PLACEHOLDER cho pipeline PE) ===
# Khoa nao chua co trong JSON se nhan gia tri 0. TODO: dien lai ten khoa
# that sau khi co pipeline PE (entropy theo section, kich thuoc file, so
# API-call import/goi...).
SIMPLE_FEATURES = [
    ("mean_entropy",   lambda d: d.get('mean_entropy', 0.0)),
    ("max_entropy",    lambda d: d.get('max_entropy', 0.0)),
    ("min_entropy",    lambda d: d.get('min_entropy', 0.0)),
    ("file_size",      lambda d: d.get('file_size', 0)),
    ("num_api_calls",  lambda d: d.get('num_api_calls', 0)),
    ("num_units",      lambda d: len(units(d))),
    ("total_nodes",    lambda d: sum(len(u.get(KEY_NODES, [])) for u in units(d).values())),
    ("total_edges_seq", lambda d: sum(len(u.get(KEY_EDGES_SEQ, []) or []) for u in units(d).values())),
    ("total_seed_edges", lambda d: total_seed_edges(d)),
    ("inter_edges",    lambda d: (d.get(KEY_CALL_GRAPH, {}) or {}).get('num_edges', 0)),
]
SIMPLE_FEATURE_NAMES = [name for name, _ in SIMPLE_FEATURES]


def add_data_root_arg(parser):
    parser.add_argument('--data-root', default=DEFAULT_DATA_ROOT,
                        help="Thu muc chua *.json dac trung (mac dinh: paths.features_dir "
                             "trong configs/config.yaml)")


def list_sample_files(data_root):
    return glob.glob(os.path.join(data_root, '*.json'))


def iter_samples(files):
    """Yield (file_path, data), bo qua file JSON hong."""
    for fp in files:
        try:
            with open(fp) as f:
                yield fp, json.load(f)
        except Exception:
            continue


def sample_id(fp):
    return os.path.basename(fp).replace(SAMPLE_SUFFIX, '').replace('.json', '')


_LABEL_RE = re.compile(rf'"{KEY_LABEL}"\s*:\s*(\d+)')


def read_label_fast(fp):
    """Doc nhan bang cach quet dong, khong parse toan bo JSON (ca file JSON
    1 dong lan file indent)."""
    with open(fp) as f:
        for line in f:
            m = _LABEL_RE.search(line)
            if m:
                return int(m.group(1))
    return None


def units(data):
    return data.get(KEY_UNITS, {}) or {}


def unit_position(unit_key):
    """Vi tri cua unit (ham/block) trong binary, trich tu phan so cuoi key,
    vd 'func_1234' -> 1234, 'func_0x401000' -> 0x401000. Sort THEO SO, khong
    sort chuoi."""
    raw = unit_key.split('_')[-1]
    for base in (10, 16):
        try:
            return int(raw, base)
        except ValueError:
            continue
    return 0


def seed_edges(unit):
    return unit.get(KEY_SEED_EDGES, []) or []


def total_seed_edges(data):
    return sum(len(seed_edges(u)) for u in units(data).values())


def seed_rules(data):
    """Tap ten luat seed (phan tu thu 3 cua moi seed edge) xuat hien trong mau."""
    return {e[2] for u in units(data).values() for e in seed_edges(u) if len(e) >= 3}


def simple_features(data):
    return [float(fn(data)) for _, fn in SIMPLE_FEATURES]


def balanced_split(data_root, split_ratio=DATASET_CFG['split']['train_ratio'], random_state=RANDOM_STATE):
    """Can bang 1:1 benign/malicious roi chia train/test - cung logic voi
    get_balanced_file_paths() trong scripts/train_tcfbg_defi.py."""
    raw_files = list_sample_files(data_root)
    if not raw_files:
        raise RuntimeError(f"Khong tim thay file .json nao trong {data_root}")

    benign_files, mal_files = [], []
    for fp in raw_files:
        try:
            label = read_label_fast(fp)
        except Exception:
            continue
        if label is None:
            continue
        (benign_files if label == 0 else mal_files).append(fp)

    max_balanced = min(len(benign_files), len(mal_files))
    if max_balanced == 0:
        raise RuntimeError("Khong du du lieu cho ca 2 lop.")

    np.random.seed(random_state)
    chosen_benign = np.random.choice(benign_files, size=max_balanced, replace=False).tolist()
    chosen_mal = np.random.choice(mal_files, size=max_balanced, replace=False).tolist()
    final_files = chosen_benign + chosen_mal
    np.random.shuffle(final_files)

    return train_test_split(final_files, test_size=(1 - split_ratio), random_state=random_state)
