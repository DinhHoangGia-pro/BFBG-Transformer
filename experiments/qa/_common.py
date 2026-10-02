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
from collections import Counter

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
KEY_SEED_EDGES = 'seed_edges'                  # [{src_node_id, dst_node_id, technique_id, ...}] - src/bfbg/bfbg_builder.py
KEY_NODE_INDICATORS = 'node_indicators'        # [{node_id, technique_id, ...}] - bang chung 1 node don le
KEY_BOUNDARY_FLAGS = 'boundary_flags'          # ['SPREAD'|'FAR_UNLINK'|'OVERLAP'] - ham angr co the gop nham
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
    ("total_node_indicators", lambda d: total_node_indicators(d)),
    ("inter_edges",    lambda d: (d.get(KEY_CALL_GRAPH, {}) or {}).get('num_edges', 0)),
]
SIMPLE_FEATURE_NAMES = [name for name, _ in SIMPLE_FEATURES]


def add_data_root_arg(parser):
    parser.add_argument('--data-root', default=DEFAULT_DATA_ROOT,
                        help="Thu muc chua *.json dac trung (mac dinh: paths.features_dir "
                             "trong configs/config.yaml)")


def list_sample_files(data_root):
    """Chi file mau (*_static.json) - bo qua file khac cung thu muc, vd vex_vocab.json."""
    return glob.glob(os.path.join(data_root, '*' + SAMPLE_SUFFIX))


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


def node_indicators(unit):
    return unit.get(KEY_NODE_INDICATORS, []) or []


def total_node_indicators(data):
    return sum(len(node_indicators(u)) for u in units(data).values())


def unit_evidence(unit):
    """(Counter technique_id cua seed edge, Counter technique_id cua node
    indicator) trong 1 ham."""
    return (Counter(e['technique_id'] for e in seed_edges(unit)),
            Counter(i['technique_id'] for i in node_indicators(unit)))


def sample_techniques(data):
    """(tap technique co seed edge, tap technique co node indicator) trong 1 mau."""
    by_edge, by_ind = set(), set()
    for u in units(data).values():
        e, i = unit_evidence(u)
        by_edge.update(e)
        by_ind.update(i)
    return by_edge, by_ind


def load_techniques():
    """[(technique_id, rule_name, co_sinh_node_indicator)] tu bang luat ATT&CK."""
    from src.semantic.seed_rules_attck import ATTACK_SEED_RULES
    return [(r.technique_id, r.name, r.singleton_as_node_indicator) for r in ATTACK_SEED_RULES]


def technique_caveats():
    """{technique_id: training_caveat} chi cho cac luat co han che DA XAC NHAN
    khi dung lam tin hieu huan luyen (src/semantic/seed_rules_attck.py)."""
    from src.semantic.seed_rules_attck import ATTACK_SEED_RULES
    return {r.technique_id: r.training_caveat for r in ATTACK_SEED_RULES if r.training_caveat}


def print_caveat_warnings(technique_ids):
    """In canh bao co dinh cho moi technique (trong technique_ids) co han che
    DA XAC NHAN - dung chung cho moi QA script in so lieu T1055."""
    caveats = technique_caveats()
    for tid in technique_ids:
        if tid in caveats:
            print(f"[CANH BAO] {tid} co FP da xac nhan tren fixture benign tu-tiem - "
                  f"xem docs/LESSONS_LEARNED.md truoc khi dung lam can cu")


def missing_evidence_fields(data):
    """Field bang chung bat buoc (seed_edges, node_indicators) bi thieu o it
    nhat 1 ham cua mau."""
    return {key for u in units(data).values() for key in (KEY_SEED_EDGES, KEY_NODE_INDICATORS) if key not in u}


def require_evidence_fields(samples):
    """Dung script (exit 2) neu co mau thieu seed_edges/node_indicators: dem
    tren JSON thieu field se cho so lieu bang chung thap GIA, khong phai do
    luat yeu. samples: list (file_path, data)."""
    bad = [(fp, m) for fp, m in ((fp, missing_evidence_fields(d)) for fp, d in samples) if m]
    if not bad:
        return
    print(f"[LOI] {len(bad)}/{len(samples)} file JSON thieu field bat buoc o cap ham - KHONG tinh so lieu "
          f"(se thap gia do thieu du lieu, khong phai do luat yeu).", file=sys.stderr)
    for fp, m in bad[:10]:
        print(f"  {fp}: thieu {sorted(m)}", file=sys.stderr)
    if len(bad) > 10:
        print(f"  ... va {len(bad) - 10} file khac", file=sys.stderr)
    print("Dung lai src/bfbg/bfbg_builder.py de sinh lai JSON day du schema.", file=sys.stderr)
    sys.exit(2)


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


# === Bang chung theo co ranh gioi ham (boundary_flags) ===
EVIDENCE_KINDS = ('edge', 'indicator', 'any')


def has_boundary_flags(data):
    return all(KEY_BOUNDARY_FLAGS in u for u in units(data).values())


def evidence_by_boundary(data):
    """Dem bang chung cua 1 mau tach theo ham co boundary_flags rong ('clean')
    hay khong rong ('flagged'):
      base[side]                = so call site API (moc so sanh: luat chi fire tai loi goi API)
      items[tid][kind][side]    = so bang chung (seed edge / node indicator / tong)
    """
    base = Counter()
    items = {}
    for u in units(data).values():
        side = 'flagged' if u.get(KEY_BOUNDARY_FLAGS) else 'clean'
        base[side] += len(u.get('api_calls', []))
        e, i = unit_evidence(u)
        for kind, c in (('edge', e), ('indicator', i), ('any', e + i)):
            for tid, n in c.items():
                items.setdefault(tid, {k: Counter() for k in EVIDENCE_KINDS})[kind][side] += n
    return base, items


def merge_boundary_stats(acc, sample_stats):
    """Cong don ket qua evidence_by_boundary() cua nhieu mau vao acc = (base, items)."""
    base, items = acc
    s_base, s_items = sample_stats
    base.update(s_base)
    for tid, kinds in s_items.items():
        dst = items.setdefault(tid, {k: Counter() for k in EVIDENCE_KINDS})
        for kind, c in kinds.items():
            dst[kind].update(c)
    return acc


def print_boundary_table(title, base, items, names, indent='  '):
    """In bang: moi technique_id x loai bang chung -> so o ham clean/flagged,
    % o ham flagged, lift = (% bang chung o ham flagged) / (% call site API o
    ham flagged). lift ~1: phan bo binh thuong; lift >> 1: tap trung o ham
    bi gan co (nghi do ranh gioi ham sai)."""
    total_sites = base['clean'] + base['flagged']
    site_share = base['flagged'] / total_sites if total_sites else 0.0
    print(f"{indent}{title}: call site API o ham bi gan co = {base['flagged']}/{total_sites} "
          f"({site_share*100:.1f}%)")
    print(f"{indent}{'Ky thuat':28s} {'Loai':10s} {'clean':>7s} {'flagged':>8s} {'% flagged':>10s} {'lift':>7s}")
    for tid in sorted(set(names) | set(items)):
        for kind in EVIDENCE_KINDS:
            c = items.get(tid, {}).get(kind, Counter())
            n = c['clean'] + c['flagged']
            share = c['flagged'] / n if n else 0.0
            lift = f"{share / site_share:7.2f}" if n and site_share else f"{'-':>7s}"
            label = f"{tid} {names.get(tid, '?')}" if kind == 'edge' else ""
            pct = f"{share*100:9.1f}%" if n else f"{'-':>10s}"
            print(f"{indent}{label:28s} {kind:10s} {c['clean']:7d} {c['flagged']:8d} {pct} {lift}")
