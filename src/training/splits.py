"""Split group-aware theo manifest v1 da dong bang (docs/dataset_v1_manifest.jsonl).
Cum near-dup = group; khong bao gio tach mot cum qua train/val."""
import json, os, random
from collections import defaultdict
from src.utils.path_resolver import REPO_ROOT

MANIFEST = os.path.join(REPO_ROOT, 'docs', 'dataset_v1_manifest.jsonl')

def load_manifest(path=MANIFEST):
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]

def by_split(records):
    d = defaultdict(list)
    for r in records:
        d[r['split']].append(r)
    return d

def group_key(r):
    """Cum near-dup lam group; mau khong thuoc cum -> rieng theo sha."""
    return r.get('cluster') or r['sha256']

def group_kfold(records, k=5, seed=42):
    """Chia records thanh k fold theo GROUP (cum), can bang so mau moi fold.
    Tra ve list[k] cac tap sha256 (val fold)."""
    groups = defaultdict(list)
    for r in records:
        groups[group_key(r)].append(r['sha256'])
    gs = list(groups.items())
    rnd = random.Random(seed)
    rnd.shuffle(gs)
    folds = [[] for _ in range(k)]
    sizes = [0]*k
    for _, shas in sorted(gs, key=lambda x: -len(x[1])):  # greedy: group lon vao fold nho nhat
        i = sizes.index(min(sizes))
        folds[i].extend(shas); sizes[i] += len(shas)
    return [set(f) for f in folds]
