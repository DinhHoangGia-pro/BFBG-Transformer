"""
check_sample_similarity.py
Do muc TRUNG LAP gan dung giua cac mau trong mot thu muc: nhom cac mau "rat
giong nhau" va bao so cum + kich thuoc tung cum. CHI la cong cu DO - chay
SAU khi import mot lo lon de biet lo do thuc su da dang hay nhieu bien the
gan trung; KHONG chan import, KHONG sua import_manual_samples.py.

Dung ppdeep (fuzzy hash thuan Python, cung thuat toan spamsum/ssdeep) tren
BYTES THO cua file mau. Hai mau duoc coi la giong nhau neu
ppdeep.compare(h1, h2) >= --threshold (0..100). Cum = thanh phan lien thong
cua quan he "giong nhau" (union-find); mau khong giong ai = cum 1 phan tu
(singleton).

Chay:  python experiments/qa/check_sample_similarity.py [--input-dir DIR]
                 [--threshold 90] [--show-singletons]
"""
import argparse
import hashlib
import os
import sys
from collections import defaultdict

import ppdeep

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from src.utils.path_resolver import load_config, resolve  # noqa: E402


class UnionFind:
    def __init__(self, items):
        self.parent = {x: x for x in items}

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb

    def clusters(self):
        groups = defaultdict(list)
        for x in self.parent:
            groups[self.find(x)].append(x)
        return list(groups.values())


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def list_raw_samples(input_dir):
    return sorted(os.path.join(input_dir, n) for n in os.listdir(input_dir)
                  if os.path.isfile(os.path.join(input_dir, n)) and not n.startswith('.'))


def cluster(samples, threshold):
    uf = UnionFind([s['id'] for s in samples])
    for i in range(len(samples)):
        for j in range(i + 1, len(samples)):
            if ppdeep.compare(samples[i]['fuzzy'], samples[j]['fuzzy']) >= threshold:
                uf.union(samples[i]['id'], samples[j]['id'])
    return uf.clusters()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--input-dir', default=None, help="Thu muc mau PE tho (mac dinh: sources.malicious_dirs[0])")
    parser.add_argument('--threshold', type=int, default=90, help="Nguong ppdeep.compare (0..100) de coi la giong")
    parser.add_argument('--show-singletons', action='store_true', help="In ca cac cum 1 phan tu")
    args = parser.parse_args()

    input_dir = resolve(args.input_dir or load_config('dataset')['sources']['malicious_dirs'][0])
    if not os.path.isdir(input_dir):
        sys.exit(f"Khong phai thu muc: {input_dir}")

    paths = list_raw_samples(input_dir)
    print(f"Thu muc mau: {input_dir}")
    print(f"So file mau: {len(paths)} | nguong ppdeep.compare >= {args.threshold}")
    if not paths:
        return

    samples = []
    for p in paths:
        with open(p, 'rb') as f:
            data = f.read()
        samples.append({'id': sha256_file(p), 'fuzzy': ppdeep.hash(data)})

    clusters = cluster(samples, args.threshold)
    clusters.sort(key=len, reverse=True)
    sizes = [len(c) for c in clusters]
    singletons = sum(1 for n in sizes if n == 1)
    dup = len(samples) - len(clusters)   # so mau "du thua" neu moi cum chi giu 1 dai dien

    print(f"\nTong mau do duoc: {len(samples)}")
    print(f"So cum: {len(clusters)} | cum >1 phan tu: {len(clusters) - singletons} | singleton: {singletons}")
    print(f"Cum lon nhat: {sizes[0] if sizes else 0} phan tu | mau trung lap uoc tinh (neu giu 1/cum): {dup}")
    print(f"\nKich thuoc tung cum (giam dan): {sizes}")

    print("\nCac cum nhieu hon 1 phan tu:")
    any_multi = False
    for c in clusters:
        if len(c) > 1:
            any_multi = True
            print(f"  [{len(c)}] " + ", ".join(sha[:16] for sha in sorted(c)))
    if not any_multi:
        print("  (khong co - moi mau khac nhau theo nguong hien tai)")

    if args.show_singletons:
        print("\nSingleton:")
        for c in clusters:
            if len(c) == 1:
                print(f"  {c[0][:16]}")


if __name__ == '__main__':
    main()
