"""
import_manual_samples.py
========================
Duong nap mau THU CONG, song song voi duong API (fetch_malware_samples.py):
nhan mot thu muc file PE da tai tay tu bat ky nguon nao (vd VX-Underground),
luu vao data/raw/malicious/<sha256> theo DUNG quy uoc cua duong API, roi goi
lai scripts/build_graphs.py tren cac mau do.

  - Mau CHI duoc doc/ghi duoi dang bytes, KHONG BAO GIO execute; file dich
    o che do chi-doc 0o444 (dung chung save_sample() voi duong API).
  - Chi nhan file PE (2 byte dau "MZ"). File khac (vd .7z/.zip chua giai
    nen, file text) bi BO QUA kem ly do, khong am tham.
  - Khong theo symlink. File goc trong --input-dir giu nguyen (chi copy).
  - Nguon tung mau ghi them vao data/raw/fetch_manifest.jsonl
    (source = --source, kem ten file goc).
  - Neu --input-dir nam TRONG repo ma khong bi .gitignore chan -> dung lai
    (tranh de mau that thanh untracked co the bi add nham).

Chay:  python scripts/import_manual_samples.py <thu_muc_mau> [--source vx-underground]
                                                [--label 1] [--workers 2] [--no-build]
"""

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys

from fetch_malware_samples import save_sample   # cung kiem tra sha256 + MZ + ghi 0o444 nhu duong API
from src.utils.path_resolver import REPO_ROOT, load_config, resolve


def iter_files(root):
    """Moi file trong root, de quy, theo thu tu on dinh. Symlink van duoc
    tra ve (de bao la bo qua), khong bao gio bi doc."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            yield os.path.join(dirpath, name)


def check_input_not_trackable(input_dir):
    """Dung lai neu input_dir nam trong repo ma git khong ignore."""
    abs_dir = os.path.abspath(input_dir)
    if os.path.commonpath([abs_dir, REPO_ROOT]) != REPO_ROOT:
        return
    probe = os.path.join(os.path.relpath(abs_dir, REPO_ROOT), '__probe__')
    ignored = subprocess.run(['git', '-C', REPO_ROOT, 'check-ignore', '-q', probe]).returncode == 0
    if not ignored:
        sys.exit(f"[DUNG] {abs_dir} nam trong repo nhung KHONG bi .gitignore chan - mau that se thanh untracked "
                 f"co the bi add nham. Dat thu muc mau ngoai repo hoac duoi data/.")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('input_dir', help="Thu muc chua file PE da tai thu cong (doc de quy)")
    parser.add_argument('--source', default='manual', help="Ten nguon ghi vao manifest, vd vx-underground")
    parser.add_argument('--dest-dir', default=None, help="Mac dinh: sources.malicious_dirs[0] trong configs/dataset.yaml")
    parser.add_argument('--no-build', action='store_true', help="Chi import, khong chay build_graphs.py")
    # Chuyen thang cho build_graphs.py
    parser.add_argument('--label', type=int, choices=[0, 1], default=1)
    parser.add_argument('--workers', type=int, default=1)
    parser.add_argument('--timeout', type=int, default=600)
    parser.add_argument('--out-dir', default=None)
    parser.add_argument('--vex-vocab', default=None)
    parser.add_argument('--failures', default=None)
    args = parser.parse_args()

    if not os.path.isdir(args.input_dir):
        sys.exit(f"Khong phai thu muc: {args.input_dir}")
    check_input_not_trackable(args.input_dir)

    dest_dir = resolve(args.dest_dir or load_config('dataset')['sources']['malicious_dirs'][0])
    os.makedirs(dest_dir, exist_ok=True)
    manifest_path = os.path.join(os.path.dirname(dest_dir), 'fetch_manifest.jsonl')

    imported, already, skipped = [], [], []
    for path in iter_files(args.input_dir):
        if os.path.islink(path) or not os.path.isfile(path):
            skipped.append((path, "symlink/khong phai file thuong - khong theo link"))
            continue
        with open(path, 'rb') as f:
            data = f.read()
        if data[:2] != b'MZ':
            skipped.append((path, f"khong phai PE (2 byte dau = {data[:2]!r})"))
            continue
        sha256 = hashlib.sha256(data).hexdigest()
        target = os.path.join(dest_dir, sha256)
        if os.path.exists(target):
            already.append(target)
            continue
        save_sample(data, sha256, dest_dir)
        imported.append(target)
        with open(manifest_path, 'a') as mf:
            mf.write(json.dumps({
                'sha256': sha256, 'source': args.source, 'original_name': os.path.basename(path),
                'imported_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }) + '\n')

    print(f"Import tu {os.path.abspath(args.input_dir)} -> {dest_dir}")
    print(f"  moi: {len(imported)} | da co san (cung sha256): {len(already)} | bo qua: {len(skipped)}")
    for path, reason in skipped:
        print(f"    bo qua {path}: {reason}")

    targets = sorted(set(imported) | set(already))
    if args.no_build or not targets:
        if not targets:
            print("Khong co mau PE nao - khong chay build_graphs.py.")
        return

    cmd = [sys.executable, os.path.join(REPO_ROOT, 'scripts', 'build_graphs.py'), *targets,
           '--label', str(args.label), '--workers', str(args.workers), '--timeout', str(args.timeout)]
    for opt in ('out_dir', 'vex_vocab', 'failures'):
        if getattr(args, opt):
            cmd += [f"--{opt.replace('_', '-')}", getattr(args, opt)]
    print(f"\nChay build_graphs.py tren {len(targets)} mau...\n", flush=True)
    sys.exit(subprocess.run(cmd).returncode)


if __name__ == '__main__':
    main()
