"""
build_graphs.py
===============
Chay src/bfbg/bfbg_builder.py tren nhieu mau PE, KHONG de 1 mau loi lam dung
ca lo va KHONG am tham bo qua mau loi.

Moi mau chay trong 1 TIEN TRINH CON rieng, co timeout:
  - exception Python   -> ghi lai type, message, traceback
  - qua --timeout giay -> tien trinh bi kill, ghi exception_type "Timeout"
                          (CFGFast co the treo tren mau pack/obfuscate)
  - tien trinh chet    -> exception_type "ProcessCrash" (vd segfault trong
                          thu vien C cua angr), kem exit code

Moi mau loi = 1 dong JSON trong --failures (mac dinh
experiments/qa/lift_failures.jsonl), gom:
  sha256, path, exception_type, exception_message,
  traceback_last_line       frame CUOI CUNG - noi loi thuc su phat sinh
                            (thuong nam trong angr/cle/pyvex)
  traceback_last_repo_line  frame cuoi cung nam trong code cua repo (src/...)
                            - de tach "bug trong code minh" voi loi cua angr
  traceback                 traceback day du - phan tich sau khong can chay lai
File --failures bi GHI DE moi lan chay (khong tron ket qua cu), tru khi --append.

Chay:  python scripts/build_graphs.py [--input-dir data/raw/malicious] [--label 1]
                                       [--workers 2] [--timeout 600]
"""

import argparse
import datetime
import hashlib
import json
import logging
import multiprocessing as mp
import os
import queue
import sys
import time
import traceback

from src.bfbg.bfbg_builder import build_bfbg, write_bfbg
from src.utils.path_resolver import REPO_ROOT, get_path, load_config, resolve

DEFAULT_FAILURES = os.path.join(REPO_ROOT, 'experiments', 'qa', 'lift_failures.jsonl')


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def _frame_str(frame):
    return f"{frame.filename}:{frame.lineno} in {frame.name}: {frame.line or ''}".rstrip()


def describe_exception(exc):
    frames = traceback.extract_tb(exc.__traceback__)
    repo_src = os.path.join(REPO_ROOT, 'src') + os.sep
    repo_frames = [f for f in frames if os.path.abspath(f.filename).startswith(repo_src)]
    return {
        'exception_type': f"{type(exc).__module__}.{type(exc).__qualname__}".removeprefix('builtins.'),
        'exception_message': str(exc),
        'traceback_last_line': _frame_str(frames[-1]) if frames else None,
        'traceback_last_repo_line': _frame_str(repo_frames[-1]) if repo_frames else None,
        'traceback': ''.join(traceback.format_exception(exc)),
    }


def _worker(path, label, out_dir, vocab_path, result_q):
    for name in ('angr', 'cle', 'pyvex'):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    try:
        bfbg = build_bfbg(path, vocab_path, label=label)
        out_path = write_bfbg(bfbg, out_dir)
        result_q.put(('ok', {'out_path': out_path, 'num_functions': bfbg['num_functions'],
                             'num_api_calls': bfbg['num_api_calls']}))
    except BaseException as exc:   # noqa: BLE001 - ghi lai MOI loi, ke ca KeyboardInterrupt/SystemExit trong angr
        result_q.put(('error', describe_exception(exc)))


def run_one(path, args, ctx):
    """Chay builder cho 1 mau trong tien trinh con; tra ve (status, info)."""
    result_q = ctx.Queue()
    proc = ctx.Process(target=_worker, args=(path, args.label, args.out_dir, args.vex_vocab, result_q))
    start = time.monotonic()
    proc.start()
    status, info = None, None
    deadline = start + args.timeout
    while status is None:
        try:
            status, info = result_q.get(timeout=1.0)
        except queue.Empty:
            if not proc.is_alive():
                break
            if time.monotonic() > deadline:
                proc.kill()
                proc.join()
                return 'error', {'exception_type': 'Timeout',
                                 'exception_message': f"vuot {args.timeout}s (tien trinh bi kill)",
                                 'traceback_last_line': None, 'traceback_last_repo_line': None, 'traceback': None}
    proc.join()
    if status is None:
        return 'error', {'exception_type': 'ProcessCrash',
                         'exception_message': f"tien trinh con thoat voi exit code {proc.exitcode} khong tra ket qua",
                         'traceback_last_line': None, 'traceback_last_repo_line': None, 'traceback': None}
    info['seconds'] = round(time.monotonic() - start, 1)
    return status, info


def collect_inputs(args):
    if args.paths:
        return sorted(args.paths)
    input_dir = resolve(args.input_dir or load_config('dataset')['sources']['malicious_dirs'][0])
    return sorted(os.path.join(input_dir, n) for n in os.listdir(input_dir)
                  if os.path.isfile(os.path.join(input_dir, n)) and not n.startswith('.'))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('paths', nargs='*', help="File PE cu the (mac dinh: moi file trong --input-dir)")
    parser.add_argument('--input-dir', default=None, help="Mac dinh: sources.malicious_dirs[0] trong configs/dataset.yaml")
    parser.add_argument('--label', type=int, choices=[0, 1], default=None)
    parser.add_argument('--out-dir', default=None, help="Mac dinh: paths.features_dir")
    parser.add_argument('--vex-vocab', default=None, help="Mac dinh: paths.vex_vocab")
    parser.add_argument('--failures', default=DEFAULT_FAILURES, help="File JSONL ghi mau loi")
    parser.add_argument('--append', action='store_true', help="Ghi tiep vao --failures thay vi ghi de")
    parser.add_argument('--workers', type=int, default=1, help="So mau xu ly song song (vocab VEX co khoa file)")
    parser.add_argument('--timeout', type=int, default=600, help="Giay toi da cho moi mau")
    args = parser.parse_args()
    args.out_dir = args.out_dir or get_path('features_dir')
    args.vex_vocab = args.vex_vocab or get_path('vex_vocab')

    inputs = collect_inputs(args)
    if not inputs:
        sys.exit("Khong co mau nao de xu ly.")
    print(f"{len(inputs)} mau, workers={args.workers}, timeout={args.timeout}s -> {args.out_dir}")

    os.makedirs(os.path.dirname(os.path.abspath(args.failures)), exist_ok=True)
    failures_f = open(args.failures, 'a' if args.append else 'w')
    ctx = mp.get_context('fork')
    ok, failed = [], []

    def handle(path, status, info):
        sha = sha256_of(path)
        if status == 'ok':
            ok.append(path)
            print(f"  OK   {sha[:16]}...  ham={info['num_functions']:5d}  API-call={info['num_api_calls']:5d}  "
                  f"{info['seconds']}s")
        else:
            row = {'sha256': sha, 'path': os.path.abspath(path), **info,
                   'run_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
            failures_f.write(json.dumps(row) + '\n')
            failures_f.flush()
            failed.append(row)
            print(f"  FAIL {sha[:16]}...  {info['exception_type']}: {info['exception_message'][:120]}")

    if args.workers <= 1:
        for path in inputs:
            handle(path, *run_one(path, args, ctx))
    else:
        from concurrent.futures import ThreadPoolExecutor   # moi thread chi dieu phoi 1 tien trinh con
        with ThreadPoolExecutor(args.workers) as pool:
            for path, result in zip(inputs, pool.map(lambda p: run_one(p, args, ctx), inputs)):
                handle(path, *result)
    failures_f.close()

    n = len(inputs)
    print(f"\nLift thanh cong: {len(ok)}/{n} ({len(ok)/n*100:.1f}%) | that bai: {len(failed)}/{n} "
          f"({len(failed)/n*100:.1f}%)")
    if failed:
        print(f"Chi tiet mau loi ({args.failures}):")
        for row in failed:
            print(f"  {row['sha256']}\n    {row['exception_type']}: {row['exception_message']}\n"
                  f"    tai: {row['traceback_last_line']}\n    trong repo: {row['traceback_last_repo_line']}")


if __name__ == '__main__':
    main()
