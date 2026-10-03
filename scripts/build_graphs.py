"""
build_graphs.py
===============
Chay src/bfbg/bfbg_builder.py tren nhieu mau PE, KHONG de 1 mau loi lam dung
ca lo va KHONG am tham bo qua mau loi.

Moi mau chay trong 1 TIEN TRINH CON rieng, co timeout:
  - exception Python   -> ghi lai type, message, traceback
  - qua --timeout giay -> tien trinh bi kill, ghi exception_type "Timeout"
                          (CFGFast co the treo tren mau pack/obfuscate).
                          NGOAI LE: neu worker da ghi xong JSON hop le ngay
                          truoc khi bi kill (race o bien timeout) thi van tinh
                          OK, khong phai Timeout - xem _salvage_output().
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
import pickle
import sys
import tempfile
import time
import traceback

from src.bfbg.bfbg_builder import build_bfbg, write_bfbg
from src.disassembly.pe_lifter import is_dotnet_assembly
from src.utils.path_resolver import REPO_ROOT, get_path, load_config, resolve

DEFAULT_FAILURES = os.path.join(REPO_ROOT, 'experiments', 'qa', 'lift_failures.jsonl')
DEFAULT_OUT_OF_SCOPE = os.path.join(REPO_ROOT, 'experiments', 'qa', 'out_of_scope_samples.jsonl')


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


def _worker(path, label, out_dir, vocab_path, result_path):
    # Tra ket qua qua FILE TAM (pickle), KHONG qua multiprocessing.Queue:
    # Queue + feeder-thread/pipe giua ThreadPool va tien trinh con tung gay
    # deadlock lam treo khi "het viec" (timeout 900s khong ban). File tam
    # + join(timeout) o parent loai han lop deadlock do.
    for name in ('angr', 'cle', 'pyvex'):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    try:
        bfbg = build_bfbg(path, vocab_path, label=label)
        out_path = write_bfbg(bfbg, out_dir)
        res = ('ok', {'out_path': out_path, 'num_functions': bfbg['num_functions'],
                      'num_api_calls': bfbg['num_api_calls']})
    except BaseException as exc:   # noqa: BLE001 - ghi lai MOI loi, ke ca KeyboardInterrupt/SystemExit trong angr
        res = ('error', describe_exception(exc))
    with open(result_path, 'wb') as f:
        pickle.dump(res, f)


def _salvage_output(path, args):
    """Vot lai ket qua khi worker bi kill vi timeout: co race o bien timeout
    - worker co the ghi xong JSON day du NGAY TRUOC khi proc.kill() ban (xem
    docs/LESSONS_LEARNED.md). Neu JSON dau ra ton tai va doc duoc (json.load
    khong loi, co field bat buoc) thi day la 'ok' that su, khong phai Timeout.
    Kill giua chung co the de file cut -> json.load bao loi -> tra None."""
    out_path = os.path.join(args.out_dir, f"{sha256_of(path)}_static.json")
    if not os.path.exists(out_path):
        return None
    try:
        with open(out_path) as f:
            d = json.load(f)
    except (ValueError, OSError):
        return None
    if d.get('num_functions') is None or 'intra_procedural_graphs' not in d:
        return None
    return {'out_path': out_path, 'num_functions': d['num_functions'],
            'num_api_calls': d.get('num_api_calls', 0)}


def run_one(path, args, ctx):
    """Chay builder cho 1 mau trong tien trinh con; tra ve (status, info).
    Timeout cung moi mau bang proc.join(timeout) + proc.kill() - khong
    phu thuoc vao viec doc Queue."""
    fd, result_path = tempfile.mkstemp(prefix='bfbg_build_', suffix='.pkl')
    os.close(fd)
    proc = ctx.Process(target=_worker, args=(path, args.label, args.out_dir, args.vex_vocab, result_path))
    start = time.monotonic()
    proc.start()
    proc.join(args.timeout)
    try:
        if proc.is_alive():
            proc.kill()
            proc.join()
            salvaged = _salvage_output(path, args)   # race o bien timeout: JSON co the da ghi xong
            if salvaged is not None:
                salvaged['seconds'] = round(time.monotonic() - start, 1)
                return 'ok', salvaged
            return 'error', {'exception_type': 'Timeout',
                             'exception_message': f"vuot {args.timeout}s (tien trinh bi kill)",
                             'traceback_last_line': None, 'traceback_last_repo_line': None, 'traceback': None}
        try:
            with open(result_path, 'rb') as f:
                status, info = pickle.load(f)
        except (EOFError, FileNotFoundError, pickle.UnpicklingError):
            return 'error', {'exception_type': 'ProcessCrash',
                             'exception_message': f"tien trinh con thoat (exit code {proc.exitcode}) khong ghi ket qua",
                             'traceback_last_line': None, 'traceback_last_repo_line': None, 'traceback': None}
        info['seconds'] = round(time.monotonic() - start, 1)
        return status, info
    finally:
        if os.path.exists(result_path):
            os.unlink(result_path)


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
    parser.add_argument('--out-of-scope', default=DEFAULT_OUT_OF_SCOPE,
                        help="File JSONL ghi mau ngoai pham vi (vd .NET/CLR) - khong lift, khong phai loi")
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
    os.makedirs(os.path.dirname(os.path.abspath(args.out_of_scope)), exist_ok=True)
    failures_f = open(args.failures, 'a' if args.append else 'w')
    oos_f = open(args.out_of_scope, 'a' if args.append else 'w')
    ctx = mp.get_context('fork')
    ok, failed, out_of_scope = [], [], []

    def handle(path, status, info):
        sha = sha256_of(path)
        if status == 'ok':
            ok.append(path)
            print(f"  OK    {sha[:16]}...  ham={info['num_functions']:5d}  API-call={info['num_api_calls']:5d}  "
                  f"{info['seconds']}s")
        elif status == 'out_of_scope':
            row = {'sha256': sha, 'path': os.path.abspath(path), 'reason': info['reason'],
                   'run_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
            oos_f.write(json.dumps(row) + '\n')
            oos_f.flush()
            out_of_scope.append(row)
            print(f"  SKIP  {sha[:16]}...  out-of-scope: {info['reason']}")
        else:
            row = {'sha256': sha, 'path': os.path.abspath(path), **info,
                   'run_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
            failures_f.write(json.dumps(row) + '\n')
            failures_f.flush()
            failed.append(row)
            print(f"  FAIL  {sha[:16]}...  {info['exception_type']}: {info['exception_message'][:120]}")

    def classify_and_run(path):
        # Phan loai TRUOC khi lift: mau .NET/CLR khong phai ma may x86, angr
        # khong lift duoc co y nghia -> out-of-scope, khong goi CFGFast.
        try:
            if is_dotnet_assembly(path):
                return 'out_of_scope', {'reason': 'dotnet_clr'}
        except Exception:
            pass   # khong doc duoc CLR header -> cu de lift binh thuong, loi (neu co) vao lift_failures
        return run_one(path, args, ctx)

    if args.workers <= 1:
        for path in inputs:
            handle(path, *classify_and_run(path))
    else:
        from concurrent.futures import ThreadPoolExecutor   # moi thread chi dieu phoi 1 tien trinh con
        with ThreadPoolExecutor(args.workers) as pool:
            for path, result in zip(inputs, pool.map(classify_and_run, inputs)):
                handle(path, *result)
    failures_f.close()
    oos_f.close()

    n = len(inputs)
    print(f"\nLift thanh cong: {len(ok)}/{n} ({len(ok)/n*100:.1f}%) | "
          f"out-of-scope: {len(out_of_scope)}/{n} ({len(out_of_scope)/n*100:.1f}%) | "
          f"that bai: {len(failed)}/{n} ({len(failed)/n*100:.1f}%)")
    if out_of_scope:
        print(f"Mau out-of-scope ({args.out_of_scope}):")
        for row in out_of_scope:
            print(f"  {row['sha256']}  {row['reason']}")
    if failed:
        print(f"Chi tiet mau loi ({args.failures}):")
        for row in failed:
            print(f"  {row['sha256']}\n    {row['exception_type']}: {row['exception_message']}\n"
                  f"    tai: {row['traceback_last_line']}\n    trong repo: {row['traceback_last_repo_line']}")


if __name__ == '__main__':
    main()
