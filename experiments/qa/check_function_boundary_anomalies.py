"""
check_function_boundary_anomalies.py
Phat hien ham angr GOP NHAM (nhieu doan code o xa nhau bi tinh chung 1 ham,
vd tail-call `jmp` toi code cua ham khac) - chieu nguoc lai cua
scripts/v1/inspect_single_contract_funcs.py ban EVM (tach nham JUMPDEST
thanh qua nhieu "ham" nho). Quan trong vi luat seed ATT&CK chi khop TRONG
1 HAM: ranh gioi ham sai thi pham vi khop sai.

Voi moi ham trong JSON BFBG (can field blocks[].size - src/bfbg/bfbg_builder.py):
  spread    = (dia chi cuoi cua block cuoi) - (dia chi block dau), byte
  coverage  = tong byte cac block / spread (ham lien mach ~ 1.0)
  segment   = day block lien mach (khe <= --gap-tol byte, cho padding can le)
Co bat thuong:
  SPREAD     spread >= --min-spread va coverage < --max-coverage
             (spread qua lon so voi luong code that)
  FAR_UNLINK co segment cach segment khac > --far-gap byte ma KHONG co canh
             CFG (jump/fallthrough) nao tu segment khac di vao no
  OVERLAP    segment chua dia chi bat dau cua MOT HAM KHAC trong cung mau
Cot 'shared' = so block cua ham nay cung nam trong ham khac (chi de tham
khao, khong tinh la co).
"""
import argparse

from _common import add_data_root_arg, iter_samples, list_sample_files, sample_id, units
from src.bfbg.boundary_flags import FLAG_NAMES, analyze_sample, default_params


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_data_root_arg(parser)
    p = default_params()   # configs/dataset.yaml -> boundary_flags (cung nguong builder ghi vao JSON)
    parser.add_argument('--min-spread', type=int, default=p['min_spread'], help="Spread toi thieu (byte) de xet co SPREAD")
    parser.add_argument('--max-coverage', type=float, default=p['max_coverage'], help="Coverage duoi nguong nay -> SPREAD")
    parser.add_argument('--far-gap', type=int, default=p['far_gap'], help="Khe (byte) giua 2 segment coi la 'xa'")
    parser.add_argument('--gap-tol', type=int, default=p['gap_tol'], help="Khe (byte) van coi la lien mach (padding)")
    parser.add_argument('--top', type=int, default=20, help="So ham bat thuong in ra moi mau")
    args = parser.parse_args()

    params = {k: getattr(args, k) for k in ('min_spread', 'max_coverage', 'far_gap', 'gap_tol')}
    for fp, data in iter_samples(list_sample_files(args.data_root)):
        analyzed = analyze_sample(units(data), params)
        results = [r for r in analyzed.values() if r is not None]
        n_skipped = sum(1 for r in analyzed.values() if r is None)
        anomalies = sorted((r for r in results if r['flags']), key=lambda r: -r['spread'])

        counts = {f: sum(f in r['flags'] for r in results) for f in FLAG_NAMES}
        print(f"=== {sample_id(fp)[:16]}... ({data.get('arch', '?')}): {len(results)} ham, "
              f"bat thuong={len(anomalies)} {counts}" + (f", bo qua {n_skipped} (thieu blocks.size)" if n_skipped else ""))
        if not anomalies:
            continue
        print(f"  {'dia chi':>10s} {'ten':28s} {'lenh':>5s} {'spread':>8s} {'cover':>6s} {'seg':>4s} "
              f"{'shared':>6s}  co / chi tiet")
        for r in anomalies[:args.top]:
            detail = []
            if r['far_unlinked']:
                detail.append("seg xa khong canh vao: " + ", ".join(f"{a:#x}" for a in r['far_unlinked']))
            if r['overlapped']:
                detail.append("chua entry ham khac: " + ", ".join(f"{a:#x}" for a in r['overlapped']))
            segs = " ".join(f"[{s:#x}-{e:#x})" for s, e in r['segments'][:4]) + (" ..." if len(r['segments']) > 4 else "")
            print(f"  {r['addr']:#10x} {r['name'][:28]:28s} {r['n_insns']:5d} {r['spread']:8d} {r['coverage']:6.2f} "
                  f"{len(r['segments']):4d} {r['shared']:6d}  {','.join(r['flags'])}")
            print(f"  {'':10s} segment: {segs}" + ("  | " + "; ".join(detail) if detail else ""))
        if len(anomalies) > args.top:
            print(f"  ... va {len(anomalies) - args.top} ham khac")


if __name__ == '__main__':
    main()
