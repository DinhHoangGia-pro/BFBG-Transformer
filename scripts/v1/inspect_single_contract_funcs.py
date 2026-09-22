"""
inspect_single_contract_funcs.py
Xem chi tiet 1 hop dong co dung 100 ham - kiem tra xem co phai heuristic
tach JUMPDEST dang qua nhay (over-segmenting) khong.
"""
import json
import glob
import os

DATA_ROOT = os.environ.get('HIN_DIR_DEFI', '.') + '/data/features_graph'

# Tim 1 file co dung 100 ham
for fp in glob.glob(os.path.join(DATA_ROOT, '*.json')):
    with open(fp) as f:
        data = json.load(f)
    intra = data.get('intra_procedural_graphs', {})
    if len(intra) == 100:
        print(f"File mau: {fp}")
        print(f"contract_id: {data.get('contract_id')}")
        print(f"bytecode_length: {data.get('bytecode_length')}")
        print(f"num_functions_detected: {data.get('num_functions_detected')}")

        # Xem 15 "ham" dau tien - kich thuoc (so node) cua tung ham
        func_sizes = [(k, len(v.get('nodes', []))) for k, v in intra.items()]
        func_sizes_sorted = sorted(func_sizes, key=lambda x: int(x[0].split('_')[1]))
        print(f"\n15 'ham' dau tien (ten, so node ben trong):")
        for name, size in func_sizes_sorted[:15]:
            print(f"  {name}: {size} node")

        sizes_only = [s for _, s in func_sizes]
        print(f"\nThong ke kich thuoc: min={min(sizes_only)}, max={max(sizes_only)}, "
              f"trung binh={sum(sizes_only)/len(sizes_only):.1f}")
        print(f"So 'ham' co <=3 node (rat nghi ngo la JUMPDEST gia, khong phai ham that): "
              f"{sum(1 for s in sizes_only if s <= 3)}/{len(sizes_only)}")
        break
