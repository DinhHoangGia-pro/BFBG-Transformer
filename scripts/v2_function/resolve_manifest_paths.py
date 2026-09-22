"""
resolve_manifest_paths.py
Doc manifest, tra ve danh sach duong dan TUYET DOI, DUY NHAT cua tung file
.sol can trich xuat - dung cho ca run_extract_function_level.sh.
"""
import json
import os
import sys

MANIFEST_PATHS = sys.argv[1:] if len(sys.argv) > 1 else ["function_labels_final_balanced.jsonl"]
SMARTBUGS_ROOT = "/home/dhgia/Work/Defi/Defi_analysis/download_dataset/function_level_v2/smartbugs_curated/dataset"
DAPPSCAN_ROOT = "/home/dhgia/Work/Defi/Defi_analysis/download_dataset/dappscan_repo/DAppSCAN-source/contracts"

seen_keys = set()
resolved = set()

# Cache danh sach file trong SmartBugs-Curated (basename -> full path) de
# khong phai os.walk lai cho moi dong manifest.
smartbugs_index = {}
for dirpath, _, filenames in os.walk(SMARTBUGS_ROOT):
    for fn in filenames:
        if fn.endswith(".sol"):
            smartbugs_index[fn] = os.path.abspath(os.path.join(dirpath, fn))

for mpath in MANIFEST_PATHS:
    with open(mpath) as f:
        for line in f:
            row = json.loads(line)
            key = (row["source"], row["contract_file"])
            if key in seen_keys:
                continue
            seen_keys.add(key)

            if row["source"] == "dappscan":
                abs_path = os.path.abspath(os.path.join(DAPPSCAN_ROOT, row["contract_file"]))
            else:
                abs_path = smartbugs_index.get(row["contract_file"])

            if abs_path and os.path.exists(abs_path):
                resolved.add(abs_path)

for p in sorted(resolved):
    print(p)
