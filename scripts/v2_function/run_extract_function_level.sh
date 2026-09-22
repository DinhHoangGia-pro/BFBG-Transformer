#!/bin/bash
# =============================================================================
#  run_extract_function_level.sh
#  Pipeline trich xuat dac trung CAP HAM (function-level) - thay the hoan
#  toan pipeline contract-level Slither-labeled cu (da gac vao
#  archive_v1_contract_level/). Nguon nhan: SmartBugs-Curated + DAppSCAN
#  (nguoi audit that, khong phai Slither tu dong).
# =============================================================================

export HIN_DIR_DEFI="/home/dhgia/Work/Defi/Defi_analysis"
export LOG_DIR="$HIN_DIR_DEFI/logs"
export TMP_DIR="$HIN_DIR_DEFI/tmp"
export DATA_DIR="$HIN_DIR_DEFI/data/features_graph_function_level"

VENV_DIR="/home/dhgia/defi_venv"
PYTHON_BIN="$VENV_DIR/bin/python"
CODE_DIR="$HIN_DIR_DEFI/scripts"
DATA_SRC_DIR="$HIN_DIR_DEFI/download_dataset/function_level_v2"
EXTRACT_SCRIPT="$CODE_DIR/extract_evm_features.py"
RESOLVE_SCRIPT="$CODE_DIR/resolve_manifest_paths.py"

# Gop ca 2 manifest (SmartBugs-Curated + DAppSCAN) - dung ban DA CAN BANG
# neu muon train truc tiep, hoac ca 2 ban rieng neu muon giu day du roi
# tu can bang sau. Mac dinh dung ban day du (chua can bang), can bang se
# lam o buoc train (giong logic get_balanced_file_paths cu).
MANIFEST_FILES="$DATA_SRC_DIR/function_labels_manifest.jsonl,$DATA_SRC_DIR/function_labels_manifest_dappscan.jsonl"

PIPELINE_LOG="$LOG_DIR/pipeline_function_level.log"
ERROR_LOG="$LOG_DIR/extract_errors_function_level.log"

mkdir -p "$LOG_DIR" "$TMP_DIR" "$DATA_DIR"
> "$ERROR_LOG"
> "$PIPELINE_LOG"
> "$LOG_DIR/xargs_stdout_fl.log"
> "$LOG_DIR/xargs_stderr_fl.log"

if [ ! -f "$VENV_DIR/bin/activate" ]; then
    echo "CRITICAL: Venv not found at $VENV_DIR"
    exit 1
fi
source "$VENV_DIR/bin/activate"

echo "=== FUNCTION-LEVEL EXTRACTION - STARTED $(date) ===" | tee -a "$PIPELINE_LOG"
echo "MANIFEST: $MANIFEST_FILES" | tee -a "$PIPELINE_LOG"

# 1. Dung script Python rieng de tao danh sach file DUY NHAT, TUYET DOI
#    (tranh trung basename giua cac project DAppSCAN)
cd "$CODE_DIR"
"$PYTHON_BIN" "$RESOLVE_SCRIPT" \
    "$DATA_SRC_DIR/function_labels_manifest.jsonl" \
    "$DATA_SRC_DIR/function_labels_manifest_dappscan.jsonl" \
    > "$TMP_DIR/all_files_fl.txt"

TOTAL_FILES=$(wc -l < "$TMP_DIR/all_files_fl.txt")
echo "Total unique .sol files to process: $TOTAL_FILES" | tee -a "$PIPELINE_LOG"

if [ "$TOTAL_FILES" -eq 0 ]; then
    echo "ERROR: Khong tim thay file nao tu manifest." | tee -a "$PIPELINE_LOG"
    exit 1
fi

rm -f "$DATA_DIR"/*_static.json 2>/dev/null || true

# 2. Background monitor
(
    while kill -0 $$ 2>/dev/null; do
        COUNT=$(find "$DATA_DIR" -name "*_static.json" | wc -l)
        echo -ne "Progress: $COUNT / $TOTAL_FILES files created...\r"
        if [ "$COUNT" -ge "$TOTAL_FILES" ]; then break; fi
        sleep 2
    done
) &
MONITOR_PID=$!

# 3. Chay song song - contract_id = hash cua duong dan (tranh ky tu la/
#    trung ten giua cac project)
cat "$TMP_DIR/all_files_fl.txt" | tr -d '\r' | xargs -P 10 -I {} sh -c '
    sol_file="{}"
    contract_id=$(echo -n "$sol_file" | sha1sum | cut -c1-16)
    "$1" "$2" "$sol_file" "$contract_id" "$3" "$4/data/features_graph_function_level" \
        >> "$5/xargs_stdout_fl.log" 2>> "$5/xargs_stderr_fl.log"
' -- "$PYTHON_BIN" "$EXTRACT_SCRIPT" "$MANIFEST_FILES" "$HIN_DIR_DEFI" "$LOG_DIR"

kill $MONITOR_PID 2>/dev/null
echo "" | tee -a "$PIPELINE_LOG"

if [ -s "$LOG_DIR/xargs_stderr_fl.log" ]; then
    grep -i "error" "$LOG_DIR/xargs_stderr_fl.log" > "$ERROR_LOG"
    grep -i "traceback" "$LOG_DIR/xargs_stderr_fl.log" >> "$ERROR_LOG"
fi

JSON_COUNT=$(find "$DATA_DIR" -name "*_static.json" | wc -l)
echo "JSON files created: $JSON_COUNT / $TOTAL_FILES" | tee -a "$PIPELINE_LOG"

if [ "$JSON_COUNT" -gt 0 ]; then
    echo "SUCCESS: Function-level extraction completed. Files in $DATA_DIR" | tee -a "$PIPELINE_LOG"
else
    echo "ERROR: No JSON files created." | tee -a "$PIPELINE_LOG"
    exit 1
fi
