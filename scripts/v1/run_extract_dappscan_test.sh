#!/bin/bash
# =============================================================================
#  run_extract_evm_xargs.sh – DeFi/EVM PROJECT VERSION
#  Da cap nhat khop cau truc thu muc that: ~/Work/Defi/Defi_analysis/
#  Du lieu train_ready/ (da dedup + can bang 1:1, 12.874 hop dong) duoc copy
#  tu download_dataset/data/dappscan_test/ sang day/data/train_ready/.
# =============================================================================

export HIN_DIR_DEFI="/home/dhgia/Work/Defi/Defi_analysis"
export LOG_DIR="$HIN_DIR_DEFI/logs"
export TMP_DIR="$HIN_DIR_DEFI/tmp"
export DATA_DIR="$HIN_DIR_DEFI/data/dappscan_test"   # da dedup + can bang, KHONG con thu muc con theo category

VENV_DIR="/home/dhgia/defi_venv"
PYTHON_BIN="$VENV_DIR/bin/python"
EXTRACT_SCRIPT="$HIN_DIR_DEFI/scripts/extract_evm_features.py"
# Neu extract_evm_features.py dang nam trong scripts_HGT/ thay vi scripts/,
# doi dong tren thanh: EXTRACT_SCRIPT="$HIN_DIR_DEFI/scripts_HGT/extract_evm_features.py"

PIPELINE_LOG="$LOG_DIR/pipeline_defi.log"
ERROR_LOG="$LOG_DIR/extract_errors.log"

mkdir -p "$LOG_DIR" "$TMP_DIR" "$HIN_DIR_DEFI/data/features_graph_dappscan_test"
> "$ERROR_LOG"
> "$PIPELINE_LOG"

if [ ! -f "$VENV_DIR/bin/activate" ]; then
    echo "CRITICAL: Venv not found at $VENV_DIR"
    exit 1
fi
source "$VENV_DIR/bin/activate"

echo "=== DEFI STATIC ANALYSIS (ENV: HIN_DIR_DEFI) – STARTED $(date) ===" | tee -a "$PIPELINE_LOG"
echo "ROOT DIR: $HIN_DIR_DEFI" | tee -a "$PIPELINE_LOG"
echo "DATA DIR: $DATA_DIR" | tee -a "$PIPELINE_LOG"

# 1. Tim toan bo file .sol (chi con 2 thu muc phang: vulnerable/ va safe/)
find "$DATA_DIR" -type f -name "*.sol" > "$TMP_DIR/all_files.txt"
TOTAL_FILES=$(wc -l < "$TMP_DIR/all_files.txt")
echo "Total .sol files to process: $TOTAL_FILES" | tee -a "$PIPELINE_LOG"

if [ "$TOTAL_FILES" -eq 0 ]; then
    echo "ERROR: No .sol files found under $DATA_DIR" | tee -a "$PIPELINE_LOG"
    echo "  -> Kiem tra lai da chay lenh 'find ... -exec cp' de copy du lieu tu" | tee -a "$PIPELINE_LOG"
    echo "     download_dataset/data/dappscan_test/ sang day chua." | tee -a "$PIPELINE_LOG"
    exit 1
fi

# 2. Don output cu (idempotent re-run)
rm -f "$HIN_DIR_DEFI/data/features_graph_dappscan_test"/*_static.json 2>/dev/null || true

# 3. Background monitor tien do
(
    while kill -0 $$ 2>/dev/null; do
        COUNT=$(find "$HIN_DIR_DEFI/data/features_graph_dappscan_test" -name "*_static.json" | wc -l)
        echo -ne "Progress: $COUNT / $TOTAL_FILES files created...\r"
        if [ "$COUNT" -ge "$TOTAL_FILES" ]; then break; fi
        sleep 2
    done
) &
MONITOR_PID=$!

# 4. Chay song song 12 luong - gan nhan theo DUONG DAN DAY DU (khong con
# thu muc con theo category nen khong the chi nhin ten thu muc cha truc tiep)
cat "$TMP_DIR/all_files.txt" | tr -d '\r' | xargs -P 12 -I {} sh -c '
    sol_file="{}"
    case "$sol_file" in
        */vulnerable/*) label=1 ;;
        */safe/*)       label=0 ;;
        *)
            echo "[CANH BAO] Khong xac dinh duoc nhan cho: $sol_file" >> "$4/label_warnings.log"
            exit 0
            ;;
    esac
    contract_id=$(basename "$sol_file" .sol)
    "$1" "$2" "$sol_file" "$contract_id" "$label" "$3/data/features_graph_dappscan_test" \
        >> "$4/xargs_stdout.log" 2>> "$4/xargs_stderr.log"
' -- "$PYTHON_BIN" "$EXTRACT_SCRIPT" "$HIN_DIR_DEFI" "$LOG_DIR"

kill $MONITOR_PID 2>/dev/null
echo "" | tee -a "$PIPELINE_LOG"

if [ -s "$LOG_DIR/xargs_stderr.log" ]; then
    grep -i "error" "$LOG_DIR/xargs_stderr.log" > "$ERROR_LOG"
    grep -i "traceback" "$LOG_DIR/xargs_stderr.log" >> "$ERROR_LOG"
fi

if [ -f "$LOG_DIR/label_warnings.log" ]; then
    N_WARN=$(wc -l < "$LOG_DIR/label_warnings.log")
    echo "CANH BAO: $N_WARN file khong xac dinh duoc nhan (xem $LOG_DIR/label_warnings.log)" | tee -a "$PIPELINE_LOG"
fi

JSON_COUNT=$(find "$HIN_DIR_DEFI/data/features_graph_dappscan_test" -name "*_static.json" | wc -l)
echo "JSON Graph files created: $JSON_COUNT" | tee -a "$PIPELINE_LOG"

if [ "$JSON_COUNT" -gt 0 ]; then
    echo "SUCCESS: DeFi feature extraction completed. Files are in $HIN_DIR_DEFI/data/features_graph_dappscan_test" | tee -a "$PIPELINE_LOG"
else
    echo "ERROR: No JSON files created." | tee -a "$PIPELINE_LOG"
    exit 1
fi
