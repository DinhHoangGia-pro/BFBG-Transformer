#!/bin/bash
# Build DOT 1 trong cgroup RIENG (systemd --user) de KHONG lam OOM/treo VS Code.
# Cau hinh: workers=4 x ~3GB/worker (angr CFGFast) = ~12GB + 2GB overhead -> MemoryMax=14G.
# May 30GB -> con >=16GB cho VS Code/OS. timeout 900s/mau. IO idle + nice 19.
# OOMKill da duoc tach khoi Timeout trong build_graphs.py (exit -9 truoc timeout).
set -euo pipefail
REPO=/home/dhgia/Work/Defi/BFBG-Transformer
IN="${1:?Usage: run_build_batch.sh <input_dir> <label 0|1>}"
LABEL="${2:?label 0 or 1}"
WORKERS=4
MEMMAX=14G
systemctl --user reset-failed bfbg-build1.service 2>/dev/null || true
systemd-run --user --unit=bfbg-build1 --nice=19 \
  --property=IOSchedulingClass=idle \
  --property=MemoryMax=$MEMMAX --property=MemorySwapMax=0 \
  bash -lc "cd $REPO && ~/bfbg_venv/bin/python scripts/build_graphs.py \
     --input-dir '$IN' --label $LABEL --workers $WORKERS --timeout 900 --append \
     > ~/bfbg_benign_work/build_batch1.out 2>&1"
echo 'Build dot 1 chay trong service bfbg-build1 (cgroup rieng, MemoryMax=14G).'
echo 'Theo doi: systemctl --user status bfbg-build1.service ; cat ~/bfbg_benign_work/build_batch1.out'
