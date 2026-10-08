# PIPELINE-CHECK / DEV-RUN LOG (KHÔNG phải kết quả)

> Mọi số dưới đây là **pipeline-check / dev-run**, KHÔNG dùng làm kết quả báo cáo.
> Chưa chạy LOFO 5 fold. Không đụng holdout_nirsoft. Design khóa ở tag `freeze-v2`
> (commit 0a3de27) TRƯỚC khi mọi fold chạy; các số này không dùng để chỉnh design.
> Ghi ngày 2026-10-09 (+07).

## Thiết lập chung
- Fold = **BumbleBee held-out family** (262 malicious), tách sẵn trong split đóng băng.
- Tập đánh giá = BumbleBee (262, dương) vs choco = holdout_source_chocolatey (benign, âm).
  1 mẫu choco `29351494…` (GNU/MinGW, chocolatey, label0, **num_functions=0**) bị loại ở
  loader (đồ thị rỗng) → tập ghép đôi dùng chung **n=306** (bb=262, choco=44), prevalence 0.856.
- BFBG: effective batch 4 (micro 2 × accum 2), 20 epoch cố định (§15), lr 2e-4, λ_sem 0.3,
  max_funcs 150, num_global_features=0, vocab đóng băng 1322. Chạy cgroup 6G/nice19, GPU.
- 2 probe RF (metadata, graph) train trên **cùng tập train** với BFBG để so ghép đôi công bằng.
- AUC = threshold-free; CI = cluster-bootstrap 2000 lần (cụm near-dup). PR-AUC bỏ (prevalence 0.856).

## Task 2 — nhiễu seed (v1, cùng 928 train / cùng val theo cụm, seed carve 20261008)

| model-seed | AUC_BFBG [CI] | AUC_graph | dAUC BFBG−graph [CI] | dAUC BFBG−metadata [CI] |
|---|---|---|---|---|
| 20261008 | 0.884 | 0.919 | −0.034 [−0.110,+0.043] | +0.000 [−0.078,+0.084] |
| 101 | 0.824 [0.741,0.897] | 0.919 | −0.095 [−0.185,−0.011] | −0.060 [−0.132,+0.020] |
| 202 | 0.680 [0.600,0.756] | 0.919 | −0.239 [−0.338,−0.144] | −0.205 [−0.277,−0.124] |

**Kết luận:** nhiễu seed của BFBG RẤT lớn — AUC(BB vs choco) dao động **0.680–0.884** (biên ~0.20)
chỉ do đổi seed; graph/metadata probe cố định (0.919 / 0.884, không phụ thuộc seed BFBG).
Hiệu ghép đôi BFBG−graph **luôn âm** ở cả 3 seed (BFBG thua), 2/3 seed loại trừ 0.
→ **So sánh một-seed là không đáng tin**; cần nhiều seed trước khi kết luận.

recall @ FPR cố định trên choco (BFBG, 3 seed): FPR1% 41/55/37, FPR5% 41/55/41, FPR10% 45/55/51.
graph ổn định 35/51/**89**; metadata 32/36/57. → BFBG không vượt graph ở điểm vận hành FPR thấp.

## Task 3 — DEV RUN v2 (v2 manifest, ISO subsample K=113, 1 seed=20261008)
- train = v2 train_pool 1266 − 28 ISO (giữ 113/141) = **1238** (gồm 249 benign mới scoop/nirsoft; KHÔNG chứa BumbleBee).
- fixed 20 epoch; loss 0.568→0.220.

| model | AUC [CI] | dAUC vs BFBG | recall@FPR 1/5/10% |
|---|---|---|---|
| metadata | **0.980** [0.953,0.998] | BFBG−meta = −0.101 [−0.166,−0.041] | 66 / 95 / 98 |
| graph | 0.906 [0.848,0.953] | BFBG−graph = −0.026 [−0.103,+0.054] | 32 / 39 / 87 |
| BFBG | 0.879 [0.818,0.932] | — | 17 / 53 / 84 |

**Quan sát:** thêm 249 benign v2 làm **metadata probe mạnh hẳn** (0.980) — RF bắt chữ ký
toolchain/linker/năm của benign mới rất tốt (xác nhận confound toolchain≈family đã ghi). BFBG
(0.879) dưới cả hai probe; BFBG−metadata loại trừ 0 (BFBG thua rõ). Là **dev run**, không kết luận.

## Task 1 — num_functions=0 (ghi §14 TRAINING_DESIGN)
- v1: 2 mẫu (đều label0: choco 1, iso 1). v2: 4 mẫu (đều label0: choco 1, scoop 2, iso 1). 0 malicious.
- Quy tắc: loại ở loader cho **CẢ hai nhãn** (label-agnostic), không sửa manifest, log số lượng.

## Task 4 — chọn epoch (ghi §15 TRAINING_DESIGN)
- Epoch **cố định = 20** (ghi trước), không early-stopping, không dùng choco/validation chọn epoch.
- Validation theo cụm chỉ chẩn đoán overfit. Task-2 val-AUC tăng tới ~0.94 ở epoch 19, không tụt
  → chưa thấy overfit trong 20 epoch.

## Task 5 — OOM / mẫu bỏ
- 3 run mới (seedA/seedB/v2dev): **fail_oom = [] (0 batch OOM)**, bad=0 mọi epoch.
- Batch OOM duy nhất trước đó ở **run consolidated epoch 14** (1/464 micro-batch): script đó CHƯA
  log sha nên **không biết chính xác mẫu nào**, và thời điểm OOM không tất định → không tái dựng được.
- **Cách xử lý OOM:** bắt `torch.cuda.OutOfMemoryError` → `empty_cache()` → **bỏ nguyên micro-batch đó**,
  KHÔNG giảm batch-size. `fold_run.py` nay ghi [epoch, danh sách sha] cho mọi batch OOM (từ run này trở đi).
- Mẫu bỏ khi chấm (mọi run): `29351494…` (num_functions=0), nhất quán.

## Provenance / git
- Commit: 65b57f6 (orig_name + ISO §13), 1d1a6e7 (mốc thời gian fold), 72991a7 (§14+§15).
  Tag chú thích **freeze-v2.1** (cf4b43c). v2 manifest hash e2e2c67.
- **CHƯA push** (môi trường thiếu credential GitHub): cần chạy
  `git push origin restructure-bfbg && git push origin freeze-v2.1`.
- Kết quả thô: `~/bfbg_benign_work/foldrun_{seedA,seedB,v2dev}.json`, `fold_consolidated.json`.
