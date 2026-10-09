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

## PRE-REGISTRATION (ghi trước 2026-10-09, trước khi chạy) — cấu hình ổn định hóa
Mục tiêu: xem cosine LR schedule có giảm nhiễu seed của BFBG không. Ghi TRƯỚC khi xem kết quả.
- Cấu hình: grad clipping 1.0 (đã là baseline) + **CosineAnnealingLR(T_max=20)** trên Adam lr 2e-4→0.
- 20 epoch cố định, v2 train (ISO cap 113), BumbleBee fold, num_global_features=0.
- **Seed ghi trước = {101, 202, 303}** (không đổi sau khi xem kết quả).
- Nhãn: **POST-HOC** (phân tích sau khi đóng băng design freeze-v2); KHÔNG dùng để chỉnh design đã khóa.
- Ngoài ra chạy lại v2dev gốc (seed 20261008, KHÔNG cosine) để lấy per-sample score cho Task 3 (cắt hàm).

## Ghi chú 2026-10-09: pre-registration 6fe7331 BỊ THAY THẾ
Pre-registration cosine LR (commit 6fe7331, seed {101,202,303}) **bị thay thế bởi §17**
(early-stopping + ReduceLROnPlateau, bỏ cosine). Các run cosine KHÔNG chạy (driver bị dừng
trước khi ra JSON). TRAINING_DESIGN.md sau §17: SHA256 `c5a948dadef4aa1f534f85c41bfdaa5646cc50343287e45edf95ee1d04b479dc`.

## Bước 3 — dev run post-hoc §17 (v2, seed 202, 1 seed, KHÔNG kết luận) 2026-10-09
- Early-stop @ep19 (no_improve≥10), nạp best ep9 (val_loss 0.382). lr giảm 2 lần (ep14, ep19). ~600s/ep, ~3h20, VRAM 4.5GB, GPU 53–56°C, 0 OOM/0 bad.
- AUC(BumbleBee vs choco): **BFBG 0.950 [0.910,0.984]**, graph 0.904, metadata 0.985.
  dAUC BFBG−graph +0.046 [−0.016,+0.115]; BFBG−metadata −0.035 [−0.077,+0.001].
  recall@FPR 1/5/10%: BFBG 51/70/79, graph 31/39/87, metadata 74/96/98.
- **Quan sát (KHÔNG quy nhân quả):** seed 202 có 0.680 ở cấu hình cũ (v1, fixed-20-epoch, lấy model epoch cuối)
  và 0.950 ở cấu hình này (v2, §17, nạp best-val_loss ep9). Hai điểm này khác NHAU cả **dữ liệu (v1→v2)** lẫn
  **quy tắc chọn epoch (last→best-val_loss)** → KHÔNG tách được đóng góp của riêng §17; không kết luận §17 "khử 0.68".
  (Phần cắt hàm đã bỏ khỏi báo cáo: non-truncated chỉ 3 benign.)
- Mốc so sánh (theo yêu cầu) = dev run v2 seed20261008 (0.879) + graph 0.906 + metadata 0.985, KHÔNG phải 0.68 của v1.
- **Bước 4:** AUC 0.950 ≥0.85 → đề xuất thêm seed (§16 cần ≥5). Người dùng chọn CHƯA CHẠY. Chưa đủ 5 seed nên KHÔNG kết luận.
- File: ~/bfbg_benign_work/foldrun_v2es202.json; checkpoint best/last ckpt_v2es202{,_last}.pt.

## Task 2 — chẩn đoán đường tắt trên embedding checkpoint §17 (seed202, 2026-10-09)
Linear probe (LogReg) dự đoán toolchain-bin / family từ embedding (dim 128), CV theo cụm (k=5).
Tập = train_pool + bumblebee + test_indist + choco (KHÔNG đụng holdout_nirsoft), n=1846.

| | toolchain-bin (CV-acc) | family (CV-acc, malicious n=1382) |
|---|---|---|
| **trained-emb** (ckpt §17) | 0.693 | 0.691 |
| **untrained-emb** (random init) | **0.797** | **0.791** |
| 7-scalar (graph feats) | 0.687 | 0.773 |
| from-label (nhãn→bin) | 0.532 | — |
| majority-class | 0.470 | 0.287 |

**Đọc trung thực:**
- Embedding mã hóa MẠNH toolchain/family: trained 0.69 (bin) & 0.69 (family) >> majority 0.47/0.29 và from-label 0.53.
  → confound toolchain≈family nằm NGAY trong biểu diễn, khớp phát hiện toàn dự án.
- **untrained > trained** (0.797 vs 0.693 bin; 0.791 vs 0.691 family): shortcut nằm ở đặc trưng đầu vào/kiến trúc
  (random projection giữ cấu trúc), KHÔNG do training tạo ra. Training thậm chí GIẢM nhẹ tính đoán-được
  toolchain/family của embedding — nhưng vẫn cao (không khử hết shortcut).
- 7-scalar cũng đoán family tốt (0.773) → đặc trưng đồ thị thô cũng confound.
Script: experiments/dataset/pilots/shortcut_probe_emb.py. Nhãn: analysis (inference), không train BFBG.

## Seed 101 — dev run post-hoc §17 (v2, 2026-10-09)
- Early-stop @ep19 (no_improve≥10), nạp best val_loss ep9 (vl 0.3715). lr 2e-4→1e-4(@ep8)→5e-5(@ep14). 0 OOM/0 bad, GPU 54–60°C, ~605s/ep.
- **CHÍNH (best val_loss, ep9):** AUC(BumbleBee vs choco) **0.891 [0.816,0.955]**; graph 0.904, metadata 0.985.
  dAUC BFBG−graph −0.012 [−0.096,+0.070]; BFBG−metadata −0.093 [−0.166,−0.029]. recall@FPR 1/5/10 = 23/27/55.
- **PHỤ (peak val-AUC = argmax val_auc @ep19, TRÙNG epoch cuối run này):** AUC 0.926 [0.865,0.978];
  dAUC−graph +0.023; dAUC−metadata −0.058 [−0.118,−0.005]. recall@FPR 1/5/10 = 28/40/88.
  Vì ep19 vừa là peak-val-AUC vừa là epoch cuối, run này KHÔNG phân biệt được "peak-val-AUC" với "last-epoch".
- **AUC nhạy với cách chọn epoch:** 0.891 (best-val_loss ep9) vs 0.926 (peak-val-AUC/last ep19) — cùng 1 seed.
- **Gate:** CHÍNH 0.891 ∈ [0.85,0.90) → KHÔNG <0.85 (không fail), KHÔNG ≥0.90 (không kích hoạt "hỏi chạy thêm"). Dừng, không tự chạy run khác.
- **Hai seed §17 (post-hoc):** best-val_loss AUC = {s101 0.891, s202 0.950}, spread ~0.06 → nhiễu seed vẫn còn dù dùng §17.
  KHÔNG quy cho §17 việc "khử 0.68" (điểm 0.68 ở v1/fixed-epoch khác cả dữ liệu lẫn quy tắc). Mới 2 seed < 5 (§16) → KHÔNG kết luận.

## Tổng hợp 4 seed §17 (post-hoc, v2, BumbleBee fold) — 2026-10-09
Seed {101,202,303,404}, cùng split/val (carve seed 20261008), §17 (early-stop, nạp best-val_loss). Đều early-stop ep17–19.

| seed | best_ep | AUC_choco (best-val_loss) [CI cụm] | dAUC−graph | dAUC−metadata | peak-val-AUC AUC | recall@FPR 1/5/10% |
|---|---|---|---|---|---|---|
| 101 | 9 | 0.891 [0.816,0.955] | −0.012 | −0.093 | 0.926 | 23/27/55 |
| 202 | 9 | 0.950 [0.910,0.984] | +0.046 | −0.035 | (n/a*) | 51/70/79 |
| 303 | 8 | 0.934 [0.886,0.976] | +0.030 | −0.051 | 0.911 | 49/56/62 |
| 404 | 7 | 0.848 [0.767,0.921] | −0.055 | −0.136 | 0.919 | 2/19/75 |

(*s202 chạy trước khi thêm tính năng lưu peak-val-AUC checkpoint → không có.)

**Tổng hợp (trung bình ± std, n=4):**
- AUC_BFBG = **0.906 ± 0.046** (min 0.848, max 0.950). graph ref 0.904, metadata ref 0.985.
- dAUC BFBG−graph = **+0.002 ± 0.046** (straddle 0) → BFBG ≈ graph probe.
- dAUC BFBG−metadata = **−0.079 ± 0.046** → BFBG **dưới** metadata nhất quán (mọi seed âm).

**Đọc trung thực (post-hoc, chưa đủ 5 seed theo §16):**
- Nhiễu seed VẪN còn dù §17: AUC 0.85–0.95 (±0.046); recall@FPR dao động rất mạnh theo seed (vd s404 2% vs s202 51% @FPR1%).
- BFBG ngang graph probe, **thua metadata** (metadata mạnh do confound toolchain≈family — xem Task 2 đường tắt).
- Mới 4 seed (§18 danh sách {101,202,303,404}); §16 cần ≥5, **chưa chốt seed thứ 5** → KHÔNG tuyên bố đủ bộ/kết luận.
