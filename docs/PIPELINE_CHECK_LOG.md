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

## 4 phép thử rẻ H1–H4 (CPU, post-hoc, dev set=choco) — 2026-10-10
Tập ghép đôi bb+choco n=306 (như trước). Tham chiếu: BFBG 4-seed 0.906±0.046, graph 0.904, metadata 0.985.

**H1 — cắt hàm / kích thước (confound):**
- num_functions (median): choco benign **4255** vs BumbleBee **394** → benign LỚN hơn malware ~10×. Cắt giữ 150 hàm đầu → với benign mất ~97% chương trình.
- AUC(label từ MỖI num_functions, eval) = 0.175 → định hướng đúng (benign lớn) = **0.825** → num_functions là shortcut xuyên-họ mạnh.
- Probe AUC truncated vs non-trunc: meta 0.980/0.987, graph 0.907/0.797 (non-trunc chỉ 3 ben → không đáng tin). Cắt không rõ làm hại probe.

**H2 — ensemble/calibration 4 checkpoint (best-val_loss):**
| | AUC | Brier | recall@FPR 1/5/10 |
|---|---|---|---|
| s101/202/303/404 | 0.891/0.950/0.934/0.848 | 0.106/0.118/0.062/0.158 | (xem log) |
| **ENSEMBLE mean4** | **0.932** | **0.077** | **25/33/97** |
→ Ensemble ≈ top-single AUC, Brier tốt, **recall@FPR10 nhảy lên 97** (vs 55–79 từng seed) + ổn định. Không cần GPU.

**H3 — bag-of-tokens TF-IDF + RF (train_pool→eval):** vocab 1361, **AUC 0.972, recall@FPR 90/90/95** → **vượt BFBG (0.906) và graph (0.907), gần metadata**. Token thô một mình đã rất mạnh.

**H4 — thêm API histogram vào probe graph:** graph-only 0.907 → **graph+APIhist 0.950** (recall@FPR5 39→88). API histogram giúp mạnh.

**Đọc tổng (trung thực):** nhiều baseline ĐƠN GIẢN không-GNN (metadata 0.985, bag-of-tokens 0.972, graph+API 0.950) **ngang/vượt BFBG 0.906**. Kết hợp Task 2 (embedding mã hóa toolchain/family, untrained≥trained) + H1 (benign lớn gấp ~10× malware) → tác vụ BumbleBee-vs-choco **bị chi phối bởi confound (kích thước họ, toolchain, tần suất token/API)**; cấu trúc GNN KHÔNG phải yếu tố quyết định. Mọi số là dev-set choco, post-hoc, chưa đụng holdout kiểm định cuối.

## Within-bin / LOFO / cắt-hàm / kích thước (CPU, post-hoc, dev=choco) — 2026-10-10
Tham chiếu BFBG 4-seed 0.906±0.046 (SE≈0.023 → 2·SE≈0.046).

### #1a WITHIN-MSVC14 (train trong bin; eval MSVC14 mal=252 vs choco MSVC14=21) — AUC [CI cụm]
| metadata | graph | graph+API | bag-of-tokens |
|---|---|---|---|
| **1.000** [1.000,1.000] | 0.974 [0.955,0.990] | 0.994 [0.985,1.000] | 0.976 [0.940,1.000] |

**BFBG train-trong-bin MSVC14: CHƯA đo** (cần train GPU trong bin, không chạy) → **bỏ cột** (cột cũ "BFBG train toàn bin, eval-subset" **không so được** vì train khác phân phối: toàn-bin vs trong-bin). Sẽ đo ở §20 nếu chạy.

**Xác minh (sửa 2026-10-10):** choco MSVC14 = **21 cụm riêng biệt** (21 singleton); BumbleBee MSVC14 = 244 cụm/252. **train∩eval overlap sha=0, cụm=0** (tách tuyệt đối, không rò rỉ). metadata AUC=1.0000 là **held-out thật**. **Không feature đơn nào** tách hẳn (linker/year/size/nonstd/max_ent đều chồng lấn pos/neg) → RF tách bằng **tổ hợp đa biến**. Bootstrap [1.000,1.000] suy biến vì AUC đúng =1.0 ở mọi cluster-resample; **n_neg=21 quá nhỏ → AUC=1.0 KHÔNG phải bằng chứng mạnh**, cần nhiều benign MSVC14 hơn.

### #1b LOFO 5-family (test = family giữ lại vs choco; train = 4 family + benign) — AUC
| family | metadata | graph | graph+API | bag-of-tokens |
|---|---|---|---|---|
| TrickBot | 0.977 | 0.898 | 0.932 | 0.922 |
| Dridex | 0.995 | 0.953 | 0.948 | 0.945 |
| IcedID | 0.955 | 0.929 | 0.943 | 0.747 |
| Emotet | 0.954 | 0.853 | 0.914 | 0.842 |
| BumbleBee | 0.977 | 0.908 | 0.938 | 0.924 |
| **mean±std** | **0.972±0.017** | 0.908±0.037 | 0.935±0.013 | 0.876±0.082 |
→ **metadata tổng quát hóa tốt & ổn định nhất** qua họ. **bag-of-tokens tụt mạnh & nhiễu** (IcedID 0.747) → tín hiệu token mang tính đặc-thù-họ, KHÔNG tổng quát. graph+API > graph.

### #2 bag-of-tokens bỏ idiom compiler (chỉ call/API) — eval bb vs choco
tokens(full, cắt theo model-view) 0.930 [0.867,0.980]; **call/API-only 0.941** [0.898,0.975] → bỏ idiom compiler KHÔNG giảm (còn tăng nhẹ) → tín hiệu token là **call/API** chứ không phải chỉ dấu-vân compiler.

### #3 seed-evidence (ATT&CK) nằm SAU điểm cắt
| nhóm | seed_tot | bị bỏ do hàm>150 | bị bỏ do token>512 |
|---|---|---|---|
| benign (train+choco) | 574 | **95.8%** | 0.2% |
| malicious (all) | 657 | **76.6%** | 0.0% |
| TrickBot/IcedID/Emotet/BumbleBee | 21/217/401/14 | 52%/39%/**97%**/**100%** | 0% |
→ **Cắt 150 hàm đầu (theo địa chỉ) vứt 77–96% bằng chứng seed; BumbleBee mất 100%, Emotet 97%.** Cắt 512 token gần như vô hại. Nhánh ngữ nghĩa của model gần như **bị bỏ đói seed**.

### #4 probe kích thước (khoảng chồng lấn num_functions [47,17653], n=283: mal239/choco44)
num_functions một mình (oriented) **0.821**; metadata 0.983, graph+API 0.936, BFBG 0.929, bag-of-tokens 0.924, graph 0.905.
→ Kiểm soát lỏng kích thước KHÔNG khử tín hiệu; metadata vẫn ~0.98. (Khoảng chồng lấn quá rộng để kiểm soát chặt.)

## KẾT LUẬN (post-hoc, dev-set; chưa đụng holdout kiểm định cuối)
1. **metadata (PE cơ bản) thống trị mọi lát cắt** (within-bin 1.000, LOFO 0.972±0.017, size-overlap 0.983) — benign set hiện tại (choco/scoop/nirsoft/iso) **tách khỏi các họ banking-trojan bằng metadata thô** (signed/linker/year/size/entropy). BFBG/GNN KHÔNG vượt metadata.
2. **Cắt 150 hàm đầu bỏ 77–100% seed evidence** → nhánh ngữ nghĩa bị đói; đây là lỗi INPUT WINDOW, không phải kiến trúc.
3. Tín hiệu token = call/API (không phải idiom compiler) nhưng **không tổng quát qua họ** (LOFO).
→ Vấn đề lớn nhất có lẽ là **DỮ LIỆU** (benign quá khác phân phối) + **cửa sổ đầu vào**, không phải kiến trúc model.

## Task 5 — ĐỀ XUẤT LẠI GT GPU (tiêu chí >2·SE ≈ +0.046 AUC trên trung bình ≥4 seed; ghi trước, CHƯA chạy)
| Ưu tiên | GT (một thay đổi) | Vì sao (bằng chứng) | Tiêu chí thắng (>2·SE) | VRAM/thời gian |
|---|---|---|---|---|
| **1 (mạnh nhất)** | **H1: chọn 150 hàm theo seed/API-density/spread thay vì 150 đầu-theo-địa-chỉ** | #3: 77–100% seed bị cắt; BumbleBee 100% | (a) seed-coverage trong cửa sổ từ ~0–23% → **>80%**; VÀ (b) BFBG choco AUC (≥4 seed) **> 0.952** (0.906+2SE) HOẶC LOFO-mean tăng >2·SE | ~4.5GB · ~2h30–3h20/seed ×4 ≈ 10–13h |
| 2 | H4: global_features = API histogram top-K (hiện=0) | graph+API 0.935 vs graph 0.908 (LOFO, ổn định) | BFBG+API choco AUC (≥4 seed) **>0.952** | ~4.5GB · 10–13h |
| — (0 GPU) | H2: ensemble 4 checkpoint sẵn có | recall@FPR10 97 | đã đạt; dùng ngay | 0 GPU |
| Bỏ | H3: nhánh bag-of-tokens | LOFO 0.876±0.082, không tổng quát | — | — |
| Hướng DỮ LIỆU (không phải GPU) | Thu benign KHÓ: cùng toolchain/size/signed với malware (giảm confound metadata) | metadata thống trị mọi lát cắt | metadata AUC tụt về <0.90 trên benign-khó | thu thập dữ liệu |

## #3 (sạch) — chọn 150 hàm KHÔNG dùng seed: first / spread-địa-chỉ / api-density (2026-10-10)
Đo trên malicious (5 family) + choco + 200 benign train. "Seed coverage" = % seed-edge nằm trong 150 hàm được chọn.

| policy | seed coverage (tổng) | malicious | benign(train) | median nodes KEPT mal/ben (ratio ben/mal) |
|---|---|---|---|---|
| first-150 (hiện tại, theo địa chỉ) | **17.6%** | 24% | 5% | 4834 / 7131 (1.48) |
| spread đều theo địa chỉ | 15.9% | 21% | 5% | 4844 / 7393 (1.53) |
| **api-density (top-150 hàm nhiều call/API)** | **71.7%** | 74% | 68% | 14781 / 41798 (**2.83**) |

→ **api-density giữ 72% seed evidence (vs 18% first-150) mà KHÔNG dùng nhãn seed** — ứng viên cho H1. spread-địa-chỉ KHÔNG giúp (16%).
⚠️ **Đánh đổi:** api-density giữ các hàm lớn → **tăng lệch kích thước** benign/malware (ratio nodes-kept 1.48→2.83). Có thể đổi confound "đói seed" lấy confound "kích thước". Cần theo dõi khi chạy H1.
