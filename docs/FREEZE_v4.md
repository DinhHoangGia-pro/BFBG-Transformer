# FREEZE v4 — manifest distinct + holdout (ĐÓNG BĂNG) 2026-10-21

## Hash (tất định)
- **docs/dataset_v4_manifest.jsonl** = `05e53c1d86bd0714735a8dff932fa22ba1554c5be7cfb3fa092ed9c5e9b8e54a` — **2208 malware distinct reps**.
- **docs/dataset_v4_benign_split.jsonl** = `755a5cc81373718c331c25c52d8a399e6d431b295030c079a720ae9f6c6bf3fb` — **207 benign v4** (neg holdout, 2 nhóm tách).
- Sinh tất định: seed **20261021**, global ppdeep union-find, rep = min(sha256)/cụm, sắp theo sha256, `json.dumps(sort_keys=True)`.
  Generator: `~/bfbg_benign_work/gen_v4_distinct.py` + benign-carve script (seed 20261021, shuffle rồi chia đôi).

## Split malware (manifest khóa, 2208)
| split | n | ghi chú |
|---|---|---|
| train_pool | 1006 | train chính (distinct, non-Zeus/non-downloader, trừ BumbleBee+BODMAS-temporal holdout) |
| holdout_bumblebee | 254 | holdout họ BumbleBee |
| holdout_bodmas_temporal | 150 | holdout cross-time BODMAS (2019-20) |
| zeus_separate | 767 | Zeus-lineage — báo cáo RIÊNG (không trộn train chính) |
| downloader_separate | 31 | Nymaim/downloader — báo cáo RIÊNG |
- **LOFO:** họ một-nguồn (qakbot, carberp, latrodectus, pikabot, zloader, ramnit, spyeye, retefe) đặt `lofo_exclude=true` → loại khỏi leave-one-family-out (family ≡ source, không tách được family khỏi source).

## Neg holdout (benign v4 = 207 → HAI nhóm tách)
| nhóm | n | ghép với |
|---|---|---|
| holdout_bumblebee_neg | 103 | holdout_bumblebee (254 pos) |
| holdout_bodmas_temporal_neg | 104 | holdout_bodmas_temporal (150 pos) |
- **benign v4 cho train = 0** — toàn bộ 207 benign v4 (mới, sạch) dùng làm neg holdout; **train-benign lấy từ v1/v2 non-holdout** (không chạm v3/holdout v2).
- Carve tất định: sắp sha256, shuffle seed 20261021, chia đôi (103/104).

## Lực thống kê (cluster-bootstrap trên manifest THẬT, giả định AUC 0.90)
- Mẫu pos là distinct cluster-reps (1/cụm) → cluster-bootstrap ≈ bootstrap chuẩn.
- **holdout_bumblebee** (pos 254 / neg 103): 95% CI = [0.880, 0.941], **±0.030**.
- **holdout_bodmas_temporal** (pos 150 / neg 104): 95% CI = [0.905, 0.963], **±0.029**.
- B=3000, seed 20261021 (`roc_auc_score` trên điểm giả định μ=√2·Φ⁻¹(0.9)).

## Quy tắc đóng băng (bắt buộc tuân thủ)
1. **Holdout chạm MỘT LẦN:** holdout_bumblebee + holdout_bodmas_temporal (và neg tương ứng) chỉ chấm **đúng một lần** ở báo cáo cuối. KHÔNG tuning, KHÔNG model selection, KHÔNG chấm lặp trên các holdout này.
2. **Zeus-lineage + downloader báo RIÊNG** — không gộp vào train/metric chính.
3. **Tất định:** mọi re-sinh phải cho đúng hash trên. Không sửa manifest sau freeze; thay đổi = manifest mới (v5), không ghi đè.
4. **Nguồn/năm/lineage/stratum** recoverable từ các trường trong manifest.
5. **KHÔNG chọn mẫu theo kết quả mô hình** — tập = toàn bộ distinct reps đã lift; split theo lineage/nguồn/năm (quy tắc ghi trước §24-§26), không phụ thuộc điểm.

## HẠN CHẾ (§26.4 — threats to validity, bắt buộc ghi trong bài)
1. **BumbleBee ĐÃ DÙNG TRONG PHÁT TRIỂN** (probe §17, các pilot, quyết định split trước) → KHÔNG phải holdout "chưa từng chạm" hoàn toàn → điểm trên holdout_bumblebee **lạc quan hơn** holdout sạch; nêu rõ.
2. **holdout_bodmas_temporal GỘP confound:** nguồn (BODMAS disarm/re-arm) + năm (2019-20) + nhãn-yếu → không tách được là do cross-time / cross-source / label-noise. Diễn giải thận trọng; kèm probe source/year (§24: AUC 0.72-0.77 trong bin).
3. **Nhãn họ BODMAS yếu** (82% None trên VT; Qakbot/Carberp ~toàn None) → family attribution nhánh BODMAS kém tin cậy.
4. **raw loader/bodmas đã xóa** (`raw_status=recoverable_no_relift`) → feature đã lift sẵn; nếu cần raw phải re-extract từ MB/DATA (meta_disarm.csv) **TRƯỚC khi lift/train** — chưa thực hiện ở bước freeze này.
5. **Neg holdout bin-mismatch:** benign v4 là MSVC14 (Scoop) → khớp bin với holdout_bumblebee (MSVC14 loaders) nhưng LỆCH bin với holdout_bodmas_temporal (phần lớn MSVC≤10) → một phần tách được ở bodmas-temporal có thể do khác bin toolchain, không chỉ cross-time.
6. Mục tiêu 1.500 train chính không đạt (1.416 distinct non-Zeus; §24.3; non-Zeus banking cạn nguồn).

## BỔ SUNG 2026-10-21 — thành phần benign train + probe nguồn holdout (KHÔNG đổi hash manifest)

### A. Thành phần benign TRAIN (v2 non-holdout, label=0, n=423; bin = classifier LINKER-PRIMARY)
| nguồn | kind | MSVC≤10 | 11-12 | MSVC14 | GNU | Go | Delphi | khác | tổng |
|---|---|---|---|---|---|---|---|---|---|
| windows11-eval-iso | ISO | 0 | 1 | 165 | 0 | 0 | 0 | 0 | 166 |
| scoop | vendor | 47 | 8 | 110 | 6 | 12 | 2 | 2 | 187 |
| nirsoft | vendor | 26 | 0 | 0 | 0 | 0 | 0 | 0 | 26 |
| 7-zip.org | vendor | 14 | 0 | 0 | 0 | 0 | 0 | 0 | 14 |
| python.org-embeddable | vendor | 0 | 0 | 12 | 0 | 0 | 0 | 0 | 12 |
| git-for-windows | vendor | 3 | 0 | 0 | 4 | 0 | 0 | 0 | 7 |
| notepad++ | vendor | 0 | 0 | 6 | 0 | 0 | 0 | 0 | 6 |
| ffmpeg | vendor | 5 | 0 | 0 | 0 | 0 | 0 | 0 | 5 |
| **TỔNG** | | **95** | **9** | **293** | **10** | **12** | **2** | **2** | **423** |

- **ISO = 166/423 = 39.2% > cap 35%** (vượt). MSVC14 = 293/423 = 69% benign train dồn vào một bin.
- **Cap vendor ≤35%/bin VƯỢT ở nhiều bin:** MSVC14 ISO 56% + scoop 38%; MSVC≤10 scoop 49%; Go scoop 100%; v.v. (các cap này là quy tắc harvest v3/v4; tập train v1/v2 đã khóa từ trước KHÔNG áp hồi tố — chỉ ghi nhận quan sát).

### B. HẠN CHẾ mới (ghi rõ trong bài)
7. **benign v4 = 0 trong train** — toàn bộ 207 benign v4 làm neg holdout; train-benign = v1/v2 (ISO+scoop+nirsoft+vendor), **không có benign nguồn-mới trong train**.
8. **neg holdout TOÀN Scoop** (MSVC14) → nguồn neg đồng nhất, lệch bin so với pos bodmas (MSVC≤10).

### C. Probe tách NGUỒN trong chính holdout (neg Scoop vs pos malware) — ĐÃ SỬA (loại artifact vex)
| holdout | pos / neg | đặc trưng probe | AUC (OOF 5-fold) |
|---|---|---|---|
| holdout_bumblebee | 254 / 103 | PE-metadata nguồn (9 feat, không vex) | **0.998** |
| holdout_bodmas_temporal | 140 / 102 | static features nội dung (8 feat, **bỏ vex**) | **0.896** |

- ⚠️ **SỬA:** số 0.994 ghi lần đầu cho bodmas **lẫn artifact pipeline** `vex_vocab_size` (xem mục D) → loại vex còn **0.896**. Vẫn là shortcut mạnh nhưng thấp hơn.
- **Kết luận: cả hai holdout TÁCH RẤT MẠNH bằng metadata/độ-phức-tạp nguồn — gần như không cần nội dung mã độc.**
  - bumblebee: `num_imports` 1.6 (packed) vs 15.5; `crt` 0 vs 0.98 → import-table/CRT là shortcut.
  - bodmas: `num_api_calls` 630 vs 4837; `num_functions` 1391 vs 4525 → malware nhỏ vs app Scoop lớn → shortcut kích-thước/phức-tạp trùng nguồn.
- **Hệ quả:** điểm cao trên 2 holdout này CÓ THỂ do khai thác shortcut nguồn (packer/kích-thước), KHÔNG phải năng lực phát hiện mã độc thật. **Phải GRL/khử-confound nguồn + báo cáo kèm cảnh báo; coi điểm holdout là CẬN TRÊN lạc quan.**
- bodmas probe chạy trên **static feature đã lift** (raw đã xóa `recoverable_no_relift`; PE-metadata-từ-raw hoãn, cần re-arm). 10/150 pos thiếu feature.

### D. ⚠️ ARTIFACT PIPELINE: `vex_vocab_size` lộ nguồn hoàn hảo (data-hygiene bắt buộc)
- `vex_vocab_size` KHÁC theo **batch lift / thư mục feature**, KHÔNG theo nội dung: v1 (`features_graph`) = 420-425; mb (`features_graph_loader`) = 587-588; bodmas = 588; scoop = ~573. **Không chồng lấp** → tách nguồn AUC=1.000 giả.
- **BẮT BUỘC: loại `vex_vocab_size` (và mọi feature phụ thuộc batch lift) khỏi input model**, hoặc chuẩn hóa chung một vocab, nếu không model học nguồn tầm thường. Mọi probe/metric phải loại feature này.

### E. Probe nguồn TRONG val in-dist của train_pool (Task 1, mb vs v1, 8 feat bỏ vex)
- train_pool: mb=553 / v1=453; chỉ **IcedID-lineage** có cả 2 nguồn (v1 114 / mb 83) — các họ khác đơn-nguồn (nguồn≈họ).
| probe | AUC | diễn giải |
|---|---|---|
| OOF group-by-lineage (khóa cả họ) | **0.423** | <0.5 → nguồn KHÔNG tách ổn định khi tổng quát qua họ (bất ổn, không phải "sạch") |
| OOF cluster 5-fold (không khóa họ) | **0.690** | lẫn với họ (nguồn≈họ) |
| **within-IcedID (test sạch duy nhất)** | **0.790** | shortcut nguồn trong-cùng-họ mức vừa, THẬT (v1 cũ vs mb mới khác size/entropy/import) |
- **Kết luận:** trong train có shortcut nguồn nội-họ ~0.79 (khớp §23 per-family 0.63-0.995) → **cần GRL/phân tầng nguồn khi train**, không chỉ ở holdout.
- (Với vex: cả 3 = 1.000 — artifact, xem mục D.)

### F. Xử lý ISO 39.2% (Task 2) — subsample ở LOADER (không xóa raw)
- Quy tắc: giữ **k=138/166** ISO (`windows11-eval-iso`), seed **20261021** (`random.Random(20261021).sample`), sắp sha256 → ISO% = 138/395 = **34.9% ≤ 35%**; bỏ 28 (chỉ mask ở loader, raw giữ nguyên).
- Danh sách giữ: `docs/iso_subsample_v4.txt` (138 sha, hash `57864041063ebc69c0374b01ee13b4d86f8fa8226b67d9fa8b4aecb994feceae`).
- Train-benign sau subsample = **395** (ISO 138 + scoop 187 + nirsoft 26 + 7-zip 14 + python 12 + git 7 + notepad++ 6 + ffmpeg 5).

### G. Đo throughput (run mẫu 3 epoch, fraction 1.0 base, 2026-10-21)
- GPU RTX 2080 Super Max-Q 8GB; model 0.53M params; BATCH=4; đo trên 876 mẫu dir `features_graph` (453 v1-mal + 423 benign).
- **~450 s/epoch (865 mẫu) → 1.9 mẫu/s** (nghẽn ở token-transformer per-function, num_workers=0).
- **peak VRAM = 5.79/8 GB** — ⚠️ có vài batch **OOM** bị bỏ (1-2/epoch) → BATCH=4 sát trần 8GB; nên **BATCH=2 hoặc giảm `max_funcs`/AMP** để ổn định (BATCH=2 ≈ gấp đôi giờ).
- Ngoại suy N_full=1401 (1006 mal + 395 benign sau ISO-subsample), 20 epoch: **12.1 min/epoch → ~4.05 h/run đầy đủ**.
- **Kế hoạch rút gọn (3 fraction × 2 seed, base) ≈ 3.5 × 4.05 = ~14.2 GPU-giờ** (BATCH=4 ổn); nếu buộc BATCH=2 ~**28 GPU-giờ**.
- Caveat: đo trên graph v1/v2 (nhỏ); mb/bodmas chưa đo, kích thước graph có thể khác → giờ thật ±.

### H. AUDIT toàn cục `vex_vocab_size` (2026-10-21) — bảng nào bị ảnh hưởng
Grep `vex` khắp `scripts/ experiments/ src/ docs/ paper_tables/ ~/bfbg_benign_work`:
| nơi | dùng vex_vocab_size làm FEATURE? | kết luận |
|---|---|---|
| `src/training/probe_baselines.py` (GRAPH 7 feat) | KHÔNG (`num_functions,num_api_calls,num_imports,file_size,max_section_entropy,is_likely_packed,total_nodes`) | sạch |
| `experiments/qa/_common.py SIMPLE_FEATURES` (8 feat) + `baseline_simple_features.py` | KHÔNG (match 'vex' chỉ là comment bỏ qua `vex_vocab.json`) | sạch |
| `~/bfbg_benign_work/source_probe.py` (§22/§23 probe nguồn, 9 PE-metadata feat) | KHÔNG | sạch |
| model `scripts/train_tcfbg_defi.py` global_features (4) | KHÔNG (`mean/max/min_entropy, has_any_external_call`) | sạch |
| model `src/training/bfbg_dataset.py` | global=0; vex chỉ là **kích thước vocab embedding** (hợp lệ) | sạch |
| `src/disassembly/*`, `bfbg_builder`, `build_graphs` | vex = tokenizer/lift (dựng graph), KHÔNG phải feature | sạch |
| **probe holdout bodmas (phiên này, §C)** | **CÓ** (static 9 feat gồm vex) | **ĐÃ SỬA 0.994→0.896** |
| **probe val-indist train_pool (§E)** | **CÓ** (vex) | **ĐÃ SỬA 1.000→0.423/0.690/0.790** |

- **Kết luận: KHÔNG có bảng v1-v3 / paper_tables / baseline / probe-nguồn committed nào dùng vex_vocab_size làm feature** → không cần tính lại gì ngoài 2 probe phiên này (đã làm, giữ số cũ + đánh dấu ⚠️ ở §C/§E).
- bumblebee holdout (§C, 0.998) dùng PE-metadata, vốn không có vex → không ảnh hưởng.

### G'. Kế hoạch rút gọn — cấu hình BATCH=2 + accumulation 2 (cập nhật)
- **BATCH=2 micro + grad-accumulation 2 → effective batch 4** (giữ nguyên động học so với §G). VRAM ~½ của BATCH=4 (5.79GB) ≈ **~3-3.5 GB → an toàn trong 8GB, hết OOM**.
- **Giờ:** vì nghẽn là **token-transformer per-function (CPU, num_workers=0)**, tổng compute/epoch ≈ KHÔNG đổi khi chia micro-batch (accumulation giữ nguyên số forward/backward) → throughput ~1.9 mẫu/s **giữ nguyên → ~4-4.5 h/run đầy đủ, rút gọn 6 run ≈ ~14-16 GPU-h**.
  - ⚠️ Con số **~28 GPU-h** chỉ đúng ở kịch bản xấu: GPU không lấp đầy ở micro-batch 2 làm throughput **giảm nửa** (ít khả năng vì bottleneck là CPU, nhưng CHƯA đo BATCH=2) → **đo lại ở run thật đầu tiên** để chốt.
- **AMP (fp16):** Turing (2080) có tensor-core → AMP giảm VRAM ~½ nữa + có thể tăng tốc nhẹ; NHƯNG (a) bottleneck CPU per-function nên lợi throughput ít, (b) fp16 dễ gây NaN ở softmax-attention + BCE `sem_loss` → **đề xuất KHÔNG AMP** (hoặc chỉ autocast phần GAT/Transformer, giữ fp32 cho loss). Không AMP = ổn định, giờ như trên.
- Khuyến nghị kèm: `num_workers≥4` để giảm nghẽn CPU (có thể cắt giờ đáng kể — chưa đo).

## Trạng thái cổng
- **CỔNG DỮ LIỆU 🔴 ĐÓNG.** Freeze v4 KHÔNG mở cổng train. Train/GRL/chấm holdout CHỈ khi DATA_EXPANSION_PLAN.md §0.1 ghi ngưỡng đã đạt.
- Freeze này: chốt manifest + hash + quy tắc. KHÔNG re-extract raw, KHÔNG train, KHÔNG xóa gì.

## BỔ SUNG 2026-10-22 — cross-family (ngoài phạm vi khóa, tham chiếu)
- LOFO-retrain sạch họ IcedID: BFBG 0.67 vs metadata/graph-RF ~0.91 (TRAINING_DESIGN §26). Số frozen §24 (0.934) bị thổi do encoder thấy họ → KHÔNG dùng. Không ảnh hưởng manifest/hash (05e53c1d).

- LOFO dừng sau họ 1 (§26a): hạn chế 1 họ / 1 seed / 20ep chưa hội tụ → BFBG 0.67 là cận dưới. Không ảnh hưởng manifest/hash.
