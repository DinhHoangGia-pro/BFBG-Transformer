# Thiết kế src/training/ (CHƯA viết code — bản thiết kế)

Dựa trên các probe/kiểm chứng (Phần A, Task 1–5, 2026-10). Ràng buộc rút ra từ dữ liệu:
seed-rule và metadata **bị confound mạnh với bin toolchain** (T1497 ≈ nhãn MSVC14; benign-ISO fire T1547 cao hơn malware trong cùng bin); loader cũ nạp toàn bộ JSON → **OOM 26GB**. Thiết kế phải xử lý cả hai.

## 1. Loader — STREAMING, bộ nhớ hằng số
- Đọc `docs/dataset_v1_manifest.jsonl` (sha, label, source, split, cluster) làm chỉ mục; **KHÔNG** nạp toàn bộ JSON.
- `Dataset.__getitem__` nạp **một** `features_graph/<sha>_static.json`, dựng `torch_geometric.Data` (node = token embedding, edges_cfg/edges_seq nội hàm, call graph liên hàm), rồi giải phóng. Collate theo batch.
- Lý do: lesson OOM — giữ bộ nhớ ~một mẫu/worker; không `[json.load(...) for all]`. Dùng `num_workers` nhỏ + `MemoryMax` ở runner (xem `run_build_batch.sh`).

## 2. Split — group-aware theo cụm near-dup (đóng băng v1)
- Dùng field `split` đã đóng băng: `train_pool` / `test_indist` / `holdout_family_bumblebee` / `holdout_source_chocolatey`. **Không tự chia lại** v1.
- Val: **k-fold group-aware** TRÊN `train_pool`, nhóm = `cluster` (near-dup) **và** vendor/source; **không bao giờ** tách một cụm qua train/val. (Cụm từ `near_duplicate_clusters.jsonl` / field `cluster`.)
- Hai holdout là **một chiều** → khi đánh giá ghép mẫu đối nhãn từ `test_indist` (ghi caveat phân phối, xem DATASET.md).

## 3. Weights theo bin toolchain (chống confound)
- Mỗi mẫu gắn `toolchain_bin` (bộ phân loại đã kiểm: Rich/linker + section + CRT; **không** nhãn "Rust?"; GNU chỉ khi `.eh_frame`/mingw).
- **Loss weight = nghịch tần suất bin** (reweight) để model không tách lớp bằng bin (vì benign v1 lệch MSVC14, malware trải MSVC≤10+14). Tùy chọn: thêm **domain-adversarial** trên bin (để sau).
- Lý do: Task 1 cho thấy trong cùng bin MSVC14, malware và benign fire T1497 ngang nhau → nếu không reweight, model dễ học "bin" thay vì "hành vi".

## 4. Báo cáo — THEO BIN và THEO NGUỒN, kèm holdout
- Mọi metric (AUC, FPR+Wilson/cluster-bootstrap, recall) báo **phân tầng theo toolchain-bin** và **theo nguồn**.
- **Bắt buộc** báo trên: `test_indist`, `holdout_source_chocolatey` (FPR chéo nguồn), `holdout_family_bumblebee` (recall cross-family). CI dùng **cluster-bootstrap** (Task 3: CI cụm rộng hơn Wilson, trung thực hơn khi có near-dup).

## 5. Đầu vào head — KHÔNG gồm global_features
- `num_global_features = 0`: head = `pooled_program` (TransformerConv call graph) **mà thôi**, bỏ `global_features` (entropy toàn cục, has_any_external_call).
- Lý do: entropy/size là **confound nguồn** (Phần A: metadata-only AUC 1.0 in-dist nhưng FPR 53% chéo nguồn; Task 2 bỏ entropy+packed giảm FPR choco 18→9%). Giữ entropy **chỉ như một ablation** riêng, không phải input mặc định. (Eq.16 nêu 2 global feature nhưng code đặt 4 → chưa định nghĩa; quyết định: bỏ hẳn.)

## 6. So sánh với baseline probe (để chứng minh BFBG hơn confound-exploiter)
Báo BFBG cạnh hai baseline đã đo, trên CÙNG holdout:
| model | AUC test_indist | FPR holdout_choco | FPR/recall holdout khác |
|---|---|---|---|
| **metadata-only** (RF, linker/year/entropy…) | 1.000 | **53%** | — (confound thuần) |
| **graph-feature** (RF, num_func/api/imports/size/entropy/packed/nodes) | 0.976 | 18% (bỏ entropy+packed: 9%) | FPR NirSoft 35% |
| **BFBG (đề xuất)** | *đo khi train* | *mục tiêu < graph-probe* | *đo trên bumblebee/choco/nirsoft* |
- **Claim chỉ đứng vững nếu BFBG đạt FPR chéo-nguồn THẤP HƠN graph-probe** (tức học cấu trúc BFBG, không chỉ lặp lại confound toolchain/entropy mà baseline đã khai thác). Nếu không hơn → phải hedge claim (xem 3 phương án trong DATASET.md).
