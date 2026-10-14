# FREEZE v3 — holdout benign (ĐÓNG BĂNG TRƯỚC MỌI PHÉP CHẤM) 2026-10-14

## Hash (tất định)
- **docs/dataset_v3_manifest.jsonl** = `d0aae90021ab737fb310e6b60cd0aa8c3d505fc0d01db691f7122674835bade2` — **166 benign** đã build.
- **docs/V3_DROP_LIST.jsonl** = `dffe24460a518751aa7d1c92ecc468cab1f66488c040f33d98077a4b9b27203e` — **59 mẫu loại/rơi**.
- Sinh tất định: seed 20261008, sắp theo sha256. `make_manifest_v3.py`/`gen_manifest_v3.py`.

## Thành phần (bin × nguồn, nhãn đã sửa)
| bin | scoop | nirsoft | tổng |
|---|---|---|---|
| MSVC≤10 | 24 | 50 | 74 |
| MSVC 14 | 41 | 0 | **41** |
| GNU/MinGW | 9 | 0 | 9 |
| Go | 17 | 0 | 17 |
| Delphi | 4 | 0 | 4 |
| khác | 21 | 0 | 21 |
| **tổng** | **116** | **50** | **166** |
- **MSVC14 = 41** (sát mức 40; n nhỏ → **khoảng tin cậy sẽ RỘNG**, không coi là mốc vững).
- **MSVC≤10 không-NirSoft (scoop) = 24**.
- **NirSoft = 50 (30%) ≤ cap 35% → KHÔNG cắt mẫu nào** (cap=62).

## Minh bạch
- **KHÔNG có lựa chọn nào dựa trên kết quả mô hình.** Tập = TOÀN BỘ 166 mẫu đã build; phiên harvest dừng QUÁ mục tiêu 120 (không cắt về 120 theo điểm số). Cap vendor là quy tắc tất định ghi trước, không phụ thuộc điểm.
- v3 raw ở import_v3/, feature ở v3_features/ (ngoài data/); CHƯA vào train/dev. CHƯA chấm bất kỳ mô hình nào.

## Danh sách loại (V3_DROP_LIST.jsonl, 59)
- dedup_drop 21 (sha256/ppdeep≥90 vs v1/v2 + nội bộ v3) · app_fail 12 (manifest/url/dl lỗi) · build_fail 26 · nf0 0 · vendor_cap 0.
- **build_fail 26 theo bin:** khác 14, GNU/MinGW 7, MSVC14 2, MSVC≤10 2, Delphi 1. Nguyên nhân: **Timeout angr (>900s, file lớn/nhiều hàm)** + dotnet out-of-scope.

## HẠN CHẾ (threats to validity)
- **Thiên lệch mẫu rơi:** mẫu rơi (build_fail) nghiêng về chương trình **nhiều hàm/lớn** (timeout) và bin khác/GNU → **benign v3 còn lại ĐƠN GIẢN hơn** (ít hàm). Phải nêu rõ khi báo cáo.
- MSVC14 n=41 → CI rộng; NirSoft chiếm toàn bộ MSVC≤10 (50/74) → bin MSVC≤10 lệch vendor.

## Task 1 — phân loại 21 bin "khác" (header/section/import/packer) 2026-10-14
- **Nghi đóng gói: 2/21 = 10%** — `1482c7c1…` (UPX0/UPX1, maxent 7.94) và `4d2e724e…` (maxent 7.79).
- 19/21 còn lại KHÔNG packer: compiler đa dạng — Rust (`_RDATA`,`.fptable`,`malloc_h`), GCC/binutils COFF (`/4 /19 /31 /45`), CFG/clang (`.gxfg`,`.retplne`), NSIS stub (`.ndata`). maxent phần lớn 6.0–6.9, import 45–356 (bình thường).
- → benign v3 bin "khác" **chủ yếu không đóng gói** (10% nghi packer).

## Task 2 — NirSoft v3 không trùng v2-holdout/pilot
- 50 NirSoft v3 so với **20 v2 holdout_source_nirsoft** + **46 pilot (import_nirsoft/, siêu tập của ~23 pilot)**:
  **trùng sha256 = 0 ; trùng ppdeep≥90 = 0** → **hoàn toàn rời**. (v3 đã dedup vs v1/v2 lúc harvest; đây xác nhận thêm vs pilot ngoài data/.)

## Task 3 — metric trên v3 (ghi rõ)
- **AUC = dev positives (BumbleBee holdout 262) vs holdout negatives (v3 166)** + cluster-bootstrap CI. (positives ghi trước, KHÔNG từ train.)
- **FPR**: ngưỡng cố định chọn từ TRAIN; báo FPR trên v3 + Wilson CI, **TÁCH THEO BIN** (MSVC≤10/MSVC14/GNU/Go/Delphi/khác).
