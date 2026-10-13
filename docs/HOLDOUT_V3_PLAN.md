# Kế hoạch holdout v3 (benign mới) — CHƯA TẢI

Mục tiêu: tăng n benign cho holdout kiểm định cuối từ 20 (nirsoft) lên **~100–150** để CI đủ hẹp
(xem FINAL_CONFIG_PROPOSAL.md §E: AUC CI ±0.05 cần ~80–120; FPR Wilson ±0.05 cần ~75–150).
Holdout v3 **chỉ benign**, **tách tuyệt đối khỏi train/dev v2**, chạm MỘT lần cùng cấu hình đã commit.

## 1. Số mẫu & nguồn (mục tiêu ~120 benign mới, dự phòng rơi ~15%)
| nguồn | mục tiêu | ghi chú |
|---|---|---|
| NirSoft (tool chưa lấy) | ~40 | nhiều util nhỏ MSVC; tránh trùng 20 đã có + pilot |
| Scoop (bucket main/extras chưa lấy) | ~45 | đa toolchain (Go/Rust/MinGW) để KHỚP phân phối malware hơn |
| PortableApps / GitHub release | ~25 | app lớn hơn, đa dạng size |
| MSVC14-only (ưu tiên) | ≥30 trong tổng | để sau này đo within-MSVC14 với n_neg lớn (khắc phục n=21) |
| **Tổng tải** | **~140** | sau dedup/rơi còn ~110–120 |

Ưu tiên benign **khớp-confound** (cùng toolchain/size/signed với malware) nếu định dùng để phản biện confound.

## 2. Quy tắc dedup (tất định)
1. **sha256 chính xác**: loại nếu trùng bất kỳ sha trong v1/v2 (train_pool/test_indist/holdout_*/dev).
2. **Loại installer**: chỉ giữ payload .exe/.dll bên trong (quy tắc benign đã khóa), KHÔNG giữ installer.
3. **api-ms-win-*/ext-ms-* forwarder DLL**: loại theo tên.
4. **num_functions==0**: loại ở loader (§14), nhưng cũng đánh dấu trong manifest.
5. **Near-dup ppdeep ≥90**: gom cụm; **không để 2 mẫu cùng cụm**; nếu cụm trùng cụm đã có trong v1/v2 → loại cả cụm (tránh rò rỉ).
6. **orig_name** (app/basename) lưu vào manifest để truy vết.
7. Sắp xếp theo sha256 tăng dần trước khi ghi → manifest tất định.

## 3. Split
- Tất cả benign v3 → **holdout_v3_benign** (một nhãn 0). KHÔNG vào train/dev. Giữ nirsoft 20 cũ riêng (holdout_source_nirsoft) hoặc gộp — ghi rõ, không trộn vào train.

## 4. Manifest v3
- Script: `experiments/dataset/pilots/make_manifest_v3.py` (tất định, seed cố định). Đầu vào: thư mục PE đã thu + (tùy) feature JSON đã build. Đầu ra: `docs/dataset_v3_manifest.jsonl` + in SHA256 của manifest để đóng băng.
- CHƯA chạy (chưa tải). Khi có dữ liệu: build feature → chạy script → ghi FREEZE.
