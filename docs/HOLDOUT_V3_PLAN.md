# Kế hoạch holdout v3 (benign mới) — CHƯA TẢI

Mục tiêu: tăng n benign cho holdout kiểm định cuối từ 20 (nirsoft) lên **~100–150** để CI đủ hẹp
(xem FINAL_CONFIG_PROPOSAL.md §E: AUC CI ±0.05 cần ~80–120; FPR Wilson ±0.05 cần ~75–150).
Holdout v3 **chỉ benign**, **tách tuyệt đối khỏi train/dev v2**, chạm MỘT lần cùng cấu hình đã commit.

## 1. Số mẫu & nguồn (mục tiêu ~120 benign mới, dự phòng rơi ~15%)
**Mục tiêu TẢI 160–180** để sau dedup + mẫu rơi (~30%) còn **≥120** benign dùng được.
| nguồn | mục tiêu tải | ghi chú |
|---|---|---|
| NirSoft (tool chưa lấy) | ~50 | util nhỏ (prior: NirSoft ≈ MSVC≤10); tránh trùng 20 đã có + pilot |
| Scoop (bucket main/extras chưa lấy) | ~75 | đa toolchain (Go/Rust/MinGW/MSVC14) để KHỚP phân phối malware hơn |
| PortableApps / GitHub release | ~55 | app lớn hơn, đa dạng size |
| MSVC14-only (ưu tiên) | ≥40 trong tổng | để sau đo within-MSVC14 với n_neg lớn (khắc phục n=21) |
| **Tổng tải** | **~180** | sau dedup/rơi ~30% còn ~**120–125** |

- **CAP VENDOR:** **NirSoft ≤ 35% holdout cuối** (tránh một vendor thống trị → confound vendor). Nếu sau dedup NirSoft > 35%, **loại bớt NirSoft** (theo thứ tự sha) để về ≤35%; cap áp ở `make_manifest_v3.py`.
- Ưu tiên benign **khớp-confound** (cùng toolchain/size/signed với malware) nếu dùng để phản biện confound.
- ⚠️ **Prior bin (nirsoft→MSVC≤10, scoop/pa mixed) chỉ là ƯỚC LƯỢNG từ pilot nhỏ** (46 nirsoft, 203 scoop trong v2); bin thật chỉ biết sau khi tải + pefile. Số dry-run là chiếu, không phải cam kết.

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

## 5. QUY TẮC KHÓA (bắt buộc, trước khi chạy BẤT KỲ mô hình nào trên v3)
1. **Commit TRƯỚC khi chạm:** `docs/dataset_v3_manifest.jsonl` + **SHA256 manifest** + **danh sách loại mẫu** (shas bị dedup/drop + lý do) phải được **commit trước** khi bất kỳ mô hình nào chấm trên v3. Ghi hash vào FREEZE.
2. **Không chỉnh sau khi thấy điểm:** sau khi đã chấm, **KHÔNG** sửa manifest/danh-sách-loại/cap theo kết quả. Mọi thay đổi ⇒ phải coi là holdout MỚI (v4), commit lại, và kết quả v3 cũ vẫn giữ nguyên trong log.
3. **v3 KHÔNG vào train / KHÔNG chọn ngưỡng:** mẫu v3 chỉ dùng để ĐÁNH GIÁ cuối; không train, không CV, không chọn ngưỡng/siêu-tham-số (ngưỡng lấy từ train/dev như FINAL_CONFIG_PROPOSAL §C).
4. **Chạm một lần:** theo FINAL_CONFIG_PROPOSAL — một cấu hình đã commit, báo cả tốt lẫn xấu, không chạm lại.
