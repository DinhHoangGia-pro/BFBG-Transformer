# ĐÓNG BĂNG thiết kế & split v2 (2026-10, bản cập nhật sau .NET-exclusion + cap)

Mốc đóng băng TRƯỚC khi chạy BFBG. Mọi thay đổi ĐÁNH GIÁ sau mốc này **phải gắn nhãn "post-hoc"**.

## Hash (tại thời điểm đóng băng)
| artifact | SHA256 |
|---|---|
| docs/dataset_v1_manifest.jsonl (v1 BẤT BIẾN) | `2c2aa06467b69187b42ec8cf394aa9668d449e2f59302813d3d250b67d1e27c6` |
| docs/dataset_v2_split_plan.jsonl (273 benign native, sau .NET+cap) | `7f33cfc2ef10e839529a8fe71210b6ff7950e5fa48fbedabac38adc6641c3667` |
| docs/TRAINING_DESIGN.md | `ce0a5d8eecb6ed272e3acde973c4bfa570d54ddb6d5d8f2fd9bba3e4a10fc582` |
| docs/DATASET.md | `4e8c3a85c6cf672a5f2d8c2a2506159c29d4f4f852577b2e10489b7622c0cb27` |
| data/insn_vocab_v2.json (vocab train) | `af69e190e0c9eed0e39b8b30fc88238b6389fe5033222d4aa00c45c83f9d1bc8` |

## Split v2 — số THẬT (dry-run)
train-eligible non-ISO **195**, test_indist **+41**, holdout_source_nirsoft **20**, holdout_lowfreq_toolchain **17**, dual-use **0**. .NET loại out-of-scope **31**.

## Quy tắc đã khóa (Task 4)
- **Mẫu rơi sau build:** nếu một mẫu trong plan **không build được** (lift fail/timeout/.NET sót) → **loại khỏi split tương ứng**, KHÔNG thay bằng mẫu khác; manifest v2 THẬT ghi đúng số build được (≤ plan). Báo delta plan-vs-built.
- **choco = TẬP PHÁT TRIỂN (development):** được nhìn khi tinh chỉnh/chọn ngưỡng. **holdout_source_nirsoft = TẬP XÁC NHẬN DUY NHẤT (held-out cuối)** — chỉ chạm MỘT lần ở báo cáo cuối; holdout_lowfreq phụ trợ.
- **Claim:** CHÍNH = **non-inferiority** (graph/BFBG không thua baseline trong-bin); **superiority = KHÁM PHÁ (exploratory)** ở fold khó + bỏ-đặc-trưng-đường-tắt.
- **Mọi số v2 báo kèm cột "chỉ-thành-viên-v1"** (tính lại chỉ trên mẫu thuộc v1) cạnh cột "v1+đợt1", để tách đóng góp dữ liệu mới khỏi thay đổi khác.
- **v1 bất biến; ISO cap ≤35% áp Ở LOADER** (không di chuyển mẫu).

## Trạng thái
CHƯA build đợt 1, CHƯA train BFBG. Build sẽ tạo manifest v2 THẬT khớp plan `7f33cfc2ef10e839529a8fe71210b6ff7950e5fa48fbedabac38adc6641c3667` (trừ mẫu rơi).

## v2 manifest THẬT (sau build đợt 1, 2026-10-08)
- **docs/dataset_v2_manifest.jsonl** = `4f438bcf0eca514dc220df7a520b321ee91ac587e61498e23e1c7c43cc2ef501` — 1886 dòng (v1 1637 bất biến + 249 benign đợt-1 built).
- Build đợt 1: **249/273 OK**, rơi 24 (23 Timeout + 1 NotImplementedError) → loại khỏi split (luật mẫu-rơi).
- Delta plan→built theo split: train_pool 195→175, test_indist 41→38, holdout_source_nirsoft 20→20, holdout_lowfreq_toolchain 17→16.
- benign v2 = 504 (v1 255 + 249). **train benign 351, ISO 141 = 40% > 35% → cap ISO Ở LOADER vẫn binding** (subsample/inverse-weight lúc train).
- Đây là manifest huấn luyện v2 chốt; **mọi thay đổi đánh giá sau đây = post-hoc**. CHƯA train BFBG.

## Cập nhật 2026-10-08 (app provenance + ISO cap + xác nhận)
- **v2 manifest (thêm orig_name cho 249 benign):** SHA256 `e2e2c67adcf236cd87fe1cdd752e5e776c5069cd69fec11b34a26ceab25350c9` (thay `4f438bcf…`). TRAINING_DESIGN.md SHA256 `2eb3467ce7ab4a7cddd885ab486dd38d4749d090b36458abd3e1481ff0c7e4ca`.
- **24 mẫu rơi:** toàn scoop (NirSoft 0 rơi); bin MSVC14 13/khác 4/GNU 4/Go 2/MSVC≤10 1; 22 Timeout + 2 NotImplementedError.
- **Cap GNU/Go/Rust:** 34/351 train benign = 9.7% ≤10% (còn đúng sau rơi).
- **holdout_nirsoft:** 20 mẫu, phân loại theo NGUỒN; **1 mẫu trùng pilot NirSoft** (pilot chỉ exploratory → không rò rỉ train; GIỮ NGUYÊN holdout theo lệnh, ghi nhận caveat).
- **ISO cap @loader:** giữ 113/141 ISO (seed 20261008+epoch), drop 28 — xem TRAINING_DESIGN §13.
- **app provenance:** orig_name (app/base) đã lưu cho benign mới; mẫu v1 không có (giữ nguyên v1).

## Tag freeze-v2.1 (2026-10-08) — mốc thời gian & minh bạch pipeline-check
- Tag `freeze-v2` cũ trỏ 0a3de27 (FREEZE còn hash `4f438bcf`, CHƯA có quy tắc subsample ISO). Commit đúng = 65b57f6 (hash `e2e2c67…` + §13). Tạo tag chú thích **freeze-v2.1** trên commit chứa ghi chú này.
- **Fold BumbleBee (pipeline-check)**: lần OOM 06:44; lần chạy hợp lệ **bắt đầu 07:11, kết thúc 09:56 (+07)**, 20 epoch.
- **Tag tạo ~12:40 (+07) ngày 2026-10-08.**
- **Minh bạch:** kết quả pipeline-check (AUC/recall/FPR/loss curve) ĐÃ được xem TRƯỚC khi tạo tag này. Đây là pipeline-check, KHÔNG phải kết quả, và KHÔNG dùng để chọn/điều chỉnh thiết kế đã khóa (design khóa ở freeze-v2/0a3de27 trước khi fold chạy).

## Cập nhật 2026-10-08 (§14 loại num_functions=0, §15 quy tắc epoch)
- TRAINING_DESIGN.md SHA256 `b9ff151793f3802b8ae38d007134ae91f0b517545726cad425ba4391371b3bbe` (thêm §14 quy tắc loại num_functions=0 áp chung hai phía; §15 epoch cố định=20, không dùng choco/validation chọn epoch).
- Kiểm kê num_functions=0: v1=2 (label0: choco1,iso1), v2=4 (label0: choco1,scoop2,iso1); 0 malicious.

## Cập nhật 2026-10-09 (§16 min-5-seed)
- TRAINING_DESIGN.md SHA256 `aa155abea4704cd86f0ae9fd3af504230c3b1746cc981a4cefe571b6992121dc` (thêm §16: tối thiểu 5 seed cho mọi so sánh BFBG; báo trung bình±std + hiệu ghép đôi theo seed).

## Cập nhật 2026-10-09 (§17 early-stopping, thay §15 cho run mới)
- TRAINING_DESIGN.md SHA256 `c5a948dadef4aa1f534f85c41bfdaa5646cc50343287e45edf95ee1d04b479dc` (thêm §17; §15 giữ cho kết quả cũ). Pre-reg cosine 6fe7331 bị thay thế bởi §17.

## Cập nhật 2026-10-09 (§18 danh sách seed + gate seed 101)
- TRAINING_DESIGN.md SHA256 `41d762e72a75796398d3430df450d8fe7eaa4d725e4bd7a81076b161c2928e2e` (thêm §18).

## Sửa 2026-10-09 (§18 làm rõ mâu thuẫn seed list)
- TRAINING_DESIGN.md SHA256 `f57706598369556324cd427eea35c85f9d90ba0e45d045c8b116676261e09ee9` (sửa §18: danh sách 4 seed duy nhất {101,202,303,404}, nêu rõ chưa chốt seed thứ 5).

## Sửa 2026-10-09 (§18 gate vùng 0.85–0.90 = hỏi; sửa báo cáo seed 101)
- TRAINING_DESIGN.md SHA256 `ccd21eae46572e5c3a6d7077c894d8556f90584dfcf638c91bfc79a07fb4b1c9`. PIPELINE_CHECK_LOG: bỏ so cắt-hàm, nêu AUC nhạy cách chọn epoch (0.891 vs 0.926), KHÔNG quy §17 "khử 0.68".
