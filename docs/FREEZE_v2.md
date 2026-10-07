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
