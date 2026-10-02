# Bài học trong quá trình xây dựng BFBG-Transformer

Các bài học phát sinh khi làm pipeline PE-malware. Bài học kế thừa từ dự án EVM cũ nằm riêng trong [LESSONS_FROM_EVM_CODEBASE.md](LESSONS_FROM_EVM_CODEBASE.md).

## 1. Nguồn dữ liệu đơn lẻ là điểm lỗi duy nhất

**Chuyện đã xảy ra** (ghi nhận 2026-10-02). Đường tải mẫu tự động `scripts/fetch_trickbot_sample.py` chỉ dựa vào API MalwareBazaar, xác thực bằng Auth-Key của một tài khoản. Tài khoản đó bị blacklist mà không rõ lý do, và toàn bộ pipeline fetch bị chặn cho tới khi có nguồn thay thế hoặc tài khoản được gỡ blacklist. Không có đường nào khác để đưa mẫu vào `data/raw/malicious/`.

**Bài học.** Cần ít nhất một nguồn dự phòng **không phụ thuộc cùng một hệ thống xác thực**. Một tài khoản thứ hai trên cùng MalwareBazaar không tính là dự phòng, vì vẫn có thể bị chặn theo cùng cơ chế.

**Đã làm.** Thêm đường nạp thủ công `scripts/import_manual_samples.py`, chạy song song với đường API. Script nhận một thư mục file PE tải tay từ bất kỳ nguồn nào (ví dụ VX-Underground), lưu theo đúng quy ước `data/raw/malicious/<sha256>`, rồi gọi lại `scripts/build_graphs.py`. Phần sau pipeline (bfbg_builder, QA) không phụ thuộc mẫu đến từ nguồn nào. Nguồn của từng mẫu được ghi trong `data/raw/fetch_manifest.jsonl`.
