# Bài học trong quá trình xây dựng BFBG-Transformer

Các bài học phát sinh khi làm pipeline PE-malware. Bài học kế thừa từ dự án EVM cũ nằm riêng trong [LESSONS_FROM_EVM_CODEBASE.md](LESSONS_FROM_EVM_CODEBASE.md).

## 1. Nguồn dữ liệu đơn lẻ là điểm lỗi duy nhất

**Chuyện đã xảy ra** (ghi nhận 2026-10-02). Đường tải mẫu tự động `scripts/fetch_trickbot_sample.py` chỉ dựa vào API MalwareBazaar, xác thực bằng Auth-Key của một tài khoản. Tài khoản đó bị blacklist mà không rõ lý do, và toàn bộ pipeline fetch bị chặn cho tới khi có nguồn thay thế hoặc tài khoản được gỡ blacklist. Không có đường nào khác để đưa mẫu vào `data/raw/malicious/`.

**Bài học.** Cần ít nhất một nguồn dự phòng **không phụ thuộc cùng một hệ thống xác thực**. Một tài khoản thứ hai trên cùng MalwareBazaar không tính là dự phòng, vì vẫn có thể bị chặn theo cùng cơ chế.

**Đã làm.** Thêm đường nạp thủ công `scripts/import_manual_samples.py`, chạy song song với đường API. Script nhận một thư mục file PE tải tay từ bất kỳ nguồn nào (ví dụ VX-Underground), lưu theo đúng quy ước `data/raw/malicious/<sha256>`, rồi gọi lại `scripts/build_graphs.py`. Phần sau pipeline (bfbg_builder, QA) không phụ thuộc mẫu đến từ nguồn nào. Nguồn của từng mẫu được ghi trong `data/raw/fetch_manifest.jsonl`.

## 2. T1055 bỏ sót pattern setup-ở-hàm-cha/payload-ở-hàm-con

**Ca cụ thể** (ghi nhận 2026-10-02, mẫu Trickbot `3bf0f489250eaaa99100af4fd9cce3a23acf2b633c25f4571fb8078d4cb7c64d`, nguồn VX-Underground). Mẫu này import đủ cả 4 API của T1055 và có lời gọi tĩnh tới cả 4, nhưng luật T1055 fire 0 lần. Vị trí các lời gọi, đọc từ JSON BFBG (`position` = thứ tự trong mọi lời gọi API của hàm; `window_size` = 8):

| Hàm | Tên | API của T1055 trong hàm (position) |
|---|---|---|
| `func_4198400` | `sub_401000` | VirtualAllocEx (1, 5, 15), WriteProcessMemory (3, 7, 9, 17), CreateRemoteThread (19) |
| `func_4200126` | `sub_4016be` | VirtualAllocEx (1, 5, 15), WriteProcessMemory (3, 7, 9, 17) |
| `func_4202163` | `_start` | OpenProcess (23) |
| `func_4212044` | `sub_40454c` | OpenProcess (1) |

- `sub_401000` có đủ 3/4 API (thiếu `OpenProcess`), và có một chuỗi đúng thứ tự mà các bước kế nhau đều nằm trong window: VirtualAllocEx (15) → WriteProcessMemory (17) → CreateRemoteThread (19).
- `OpenProcess` nằm ở `_start`. Call graph có cạnh gọi trực tiếp `_start` → `sub_401000` (và `_start` → `sub_4016be`).
- **Giả thuyết, CHƯA kiểm chứng:** handle trả về từ `OpenProcess` trong `_start` được truyền xuống `sub_401000` qua tham số. Dữ liệu hiện có chỉ cho thấy có cạnh gọi trực tiếp. Chưa có phân tích luồng dữ liệu, và chưa xác định lệnh gọi `sub_401000` trong `_start` nằm trước hay sau `OpenProcess` (JSON không còn `op_str`).

**Liên hệ với thiết kế.** Đây là minh chứng cho đúng giới hạn "phạm vi khớp chỉ trong 1 hàm" mà docstring của `src/semantic/seed_rules_attck.py` đã nêu là giới hạn có chủ đích (Stage 2 Macro Inter-function Graph Transformer lo lan truyền tín hiệu xuyên hàm). Docstring đó cũng đã dự báo đúng tình huống "chuỗi process-injection bị tách qua 1 hàm wrapper" và chỉ hướng mở rộng là ở `bfbg_builder`, nơi có call graph.

**Cơ chế thứ hai, đọc từ code (không phải giả thuyết):** `_match_ordered_chain` duyệt `rule.apis` từ phần tử đầu (`OpenProcess`). Nếu hàm không có `OpenProcess`, vòng lặp dừng ngay ở bước đầu, nên chuỗi VirtualAllocEx → WriteProcessMemory → CreateRemoteThread trong `sub_401000` không sinh được cả `partial_chain`. `partial_chain` chỉ đếm **tiền tố** của chuỗi.

**Phương án — QUYẾT ĐỊNH THIẾT KẾ ĐANG MỞ, chưa chọn, chờ thêm dữ liệu:**

- **A. Giữ nguyên.** Luật seed chỉ khớp trong một hàm; dựa vào Stage 2 (Macro Graph Transformer) học quan hệ xuyên hàm qua cạnh call graph. Hệ quả: hàm như `sub_401000` không mang seed edge hay node indicator nào của T1055 để làm nhãn yếu.
- **B. Mở rộng khớp liên hàm 1-hop qua call graph** trong `bfbg_builder`: khi khớp T1055 cho một hàm, cho phép các bước đầu của chuỗi đến từ hàm gọi trực tiếp nó (caller 1-hop). Cần quyết định thêm: cách tính khoảng cách window giữa hai hàm khác nhau, và cách biểu diễn seed edge nối hai node ở hai đồ thị nội hàm khác nhau.

Tần suất của pattern này trên toàn bộ dữ liệu cần được đo trước khi chọn phương án.

