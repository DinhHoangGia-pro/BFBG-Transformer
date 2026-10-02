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

## 3. T1055 không phân biệt được tự-tiêm với tiêm-tiến-trình-khác — phát hiện qua fixture self-injection benign

**Chuyện đã xảy ra** (ghi nhận 2026-10-02). Phép thử false-positive trên w32.exe/w64.exe ở mục trước vô giá trị vì cả hai không import API nào của T1055. Để có một mẫu benign đúng hình dạng cross-function của `3bf0f489…`, dựng fixture `self_patch_updater.exe` (PE32 tối giản, label benign): `OpenProcess` được gọi với tham số rỗng/vô nghĩa ở hàm cha `_start`, `_start` gọi hàm con `sub_401010`, và hàm con chứa đủ `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` liền nhau. Các API được gọi với tham số 0/không hợp lệ — không cấp phát, không ghi, không tạo thread, không có payload; file chỉ để tạo đúng hình dạng import + call-graph cho phân tích tĩnh.

Kết quả qua `build_graphs.py`:
- `cross_function_seed_edges` fire **đủ 4 bước** OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread (3 cạnh, confidence `cross_function_1hop`) trên chương trình benign này.
- Seed edge nội hàm vẫn 0 ở cả hai hàm, giống `3bf0`.

**Nguyên nhân gốc.** Luật T1055 chỉ khớp theo **tên API + thứ tự + khoảng cách**. Nó **không đọc tham số** của `OpenProcess` để biết tiến trình đích là chính tiến trình hiện tại (self-injection, phổ biến ở updater/launcher hợp pháp) hay một tiến trình khác (dấu hiệu tiêm mã độc hại). Đây là hạn chế **chung** của cả thiết kế gốc (khớp trong 1 hàm, `generate_seed_edges`) lẫn phần mở rộng Phương án B (khớp xuyên hàm 1-hop, `generate_cross_function_seed_edges`) — **không phải lỗi riêng của phần mở rộng**. Tự-tiêm hợp pháp và tiêm-tiến-trình-khác độc hại dùng đúng cùng một chuỗi API; chỉ tham số (và luồng dữ liệu của handle) mới phân biệt được, mà luật hiện không nhìn tới.

**Phát hiện phụ: window=8 cắt chuỗi theo khoảng cách lệnh, không theo ranh giới hàm.** Fixture này khớp đủ 4 bước vì ba API con nằm liền nhau (vị trí 0,1,2). `3bf0` bị cắt mất `CreateRemoteThread` **dù dùng đúng cùng window=8**, vì trong hàm con của nó ba API nằm rải (CreateRemoteThread ở vị trí 19, cách bước trước > 8). Vậy "window quá hẹp" là giới hạn do khoảng cách giữa các lời gọi, xuất hiện cả trong một hàm lẫn qua ranh giới hàm — không phải đặc tính riêng của ranh giới hàm hay của Trickbot.

**Trạng thái.** `generate_cross_function_seed_edges()` và field `cross_function_seed_edges` được GIỮ NGUYÊN để nghiên cứu sau, chưa quyết định xoá hay giữ. T1055 được gắn cờ `training_caveat` trong `src/semantic/seed_rules_attck.py`; `check_seed_rule_fire_rate.py` in cảnh báo cố định mỗi khi báo số liệu T1055.

## 4. Near-duplicate phải nằm cùng phía train/test (ràng buộc split cho dataset loader)

**Chuyện đã xảy ra** (ghi nhận 2026-10-02). `experiments/qa/check_sample_similarity.py` (ppdeep) phát hiện hai mẫu Trickbot `4becc0d518a97cc3…` và `ef6603a7ef46177e…` là near-duplicate (`ppdeep.compare = 96`) dù số hàm rất khác nhau (563 vs 2896). Chế độ proxy cũ bỏ sót vì gom theo (số hàm, số API-call), vốn mù với mức giống byte.

**Yêu cầu thiết kế cho bước dataset/train sắp tới** (CHƯA code — `src/training/` chưa tồn tại). Khi viết dataset loader / hàm chia train-test:
- Các mẫu trong cùng một cụm near-duplicate phải luôn nằm **CÙNG PHÍA** train hoặc test, không được tách rời. Nếu không, một biến thể lọt vào test gần như trùng với một biến thể trong train → rò rỉ, làm điểm test cao giả.
- Tức là chia theo **nhóm (group-aware split)**, với nhóm = cụm near-duplicate, không chia theo từng mẫu độc lập. Cùng họ với ý tưởng `group_key` đã có trong `configs/dataset.yaml` (vd campaign) — cụm near-duplicate là một `group_key` nữa cần tôn trọng.
- Danh sách cụm cụ thể nằm ở `data/raw/near_duplicate_clusters.jsonl` (dữ liệu cục bộ, `data/` bị gitignore; **tái sinh được** bằng `check_sample_similarity.py` trên tập mẫu cuối). Dataset loader nên đọc file này nếu có, và không hard-code sha256 vào mã nguồn.

Chưa loại bỏ mẫu nào; đây chỉ là ràng buộc cho bước sau.

## 5. Giới hạn kích thước mẫu benign — DLL ffmpeg lớn (>50MB) không lift được trong timeout hợp lý

**Chuyện đã xảy ra** (ghi nhận 2026-10-02). Khi mở rộng benign corpus từ bản dựng FFmpeg release-full-shared, hai DLL lớn (~93MB và ~102MB, như avcodec) **không lift xong trong `--timeout 900s`**; cả lô bị khung quản lý tiến trình nền kết thúc sau 30 phút. Đây **không phải lỗi code**: `angr CFGFast` có chi phí tăng siêu tuyến tính theo kích thước code, và hai DLL này quá lớn so với mọi thứ pipeline từng xử lý.

**Ngưỡng theo bằng chứng.** Trên toàn bộ 64 mẫu đã lift thành công (cả malicious lẫn benign), mẫu lớn nhất là 7,78 MB (`069739cb…`, 11.217 hàm, ~252s); lớn nhì 7,56 MB. Tất cả đều ≤ 7,78 MB. Đặt ngưỡng kích thước tối đa cho mẫu = **12 MB** (≈ 1,5× mẫu lift lớn nhất đã chứng minh), phản ánh đúng "cỡ mà pipeline xử lý được trong thời gian hợp lý" chứ không phải một con số MB cảm tính. (Phương án 2× ≈ 15,6 MB đã cân nhắc nhưng loại: ~2× mức đã chứng minh, rủi ro chạm trần 900s.) Hai DLL ffmpeg bị loại khỏi corpus theo ngưỡng này.

**Lý do khoa học, không chỉ vì tốc độ.** Các mẫu này là **outlier độ phức tạp cực đoan** so với toàn bộ phân phối hiện có (kể cả phía malicious). Giữ chúng lại có nguy cơ lặp lại kiểu confound đã gặp với mẫu benign `93488fa7…` — một mẫu duy nhất (9.880 hàm, 41,1% hàm bị gắn cờ) chi phối toàn bộ thống kê boundary-anomaly của cả nhóm benign (xem mục bảng QA n=55).

**Ràng buộc áp dụng xuyên suốt dự án.** MỌI đợt thu thập sau này — benign lẫn Trickbot mở rộng ở Giai đoạn B — đều phải **lọc theo cùng ngưỡng kích thước này TRƯỚC khi đưa vào lift**, không chỉ riêng đợt này. Ngưỡng sẽ được ghi vào `configs/dataset.yaml` và áp dụng trong các script thu thập/dựng đồ thị để nhất quán.
