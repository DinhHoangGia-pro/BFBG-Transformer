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

## 6. Size cap (12MB) cần nhưng không đủ — số hàm, không phải kích thước file, mới là yếu tố chi phối thời gian lift

**Bằng chứng** (ghi nhận 2026-10-02). `c52c9ed2…` (notepad++, 8,15MB — **DƯỚI** ngưỡng 12MB) có **14.512 hàm**, lift mất **584,6s** — gấp ~2,3× khung ~250s quan sát ở kỷ lục cũ (`069739cb…`, 11.217 hàm, 252s). Kích thước file nhỏ hơn hẳn nhưng **số hàm** cao hơn mới là biến chi phối thời gian.

**Vì sao không thể thay size cap bằng ngưỡng số-hàm.** Size cap là bộ lọc **TIỀN-xử-lý**: biết trước khi đọc/lift file (chỉ cần `os.path.getsize`), rất rẻ. Trong khi số hàm chỉ biết được **SAU khi angr đã dựng xong CFG** — tức chính phần chi phí mà ta muốn tránh. Vì vậy ngưỡng số-hàm không thay được vai trò của size cap; hai ngưỡng khác mục đích, không loại trừ nhau.

**Chốt chặn thời gian thực sự vẫn là `--timeout` mỗi mẫu** (hiện 900s) — đây là lưới an toàn cuối cùng, không phải size cap. Trong lô benign này không mẫu nào chạm 900s (lâu nhất 584,6s), nhưng khi quy mô lớn hơn thì timeout mới là thứ bảo đảm batch luôn kết thúc.

**Hướng mở (chưa làm, không cần làm ngay).** Nếu muốn giảm chi phí phí phạm trên mẫu nhiều-hàm TRƯỚC khi lift, cần một proxy rẻ tương quan với số hàm — ví dụ số section, kích thước riêng của section `.text` (thay vì `file_size` tổng), hoặc phân bố entropy. KHÔNG kết luận proxy nào thực sự hoạt động; chỉ ghi như hướng cân nhắc cho Giai đoạn B, khi quy mô lớn hơn khiến vài % mẫu "unlucky" nhiều-hàm cộng dồn thành chi phí đáng kể.

## 7. Boundary-anomaly rate có thể là tín hiệu "outlier hiện diện", không phải tín hiệu benign/malicious

**Bằng chứng** (ghi nhận 2026-10-02). Khi benign tăng 26 → 44 mẫu:
- Tỉ lệ hàm bị gắn cờ của benign giảm 7,17% → 5,07% (pha loãng ảnh hưởng của outlier cũ `93488fa7…`, vốn một mình đóng 4.063/5.941 cờ).
- Nhưng BỎ outlier đó ra thì benign ≈ 1,75% ở cả n=26 lẫn n=44, gần bằng malicious (1,98%) — tức khi không có outlier, boundary rate gần như KHÔNG phân biệt hai lớp.
- Và một outlier benign MỚI xuất hiện ngay trong đợt mở rộng: `3e74aa37…` (9.778 hàm, 4,6%, chủ yếu OVERLAP) — cao hơn hẳn phần còn lại, dù độ lớn chưa bằng `93488fa7` (41,1%).

**Giả thuyết.** Dường như "luôn có 1–2 mẫu cực đoan trong benign" bất kể cỡ mẫu, chứ boundary-anomaly rate không hội tụ về một tỉ lệ ổn định đặc trưng cho lớp. Nếu đúng, tỉ lệ tổng của nhóm chủ yếu phản ánh **có hay không một outlier trong batch**, không phản ánh bản chất benign/malicious.

**Khuyến nghị.** KHÔNG dùng boundary-anomaly rate làm đặc trưng discriminative cho tới khi n đủ lớn để kiểm tra giả thuyết này nghiêm túc — ví dụ khi n→200, xem outlier có tiếp tục xuất hiện theo một tỉ lệ không đổi (ủng hộ "luôn có outlier") hay thực sự hội tụ về một giá trị ổn định. Trước khi có câu trả lời, boundary_flags nên dùng ở cấp từng-hàm (đã có trong JSON) cho mục đích chẩn đoán ranh giới hàm, không gộp thành tỉ lệ cấp-mẫu làm feature.

## 8. Deadlock khi thu kết quả build song song — timeout mỗi-mẫu không cứu được

**Chuyện đã xảy ra** (ghi nhận 2026-10-03, lần build Lô 1 Giai đoạn B, 471 mẫu, workers=4). Build chạy xong **toàn bộ phần native** (454 JSON đã ghi đúng) rồi **treo ~2,5 giờ** ở cuối: tiến trình chính + 2 worker con sống mãi ở **<1% CPU** (đang blocked, không tính toán). `--timeout 900s` mỗi-mẫu **không bắn** vì tiến trình cha kẹt ở bước thu kết quả, không phải kẹt trong CFGFast. Dữ liệu không hỏng, không mất — chỉ việc đóng tiến trình sạch là thất bại.

**Nguyên nhân gốc.** Lớp điều phối cũ dùng `multiprocessing.Queue` giữa các luồng giám sát (ThreadPool) và tiến trình con để trả `(status, info)`. Queue có một feeder-thread + pipe nội bộ; dưới fork + nhiều Queue đồng thời, việc này deadlock ở thời điểm "hết việc" (đặc biệt khi mẫu bị skip sớm / vừa xong). Timeout dựa trên `result_q.get(timeout=1.0)` cũng vô hiệu vì get() không nhả.

**Cách sửa** (chỉ lớp thu kết quả + kết thúc tiến trình; KHÔNG đụng `is_dotnet_assembly`, ghi seed/node/boundary, phân loại OK/SKIP/FAIL, format JSON):
- Tiến trình con ghi `(status, info)` ra **file tạm pickle**, bỏ hẳn `multiprocessing.Queue` → loại cả lớp deadlock feeder/pipe.
- `run_one` dùng `proc.join(timeout)` rồi `proc.kill()` cho timeout cứng, không phụ thuộc đọc Queue; đọc kết quả từ file tạm sau join; thiếu file → `ProcessCrash`.

**Kiểm chứng và giới hạn.** Ba nhánh đã đổi đều thoát sạch, không sót tiến trình, số liệu không đổi: all-.NET (17/17 out-of-scope, 2,1s), ok (3/3 lift), Timeout (`--timeout 1` → 3/3 hard-kill, 3,4s). KHÔNG tái tạo được cái treo gốc một cách tất định (phụ thuộc timing/race ở lần 471 mẫu; lô 17-.NET vốn chạy xong cả ở code cũ), nên khẳng định đóng lỗi dựa trên review tương tác queue/pool + ba test nhánh, không dựa trên việc dựng lại đúng cái treo.

## 9. cle vấp `IndexError` trên COFF symbol table bị cố tình làm hỏng (giới hạn công cụ đã biết)

**Chuyện đã xảy ra** (ghi nhận 2026-10-03, build Lô 3 IcedID, 271 mẫu). 9 mẫu thất bại với `IndexError: list index out of range`, **không phải Timeout**. Truy vết: `cle/backends/pe/pe.py:1258 _load_symbols_from_coff_header` → `rva = self._pe.sections[section - 1].VirtualAddress + value`; frame cuối trong repo chỉ là `src/disassembly/pe_lifter.py:103 load_project → angr.Project(...)`. Tức lỗi phát sinh **bên trong cle** ngay khi nạp project, không phải code repo.

**Phân loại bản chất** (đọc header bằng `pefile`, không sửa gì). Cả 9 mẫu giống hệt: 19 section khai báo = 19 section parse được (**section table lành**); nhưng `PointerToSymbolTable != 0` (có COFF symbol table — bất thường, linker hiện đại strip bảng này), `NumberOfSymbols=1743` nằm trong vùng file hợp lệ, và **66 symbol có `SectionNumber` rác** (hợp lệ phải ∈ [1, 19] hoặc 0/−1/−2; đây lên tới **30821**). cle làm `sections[section-1]` không kiểm tra biên → IndexError. Đây là **PE cố tình làm hỏng COFF symbol table để chống phân tích**, không phải PE compile bất thường vô hại: section table nguyên vẹn, chỉ riêng symbol table bị nhồi SectionNumber rác đúng chỗ công cụ naïve sẽ vấp.

**Hệ quả dataset.** Cả 9 "thất bại" thực chất là **1 biến thể IcedID × 9 bản near-duplicate** (cùng 591 KB / 19 section / 1743 symbol / 66 symbol rác / maxSectNum 30821, lệch vài byte). Dù lift được, chúng cũng gộp về một cụm near-dup → mất 9 mẫu này ≈ mất 1 biến thể độc lập, gần như không giảm đa dạng IcedID.

**Quyết định.** Giữ nguyên là failure (đã ghi đầy đủ traceback vào `lift_failures.jsonl`), KHÔNG workaround. Lý do: (1) lỗi nằm trong cle, vá ở repo đồng nghĩa patch/monkeypatch loader của thư viện — rủi ro, ngoài phạm vi; (2) mất mát thực tế chỉ 1 biến thể. Pipeline đã hành xử đúng: bắt lỗi, ghi lại, không treo, không âm thầm bỏ qua. Nếu sau này cần: có thể bọc `angr.Project(..., main_opts={'force_load_libs':...})` không giúp — cần disable COFF symbol loading ở tầng cle (chưa có cờ public), hoặc strip symbol table trước khi nạp.

## 10. Race ở biên timeout — worker ghi xong JSON đúng lúc cha bắn kill, bị log nhầm Timeout

**Chuyện đã xảy ra** (ghi nhận 2026-10-03, build Lô 4 BumbleBee, 266 mẫu, workers=4, timeout=900). Log thô ghi 260 OK / 6 FAIL, nhưng **2/6 mẫu "FAIL" (Timeout) thực chất đã có JSON hợp lệ, hoàn chỉnh** trong `data/features_graph/`:
- `e6c6ad04…`: JSON 4,4MB / 485 hàm, mtime **16:15:52** — đúng mốc ~900s kể từ lúc worker bắt đầu. Worker chạy `write_bfbg()` xong (JSON ghi đầy đủ) **đúng vào thời điểm** `proc.join(900)` ở tiến trình cha hết hạn và gọi `proc.kill()`; cha chỉ thấy `proc.is_alive()` → kết luận Timeout, không biết JSON đã ghi.
- `024291b9…`: JSON 5,4MB / 394 hàm, cũng có sẵn và hợp lệ.

**Nguyên nhân gốc.** `run_one` cũ kết luận Timeout **chỉ dựa vào** `proc.is_alive()` sau `join(timeout)`, không kiểm tra sản phẩm đầu ra. Có một cửa sổ race hẹp: worker hoàn tất `write_bfbg()` trong vài mili-giây cuối trước khi bị kill → JSON tồn tại và đầy đủ, nhưng mẫu vẫn bị tính là thất bại. Hệ quả: (a) đếm trùng — mẫu vừa có JSON dùng được vừa nằm trong `lift_failures.jsonl`; (b) thổi phồng tỉ lệ thất bại.

**Cách sửa** (chỉ `run_one`, không đụng worker/builder/phân loại). Thêm `_salvage_output(path, args)`: sau khi `proc.kill()` vì timeout, kiểm tra `data/features_graph/<sha>_static.json` — nếu `json.load()` không lỗi và có field bắt buộc (`num_functions`, `intra_procedural_graphs`) thì trả kết quả **OK** (vớt lại), ngược lại mới là Timeout. Kill giữa chừng để file cụt → `json.load` báo lỗi → vẫn tính Timeout, an toàn.

**Số liệu bị ảnh hưởng.** Quét lại TOÀN BỘ `lift_failures.jsonl` cả 4 lô, đối chiếu từng dòng `Timeout` với JSON tương ứng: chỉ 2 mẫu trên bị ghi nhầm (đều ở Lô 4). Đã xóa 2 dòng khỏi `lift_failures.jsonl`. Con số tích luỹ trước Lô 4 (11 = 9 IndexError + 2 Dridex Timeout) **không đổi** — 2 Dridex Timeout là thất bại thật, không có JSON. Sau khi dọn: **15 thất bại thật** (9 IndexError + 4 Timeout + 2 KeyError), **1382 malicious JSON dùng được**.

## 11. [QUYẾT ĐỊNH TREO] Chiến lược dataset loader với 674 mẫu near-duplicate: group-aware split (giữ 1.382) hay dedup (còn 708)

**Bối cảnh** (ghi nhận 2026-10-03, hết Giai đoạn B). Sau khi lift xong, `check_sample_similarity.py` (ppdeep ≥90) trên 1.382 mẫu malicious cho **141 cụm near-duplicate / 674 mẫu trùng thừa → chỉ 708 mẫu khác biệt thật** (48,8% trùng; lệch mạnh: Dridex 82%, IcedID 56%, TrickBot 53%, Emotet/BumbleBee <4% — xem `docs/DATASET.md`). Đây là quy mô near-dup lớn hơn hẳn ca `{4becc0d5…, ef6603a7…}` ở mục 4 (chỉ 1 cặp) — cần một quyết định thiết kế ở tầng dataset loader, chứ không chỉ một ràng buộc split.

**Hai hướng, CHƯA chọn** (dataset loader `src/training/` chưa viết):
- **(a) Giữ toàn bộ 1.382, BẮT BUỘC group-aware split theo 141 cụm** (`data/raw/near_duplicate_clusters.jsonl`). Giữ nguyên dữ liệu, kiểm soát rủi ro rò rỉ qua split — đúng chính sách đã áp dụng từ Giai đoạn A (mục 4). Giữ được thông tin tần suất xuất hiện thật của biến thể trong tự nhiên (một biến thể phát tán rộng = nhiều mẫu near-dup), nhưng model có thể bị lệch về các biến thể đông bản (vd Dridex 85 mẫu/cụm) và điểm train phản ánh tần suất chứ không chỉ khả năng phân biệt.
- **(b) Dedup trước khi train, chỉ dùng 708 mẫu khác biệt** (giữ 1 đại diện/cụm). Đơn giản hơn, cân bằng biến thể tốt hơn, loại nguy cơ model học thuộc biến thể đông bản; nhưng **vứt bỏ thông tin tần suất xuất hiện thật** và giảm mạnh số mẫu (nhất là Dridex 377→68).

**Trạng thái.** TREO — chưa tự quyết, giống cách xử lý cụm `{4bec…, ef66…}` ở mục 4 (ghi nhận, chưa loại mẫu nào). Hai điều kiện ràng buộc dù chọn hướng nào: (1) `near_duplicate_clusters.jsonl` là nguồn chân lý cho cụm, loader đọc file này, **không hard-code sha256**; (2) nếu chọn (a), ràng buộc cùng-phía của mục 4 là bắt buộc, không tùy chọn. Quyết định cuối sẽ chốt khi viết `src/training/` và phải ghi lại kèm lý do tại đây.
