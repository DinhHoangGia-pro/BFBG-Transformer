# Dataset

Mô tả nguồn dữ liệu và lựa chọn family cho BFBG-Transformer. Đề tài: **Cross-Family Banking-Trojan Detection**.

> Số liệu dưới đây là **số thật cuối cùng sau khi thu thập + lift** (cập nhật 2026-10-03, hết Giai đoạn B). Phần khảo sát trước-fetch (trần API từng family) xem lịch sử git của file này.

## Phía malicious — lựa chọn family (Giai đoạn B)

Nguồn: MalwareBazaar (abuse.ch), qua `scripts/fetch_malware_samples.py` (API `get_siginfo` + lọc size ≤ `max_file_size_mb` + **dedup sha256**, tất cả từ metadata trước khi tải). **Không** lọc near-duplicate ở bước fetch — near-duplicate được **đo sau khi lift** bằng `experiments/qa/check_sample_similarity.py` (ppdeep), xem mục "Trùng lặp near-duplicate" bên dưới.

### Số thật sau thu thập + lift

"fetched" = số mẫu tải về sau lọc size ≤12MB + dedup sha256. "JSON" = số BFBG dùng được. "oos .NET" = mẫu .NET/CLR loại ở bước lift (`out_of_scope_samples.jsonl`). "fail" = lift thất bại (`lift_failures.jsonl`).

| Family | fetched | JSON dùng được | .NET out-of-scope | lift-fail | Vai trò |
|---|---|---|---|---|---|
| TrickBot | 400 | 396 | 4 (1,0%) | 0 | banking trojan (lõi đề tài) |
| Emotet | 92 | 79 | 13 (14,1%) | 0 | banking trojan / loader |
| Dridex | 379 | 377 | 0 | 2 (0,5%) | banking trojan |
| IcedID | 271 | 260 | 2 (0,7%) | 9 (3,3%) | banking trojan |
| BumbleBee | 266 | 262 | 0 | 4 (1,5%) | loader cùng hệ sinh thái kế nhiệm TrickBot |
| VX/thủ-công | 8 | 8 | 0 | 0 | mẫu import thủ công (VX-Underground) |
| **Tổng** | **1.416** | **1.382** | **19 (1,3%)** | **15 (1,1%)** | |

Phía benign: **44** mẫu native dùng được (xem mục "Phía benign").

### Chi tiết lift-failure theo loại (15 mẫu)
- **9 × IndexError** — toàn bộ IcedID, cùng 1 biến thể × 9 bản near-dup có COFF symbol table bị cố tình làm hỏng (cle vấp khi nạp). Giới hạn công cụ đã biết — `docs/LESSONS_LEARNED.md` mục 9.
- **4 × Timeout** (>900s) — 2 Dridex + 2 BumbleBee, mẫu nhiều hàm/pack, CFGFast không xong trong giới hạn — `docs/LESSONS_LEARNED.md` mục 6.
- **2 × KeyError** — BumbleBee, lỗi trong angr/cle (`function_manager.get`, `cle/memory.load`).

Lưu ý: tỉ lệ .NET khác nhau rõ giữa family — **Emotet 14,1%** (nhiều biến thể .NET nhất), các family khác ≤1%. .NET bị loại vì là CIL bytecode, angr/CFGFast không lift ra mã máy x86 có nghĩa.

### Trùng lặp near-duplicate (ppdeep, threshold ≥90)

Đo trên toàn bộ 1.382 malicious + 44 benign bằng `check_sample_similarity.py`; cụm = thành phần liên thông của quan hệ `ppdeep.compare ≥ 90`. Kết quả ghi vào `data/raw/near_duplicate_clusters.jsonl` (ràng buộc: các mẫu cùng cụm phải nằm **cùng phía** train/test — `docs/LESSONS_LEARNED.md` mục 4).

**141 cụm** >1 phần tử (139 malicious-only, 2 benign-only, **0 cụm lẫn cả hai nhãn**). Nếu giữ 1 đại diện mỗi cụm malicious-only thì **674/1.382 mẫu là trùng thừa → chỉ còn ~708 mẫu malicious thực sự khác biệt (48,8% trùng)**. Mức đa dạng rất lệch theo family:

| Family | JSON | số cụm | mẫu thừa | mẫu khác biệt | % trùng |
|---|---|---|---|---|---|
| TrickBot | 396 | 79 | 208 | 188 | 52,5% |
| Emotet | 79 | 2 | 2 | 77 | 2,5% |
| Dridex | 377 | 30 | 309 | **68** | **82,0%** |
| IcedID | 260 | 21 | 146 | 114 | 56,2% |
| BumbleBee | 262 | 6 | 8 | 254 | 3,1% |
| VX/thủ-công | 8 | 1 | 1 | 7 | 12,5% |
| **Tổng** | **1.382** | **139** | **674** | **708** | **48,8%** |

Hệ quả: **Dridex tuy có 377 mẫu nhưng chỉ 68 khác biệt** (cụm lớn nhất 85 mẫu); IcedID có một cụm 116 mẫu. Khi báo cáo quy mô dataset và chia train/test phải dùng **số mẫu khác biệt (708)**, không phải 1.382, để tránh rò rỉ gần-trùng giữa train và test.

> **BÁO CÁO QUY MÔ DATASET — PHẢI TRÍCH DẪN CẢ HAI CON SỐ.**
> Dataset có **1.382 mẫu PE hợp lệ**, nhưng chỉ **708 mẫu KHÁC BIỆT THẬT** (ssdeep < 90 giữa mọi cặp) sau khi loại near-duplicate. Mọi báo cáo về quy mô dataset trong bài báo **PHẢI trích dẫn cả hai con số, không chỉ 1.382**. Báo cáo riêng 1.382 mà không nhắc 708 là **overclaim về tính đa dạng của dữ liệu** — 48,8% số mẫu là near-duplicate, và mức trùng cực kỳ lệch theo family (Dridex chỉ 68 khác biệt / 377 mẫu).

### Family bị loại, kèm lý do

- **QakBot** — loại vì **không lấy được từ MalwareBazaar**: `get_siginfo(signature="Qakbot"/"QakBot"/"QBot"...)` trả `no_results`; `get_taginfo(tag="qakbot"...)` trả `error` ổn định. MB không phát hành mẫu QakBot dưới các tên này qua API.
- **SystemBC** — tuy trần lớn hơn (484 PE ≤12MB) nhưng loại vì **construct-validity mismatch**: SystemBC là proxy/backdoor tool, **không phải banking trojan** theo đúng tên đề tài. Đưa vào sẽ lặp lại đúng loại lỗi RQF-02 đã bắt ở audit T-CFBG gốc (mẫu không khớp lớp hành vi mà đề tài tuyên bố đo). BumbleBee được chọn thay vì SystemBC vì là loader cùng hệ sinh thái kế nhiệm TrickBot — khớp đúng lớp hành vi, dù quy mô nhỏ hơn.

### Ràng buộc áp dụng khi thu thập
- Lọc size ≤ `sources.max_file_size_mb` (12MB) — xem `docs/LESSONS_LEARNED.md` mục 5–6.
- Dedup sha256 ở bước fetch (near-duplicate **không** lọc ở fetch — đo sau lift, xem trên).
- Mẫu .NET/CLR bị loại ở bước lift (`src/disassembly/pe_lifter.is_dotnet_assembly`), ghi vào `experiments/qa/out_of_scope_samples.jsonl`.
- Near-duplicate phải nằm cùng phía train/test — xem `docs/LESSONS_LEARNED.md` mục 4.

## Phía benign

Hiện **255 mẫu JSON dùng được** (native, ≤12MB), từ 3 nhóm nguồn (cập nhật 2026-10-07, hết Giai đoạn 1-2 mở rộng benign):

| Nguồn | JSON dùng được |
|---|---|
| Windows 11 Enterprise Eval ISO (System32/SysWOW64) | 166 |
| Chocolatey (payload nhúng, 28 vendor khác nhau) | 45 |
| Cũ (7-Zip, Python embeddable, Notepad++, FFmpeg, Git for Windows) | 44 |
| **Tổng** | **255** |

- **Thu thập ISO:** tải Win11 26H2 Enterprise Eval x64 (7,7GB), trích `install.wim` bằng 7z, chọn có kiểm soát ~180 PE top-level System32/SysWOW64 phân tầng kích thước (seed 42), loại trước `api-ms-win-*`/`ext-ms-*` (forwarder rỗng code) theo tên. 180 → 166 JSON / 2 .NET out-of-scope / 12 Timeout.
- **Thu thập Chocolatey:** tải `.nupkg` qua `api/v2/package/<id>` (không cần CLI), giải nén đệ quy archive lồng, lấy **payload PE** bên trong (không lấy installer gốc — xem memory `benign-installer-payload-only`), phân biệt payload/installer bằng `7z -slt Type=`. 28/90 package có nhúng binary (62 chỉ có URL vendor → bỏ qua). 48 → 45 JSON / 1 .NET / 2 Timeout.
- **Near-duplicate benign:** `check_sample_similarity.py` chạy trên **278 file thô** (255 có JSON + 23 không: 9 .NET + 14 Timeout) → chỉ **2 cụm** (đều 2 phần tử, đều là Python-embeddable cũ), 276/278 khác biệt (**0,7% trùng**). Payload Chocolatey **không tạo cụm mới** → rủi ro "installer-stub trùng lặp" KHÔNG xảy ra.

> **CẢNH BÁO nguồn benign mất cân bằng — cần source-holdout.**
> Windows-ISO chiếm **166/255 = 65%** benign, **vượt mức trần 30-40%** đã đặt cho nguồn Microsoft đơn nhất. Rủi ro đúng như MalConv Group A đã ghi: model có thể **"học nguồn thay vì học nhãn"** (nhận ra "từ Microsoft/System32" thay vì "benign"). Khi train/đánh giá PHẢI dùng **source-holdout** (giữ một nguồn benign hoàn toàn ngoài train để kiểm tra generalize), không chỉ chia ngẫu nhiên. Cần bổ sung benign đa vendor (mở rộng Chocolatey/winget) để kéo tỉ lệ ISO xuống.

- **Selection effect tỉ lệ Timeout:** benign **14 Timeout** (ISO 12 + choco 2, trên 228 lần thử ≈ 6,1%) cao hơn hẳn malicious (**4 Timeout thật**, 6 lần chạm thô trên 1.416 ≈ 0,4%). Nguyên nhân đã biết: DLL hệ thống Windows và dev-tool thường là binary **rất nhiều hàm** (vd DLL System32 14.250 hàm) → CFGFast dễ vượt budget hơn malware banking vốn nhỏ gọn. Đây là thiên lệch chọn mẫu cần lưu ý khi so tỉ lệ build giữa hai lớp.

SOREL-20M đã khảo sát và **loại**: binaries là malware đã "disarmed" (trường Machine = 0, angr không nạp được) và không có benign binaries. Benign (255) vẫn **mất cân bằng** so với malicious (1.382 thô / 708 khác biệt) — tiếp tục mở rộng.

## Dataset v1 — đóng băng held-out (2026-10-07)

Snapshot đóng băng để mọi thí nghiệm dùng chung một split. Manifest: `docs/dataset_v1_manifest.jsonl` (1.637 dòng, mỗi mẫu: `sha256, label, source, num_functions, cluster, split`). **Hash đóng băng:** `sha256 = 2c2aa06467b69187b42ec8cf394aa9668d449e2f59302813d3d250b67d1e27c6` — kiểm tra bằng `sha256sum docs/dataset_v1_manifest.jsonl`; nếu lệch nghĩa là dataset đã đổi và split không còn hợp lệ.

### Quy mô theo split

| split | malicious | benign | tổng |
|---|---|---|---|
| train_pool | 915 | 176 | 1.091 |
| test_indist | 205 | 34 | 239 |
| holdout_family_bumblebee | 262 | 0 | 262 |
| holdout_source_chocolatey | 0 | 45 | 45 |
| **tổng** | **1.382** | **255** | **1.637** |

### Định nghĩa held-out (Dual, đã chốt)

- **holdout_family_bumblebee** — toàn bộ malicious family **BumbleBee** (262), giữ hoàn toàn ngoài train. Đây là **thí nghiệm cross-family lõi**: train trên TrickBot+Emotet+Dridex+IcedID, đo khả năng bắt một loader family chưa từng thấy.
- **holdout_source_chocolatey** — toàn bộ benign nguồn **Chocolatey** (45, 28 vendor non-Microsoft), giữ ngoài train. Đo **generalization chéo nguồn benign** (chống rủi ro "học Microsoft thay vì học nhãn" do ISO chiếm 65%).
- **test_indist** — ~15% phần còn lại, **cluster-aware** (cụm near-dup luôn cùng phía) + stratified theo family/nguồn (malicious 205 ≈ 18%, benign 34 ≈ 16% sau khi làm tròn theo cụm). Đo in-distribution.
- **train_pool** — phần còn lại (1.091); val tách ra từ đây khi train, KHÔNG đụng vào 3 split trên.

**Bất biến:** split gán ở mức **cụm near-dup** (field `cluster`), không bao giờ tách một cụm qua hai split. `holdout_*` đóng băng theo family/nguồn; `test_indist` sinh với seed 42 (xem `make_v1.py`). Mọi mở rộng dataset (Bậc 1/2) sẽ tạo **v2 mới**, KHÔNG sửa v1 — để kết quả v1 tái lập được.

### Rủi ro & hạn chế v1 (cần xử lý ở v2)

- **Train benign lệch nặng về Windows ISO (~80%).** train_pool benign = 176, trong đó **141 là Windows-ISO (80%)**, chỉ 35 non-Microsoft (7-Zip 11, python-embeddable 10, Notepad++ 5, Git 5, FFmpeg 4). Vượt xa trần 30-40% cho nguồn Microsoft → v2 phải bổ sung benign non-Microsoft (Scoop/GitHub/winget, KHÁC Chocolatey vì Chocolatey đã là holdout) để kéo tỉ lệ ISO xuống.
- **Hai holdout là MỘT CHIỀU (one-way).** `holdout_family_bumblebee` chỉ có malicious (262, 0 benign) → chỉ đo được **recall/TPR**; `holdout_source_chocolatey` chỉ có benign (45, 0 malicious) → chỉ đo được **FPR/specificity**. Khi đánh giá phải **ghép mẫu âm/dương từ `test_indist`** của nhãn đối diện (vd recall BumbleBee dùng benign test_indist làm âm; FPR Chocolatey dùng malicious test_indist làm dương). **Hạn chế:** mẫu ghép không cùng phân phối với holdout (benign test_indist ≠ benign Chocolatey; malicious test_indist ≠ BumbleBee), nên điểm tuyệt đối chỉ tham khảo; dùng để so sánh tương đối giữa các mô hình trên cùng cách ghép.
- **test_indist chỉ có 34 benign** (vs 205 malicious) → ước lượng FPR/specificity in-distribution có sai số lớn. v2 phải tăng benign để test_indist có đủ mẫu âm.
- **Confound metadata (probe Phần A, 2026-10-07).** Classifier CHỈ-metadata (linker, compile-year, entropy, …) đạt **AUC = 1.000** trên test_indist nhưng **FPR 53% trên holdout_chocolatey** (Wilson95 [39%,67%]) → tách lớp in-distribution là **confound nguồn/thời điểm**, KHÔNG generalize. Hệ quả: (1) mọi đánh giá BFBG phải báo kèm holdout chéo-nguồn để phát hiện mô hình ăn gian theo metadata; (2) BFBG dùng VEX token + call graph (không nhận các header này), nhưng vẫn cần kiểm tra nó không gián tiếp học entropy/size. Số liệu thô trong lịch sử phiên; tái lập bằng probe metadata trên manifest v1.

## Kế hoạch v2 benign (chưa thực hiện — v1 giữ nguyên, không sửa)

Dựa trên probe Phần A + Task 2-5 (2026-10-07). **KHÔNG sửa dataset v1/manifest/split**; v2 là tập mới, chỉ bắt đầu khi plan này được duyệt.

### Mục tiêu theo toolchain-bin (đủ benign non-Microsoft ở MỖI bin, không "khớp %")
Probe cho thấy benign-train hiện ~MSVC14 (ISO) trong khi malware trải rộng, tập trung **MSVC≤10 (680/1382 ≈ 49%)**. Mục tiêu v2 **KHÔNG** phải ép khớp đúng tỉ lệ % của malware, mà là: **mỗi bin lớn có tổng ≥N benign non-Microsoft** (đề xuất **N≥150/bin**, chốt sau) **chia được cho CẢ train lẫn test qua group-aware cross-validation** (CV theo cụm near-dup + vendor, không chia ngẫu nhiên từng mẫu), rồi **reweight theo bin ở loader**. **LƯU Ý:** `test_indist` 15% của v1 (chỉ 34 benign) **KHÔNG** đủ cho 150/bin ở test — v2 phải hoặc tăng benign tổng để 15% test đạt ngưỡng mỗi bin, hoặc dùng group-aware CV k-fold thay cho một test_indist cố định. Báo cáo thu thập v2 **theo từng bin** (yield + đếm cuối mỗi bin), không chỉ tổng.

| toolchain-bin | benign v1 hiện có | nguồn phù hợp (đã loại Scoop GNU khỏi bin ≤10) |
|---|---|---|
| MSVC≤10 (bin lớn) | ~rất ít (ISO toàn v14) | PA app cũ (IrfanView v8), old GitHub release tags (2008-2012), Scoop **Versions** (bản cũ) |
| MSVC 14 (bin lớn) | nhiều (ISO 159) | GitHub OSS release (có ký), đã dư |
| MSVC 11-12 | ~0 | GitHub tag 2012-2015, Scoop Versions |
| **GNU/MinGW/Go/Rust (bin RIÊNG)** | ít | Scoop (busybox/gawk/make/jq…), Go/Rust CLI |
| Delphi / khác | ~0 | HeidiSQL/IssRC (Delphi) |

**GNU/MinGW/Go/Rust là một bin RIÊNG, KHÔNG dùng để lấp bin MSVC≤10** (toolchain khác hẳn về cấu trúc PE/CRT). Malware chỉ có **18 mẫu GNU** (và ~0 Go/Rust tin cậy) → **cap bin GNU/Go/Rust ở ≤10% tổng benign** để không tạo confound ngược (benign toàn GNU trong khi malware toàn MSVC).

### Quy tắc dedup & gán holdout (bắt buộc)
- **`ppdeep = 100` HOẶC trùng sha256** với một mẫu **holdout** (hoặc mẫu đã fail/không-JSON) → **LOẠI** (không đưa vào bất kỳ split). *(Pilot Scoop: fd/graphviz/nasm/putty/ripgrep/upx trùng khít holdout_chocolatey; wget trùng sha mẫu đã fail → đều LOẠI.)*
- **`90 ≤ ppdeep < 100`** với một mẫu hiện có → **kế thừa split** của mẫu đó (giữ ràng buộc cụm near-dup; nếu mẫu đó ở holdout thì mẫu mới cũng vào holdout, không train).
- **Cap ≤3 payload/app** và **cap vendor THEO BIN: đề xuất ≤35% mỗi bin cho một vendor** (con số đề xuất, chốt sau) — tránh một vendor chiếm ưu thế TRONG bin (vd NirSoft một mình phủ bin MSVC≤10 sẽ lặp confound kiểu ISO-65% ở v1, nhưng ở cấp bin). Ưu tiên exe chính (bỏ DLL bundle phụ của bên thứ ba).

### Nguồn (ngoài Chocolatey — đã là holdout)
- **Scoop** (0 .NET, phủ nhiều toolchain) — nhưng cho **bin GNU/Go/Rust** và (qua Versions) bin MSVC cũ; dedup chống trùng holdout.
- **GitHub Releases OSS MSVC** (có ký, ~toàn MSVC14) — cho bin MSVC14.
- **PortableApps.com** (có ký, có app cũ <12, 0 trùng) — bổ sung bin MSVC≤10; cần trích URL tốt hơn (yield tự động thấp).
- Lưu timeout: Rust/Go static + app nhiều hàm cần `--timeout 900` (pilot timeout@300 rớt fd/ripgrep).

> **Cảnh báo ngoại suy:** pilot Scoop (22 app) **chọn tay công cụ GNU/C** nên yield (86%), tỉ lệ .NET (0%) và tỉ lệ near-dup (37%) **KHÔNG ngoại suy** cho Scoop nói chung — cần pilot ngẫu nhiên (seed cố định) để có số đại diện. Xem `experiments/dataset/pilots/`.

### global_features trong classification head — CHƯA định nghĩa
Head (`bfbg_transformer.py`) nối `pooled_program ⊕ global_features` với `num_global_features=4`, nhưng loader `src/training/` chưa viết và Eq.16 chỉ nêu **2** đặc trưng (entropy toàn cục, has_any_external_call). **Khuyến nghị: BỎ global_features khỏi head** (`num_global_features=0`) để không nạp entropy vào head — vì probe Phần A cho thấy entropy/size là confound nguồn (AUC metadata=1.0, FPR choco 53%; Task 2 bỏ entropy+packed giảm FPR 18→9%). Giữ entropy **chỉ như một ablation** riêng, không phải input mặc định. Chốt khi viết loader.

### Kết quả kiểm chứng classifier + pilot ngẫu nhiên (2026-10-07)
- **Classifier toolchain:** kiểm chứng 30 mẫu phân tầng (heuristic vs ground-truth bằng chuỗi compiler/section/CRT) → **24/30 đúng (80%)**. **Nhãn "Rust?" (heuristic bcrypt+api-ms-crt) sai 4/4 (100%) → ĐÃ BỎ** (fold vào MSVC14; chỉ nhận Rust khi có chuỗi `rustc`). Lỗi phụ: luật GNU quá rộng gọi nhầm 2 MSVC≤10 (upx/busybox import msvcrt) → bộ đã kiểm chỉ gọi GNU khi có `.eh_frame`/chuỗi GCC/mingw-dll. Dùng bộ đã kiểm cho binning v2. Code: `experiments/dataset/pilots/validate_tc.py`.
- **Pilot ngẫu nhiên (seed 20261007, `pilot_random.py`):** Scoop Main 25 → yield **11/25 (44%)** (so với 86% chọn tay → **không ngoại suy được**), đa dạng toolchain (MSVC14/≤10/Go/GNU/Rust). Nirsoft 25 → yield **23/25 (92%), toolchain 100% MSVC≤10 (linker 6-8)**, native, 0 near-dup, 0 timeout.
- **Hệ quả nguồn:** Nirsoft là nguồn lý tưởng cho **bin MSVC≤10** đang thiếu, NHƯNG là **một vendor duy nhất** (Nir Sofer) → áp **cap theo vendor** mạnh để không lặp confound kiểu ISO-65%. Scoop Main (random) bổ sung đa vendor nhưng yield thấp (44%) và lẫn Go/Rust (→ bin GNU/Go/Rust riêng, cap ≤10%).

### Bổ sung v2 (c–e, 2026-10-07)
- **(c) Tập dual-use "stress" riêng — CHỈ báo FPR, KHÔNG train.** Các tool mạng/sniffer/recovery (bị regex loại khỏi benign thường, xem danh sách ở `pilot_random.py`) gom thành một tập stress riêng để **đo FPR** (model có coi tiện ích hệ thống hợp pháp là malicious không), **không đưa vào train/test chính**. **Ghi chú:** nhãn "benign" của tập này **chưa xác minh được** (dual-use: thật sự lành tính hay bị lạm dụng tùy ngữ cảnh) → chỉ dùng như phép thử FPR, không coi là ground-truth benign.
- **(d) Mẫu số các con số toolchain:**
  - **680** = số malware phân loại **MSVC≤10 bằng heuristic header** (Rich/linker, bảng Task 2) trên **mẫu số 1.382 malware v1** → 680/1.382 ≈ 49%.
  - **728** = số malware có **linker major ≤10 (đọc trực tiếp pefile, proxy nhanh)**, dùng làm nhóm so phân phối num_functions/num_api_calls (Task 1-2), cũng trên **1.382 malware v1**. Chênh 680 vs 728 do hai cách xác định (heuristic đa-tín-hiệu vs chỉ linker major); cả hai là xấp xỉ bin MSVC≤10, không phải con số chính xác tuyệt đối.
- **(e) Giấy phép nguồn benign đã pilot:**
  - **NirSoft:** **freeware, đóng mã (proprietary)**; mỗi tool một giấy phép freeware riêng, **nhiều tool CẤM phân phối lại** (redistribute) nếu không xin phép. ⇒ chỉ dùng **cục bộ cho nghiên cứu**, **KHÔNG commit/redistribute** binary (đã gitignore `data/`). Là **một vendor duy nhất** → ràng buộc cap-vendor-theo-bin ở trên.
  - **Scoop:** bản thân manifest/manager là Unlicense/MIT; **app bên trong mang giấy phép riêng** (hỗn hợp OSS như MIT/GPL/Apache + vài freeware). Manifest Scoop có field `license` (đọc được khi thu thập) → ghi provenance giấy phép theo từng app. Payload lấy ra cũng **không redistribute** (gitignore).
