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

### Family bị loại, kèm lý do

- **QakBot** — loại vì **không lấy được từ MalwareBazaar**: `get_siginfo(signature="Qakbot"/"QakBot"/"QBot"...)` trả `no_results`; `get_taginfo(tag="qakbot"...)` trả `error` ổn định. MB không phát hành mẫu QakBot dưới các tên này qua API.
- **SystemBC** — tuy trần lớn hơn (484 PE ≤12MB) nhưng loại vì **construct-validity mismatch**: SystemBC là proxy/backdoor tool, **không phải banking trojan** theo đúng tên đề tài. Đưa vào sẽ lặp lại đúng loại lỗi RQF-02 đã bắt ở audit T-CFBG gốc (mẫu không khớp lớp hành vi mà đề tài tuyên bố đo). BumbleBee được chọn thay vì SystemBC vì là loader cùng hệ sinh thái kế nhiệm TrickBot — khớp đúng lớp hành vi, dù quy mô nhỏ hơn.

### Ràng buộc áp dụng khi thu thập
- Lọc size ≤ `sources.max_file_size_mb` (12MB) — xem `docs/LESSONS_LEARNED.md` mục 5–6.
- Dedup sha256 ở bước fetch (near-duplicate **không** lọc ở fetch — đo sau lift, xem trên).
- Mẫu .NET/CLR bị loại ở bước lift (`src/disassembly/pe_lifter.is_dotnet_assembly`), ghi vào `experiments/qa/out_of_scope_samples.jsonl`.
- Near-duplicate phải nằm cùng phía train/test — xem `docs/LESSONS_LEARNED.md` mục 4.

## Phía benign

Hiện **44** mẫu (native, ≤12MB) từ 5 nguồn portable chính thức: 7-Zip, Python embeddable, Notepad++, FFmpeg, Git for Windows (6 mẫu .NET của Git for Windows đã bị loại out-of-scope). Có 2 cụm near-duplicate benign (Python embeddable). SOREL-20M đã khảo sát và **loại**: binaries là malware đã "disarmed" (trường Machine = 0, angr không nạp được) và không có benign binaries. Benign hiện **mất cân bằng mạnh** so với malicious (44 vs 708 khác biệt) — kế hoạch mở rộng benign còn đang cân nhắc nguồn.
