# Dataset

Mô tả nguồn dữ liệu và lựa chọn family cho BFBG-Transformer. Đề tài: **Cross-Family Banking-Trojan Detection**.

## Phía malicious — lựa chọn family (Giai đoạn B)

Nguồn: MalwareBazaar (abuse.ch), qua `scripts/fetch_malware_samples.py` (API `get_siginfo` + lọc size ≤ `max_file_size_mb` + dedup sha256 + loại near-duplicate bằng ssdeep, tất cả **từ metadata trước khi tải**).

Trần thực tế từng family (khảo sát 2026-10-02 qua `get_siginfo`, limit 500 — trần thực dụng của API; `limit=1000` trả HTTP 502). "PE ≤12MB" = file_type exe/dll, file_size ≤ 12MB, unique theo sha256:

| Family | PE ≤12MB (unique) | Khoảng first_seen | Vai trò |
|---|---|---|---|
| TrickBot | 400 | 2021-08 → 2026-09 | banking trojan (lõi đề tài) |
| Emotet | 95 | 2020-03 → 2026-04 | banking trojan / loader |
| Dridex | 379 | 2021-11 → 2025-10 | banking trojan |
| IcedID | 271 | 2023-01 → 2026-03 | banking trojan |
| BumbleBee | 266 | 2022-04 → 2026-08 | loader cùng hệ sinh thái kế nhiệm TrickBot |
| **Tổng** | **~1.411** | | (trước khi trừ 25 TrickBot đã có + near-dup) |

Mỗi family lấy hết phần liftable (không gồng ép vượt kho thật). Tổng ~1.411 PE ≤12MB unique, hướng tới mốc 1.200–1.800 của Giai đoạn B.

### Family bị loại, kèm lý do

- **QakBot** — loại vì **không lấy được từ MalwareBazaar**: `get_siginfo(signature="Qakbot"/"QakBot"/"QBot"...)` trả `no_results`; `get_taginfo(tag="qakbot"...)` trả `error` ổn định. MB không phát hành mẫu QakBot dưới các tên này qua API.
- **SystemBC** — tuy trần lớn hơn (484 PE ≤12MB) nhưng loại vì **construct-validity mismatch**: SystemBC là proxy/backdoor tool, **không phải banking trojan** theo đúng tên đề tài. Đưa vào sẽ lặp lại đúng loại lỗi RQF-02 đã bắt ở audit T-CFBG gốc (mẫu không khớp lớp hành vi mà đề tài tuyên bố đo). BumbleBee được chọn thay vì SystemBC vì là loader cùng hệ sinh thái kế nhiệm TrickBot — khớp đúng lớp hành vi, dù quy mô nhỏ hơn.

### Ràng buộc áp dụng khi thu thập
- Lọc size ≤ `sources.max_file_size_mb` (12MB) — xem `docs/LESSONS_LEARNED.md` mục 5–6.
- Dedup sha256 + loại near-duplicate (ssdeep) từ metadata trước khi `get_file`.
- Mẫu .NET/CLR bị loại ở bước lift (`src/disassembly/pe_lifter.is_dotnet_assembly`), ghi vào `experiments/qa/out_of_scope_samples.jsonl`.
- Near-duplicate phải nằm cùng phía train/test — xem `docs/LESSONS_LEARNED.md` mục 4.

## Phía benign

Hiện 44 mẫu (native, ≤12MB) từ 5 nguồn portable chính thức: 7-Zip, Python embeddable, Notepad++, FFmpeg, Git for Windows (6 mẫu .NET của Git for Windows đã bị loại out-of-scope). SOREL-20M đã khảo sát và **loại**: binaries là malware đã "disarmed" (trường Machine = 0, angr không nạp được) và không có benign binaries. Kế hoạch mở rộng benign cho quy mô 1.000–2.000 còn đang cân nhắc nguồn.
