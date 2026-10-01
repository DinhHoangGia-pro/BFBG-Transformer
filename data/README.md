# data/

Mọi thứ trong thư mục này **không được commit** (`.gitignore`: `data/*`), trừ file README này. Mẫu PE thật (kể cả malware) chỉ nằm trên máy cục bộ.

Bố cục theo `configs/config.yaml` và `configs/dataset.yaml`:

| Đường dẫn | Nội dung | Sinh bởi |
|---|---|---|
| `data/raw/malicious/`, `data/raw/benign/` | File PE gốc, đặt tên theo sha256 | thu thập thủ công / script tải mẫu |
| `data/vt_reports/` | Report VirusTotal (JSON, tên file = sha256) | script tải report |
| `data/features_graph/` | `<sha256>_static.json` - BFBG của từng mẫu | `python -m src.bfbg.bfbg_builder` |
| `data/vex_vocab.json` | Bảng id token VEX dùng chung cho mọi JSON BFBG | `bfbg_builder` (ghi có khoá file) |

Pre-commit hook trong `scripts/hooks/` chặn mọi file bắt đầu bằng `MZ` (PE) lọt vào commit, kể cả khi dùng `git add -f` - xem `README.md` ở gốc repo để cài.
