# Dataset-source pilots (code only, no data)

Pilot scripts đo khả thi nguồn benign non-Microsoft cho v2 (xem
`docs/DATASET.md` mục "Kế hoạch v2 benign"). Chỉ là công cụ ĐO — không thu
thập hàng loạt, không ghi mẫu vào repo (mẫu/paylod ra thư mục tạm ngoài repo).

- `pilot_scoop.py` — pilot Scoop (chọn tay công cụ GNU/C; KHÔNG ngoại suy được).
- `pilot_github.py` — pilot GitHub Releases OSS MSVC (chọn tay).
- `pilot_pa.py` — pilot PortableApps.com.
- `pilot_random.py` — pilot NGẪU NHIÊN (seed cố định) Scoop Main + nirsoft; loại tool mật khẩu/hack. Dùng bộ phân loại toolchain đã kiểm (bỏ nhãn "Rust?" heuristic).
- `validate_tc.py` — kiểm chứng classifier toolchain (confusion matrix heuristic vs ground-truth).
