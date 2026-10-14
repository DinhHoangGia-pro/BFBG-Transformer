# Đề cương bài — Hướng B (measurement / cautionary study)

*Written for: đồng tác giả + phản biện. Mọi số là dev-set/post-hoc cho tới khi chạm holdout cuối.*

## Tiêu đề (nháp)
"Confound hơn cấu trúc: baseline PE-metadata vượt mô hình đồ thị/transformer trong phát hiện
banking-trojan xuyên-họ, và một bệnh lý cửa-sổ-đầu-vào"

## Đóng góp (claims — tất cả gắn phạm vi)
C1. Kiểm toán confound có hệ thống trên tác vụ family-vs-benign: baseline **metadata-PE** tổng quát tốt nhất
    (LOFO 5-family 0.972±0.017) và **≥** mô hình đồ thị BFBG (0.906±0.046) trên dev-set.
C2. **Chẩn đoán đường tắt**: embedding (kể cả **chưa train**) mã hóa toolchain/family (0.80/0.79 ≥ trained).
C3. **Bệnh lý cửa-sổ-đầu-vào**: cắt 150 hàm đầu bỏ 77–100% seed ATT&CK; chọn theo api-density giữ 72%
    (không dùng nhãn) — kết quả phụ thuộc thiết kế loader.
C4. **Bộ công cụ + giao thức đánh giá tái lập** (manifest+hash, within-bin, LOFO, holdout khóa) để
    cộng đồng tránh các confound này.

## Cấu trúc mục
1. Giới thiệu — vấn đề phát hiện xuyên-họ, câu hỏi: GNN có thêm giá trị trên baseline PE không?
2. Dữ liệu & thiết lập — v1/v2 manifest, split group-aware, confound đã biết (toolchain/size).
3. Phương pháp đo — baseline (metadata/graph/bag-of-tokens/graph+API), BFBG, within-bin, LOFO, holdout khóa.
4. Kết quả — (4.1) baseline vs GNN; (4.2) shortcut probe; (4.3) cửa-sổ-đầu-vào & api-density; (4.4) kích thước.
5. Holdout kiểm định cuối (v3) — chạm một lần, cấu hình đã commit.
6. Thảo luận — vì sao confound chi phối; khuyến nghị đánh giá.
7. Hạn chế & đe dọa hiệu lực — dev-set, n nhỏ, 1 kiến trúc, benign lệch phân phối.
8. Kết luận.

## Bảng/Hình cần có (mỗi cái ghi script sinh)
| # | Nội dung | Script sinh |
|---|---|---|
| B1 | BFBG 4-seed (first-150 & api-density) mean±std vs baseline | `reproduce_tables.py` (BANG 1) |
| B2 | Within-MSVC14 AUC [CI cụm] (khử toolchain) | `reproduce_tables.py` (BANG 2) + `verify_sel.py` (xác minh n_neg, no-leak) |
| B3 | LOFO 5-family AUC mean±std | `reproduce_tables.py` (BANG 3) |
| B4 | Shortcut probe (trained vs untrained emb, toolchain/family) | `shortcut_probe_emb.py` |
| B5 | Cửa-sổ: seed bị cắt theo nhãn/family + coverage 3 policy | `reproduce_tables.py` (BANG 5) + `verify_sel.py` (#3) |
| B6 | Baseline đơn giản (BoT-full/model-view, graph+API) | `reproduce_tables.py` (BANG 4) + `experiments_h.py` (BoT-full) |
| H1 | num_functions phân phối benign vs malware (hình) | `experiments_h.py` (H1) |
| B7 | Holdout v3 kết quả (chạm một lần) | (sau khi có v3; cấu hình trong FINAL_CONFIG_PROPOSAL) |

## Claim KHÔNG được nói (xem DIRECTION_B_REVIEW §C, §E)
- ❌ "BFBG học hành vi"; ❌ "BFBG vượt baseline"; ❌ "đúng cho mọi family";
- ❌ "metadata mạnh VÌ toolchain" như sự thật (là **giả thuyết**, cần benign khớp-confound);
- ❌ "api-density sửa được cửa sổ" (§20 chưa đạt +0.07, p=0.20);
- ❌ số dev-set trình như năng lực tổng quát; ❌ nhân quả "cắt-hàm GÂY thất bại" (mới tương quan + 1 can thiệp).

## Venue đề xuất (2)
1. **DIMVA 2026** (Detection of Intrusions and Malware & Vulnerability Assessment) — hợp đo lường/empirical malware, nhận cautionary/benchmark study.
2. **ACM AISec (workshop tại CCS)** — ML-security, hoan nghênh confound/shortcut analysis + bộ công cụ tái lập.
   (Dự phòng: RAID, hoặc NeurIPS Datasets & Benchmarks nếu kèm bộ benign khớp-confound.)
