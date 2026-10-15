# Đề cương bài — Hướng B (measurement / cautionary study)

*Written for: đồng tác giả + phản biện. Mọi số là dev-set/post-hoc cho tới khi chạm holdout cuối.*

## Tiêu đề (đã chốt)
"A Shortcut-Aware Evaluation Protocol and Benchmark for Static Banking-Trojan Detection"

## Đóng góp (claims — tất cả gắn phạm vi)
C1. Kiểm toán confound có hệ thống trên tác vụ family-vs-benign: baseline **metadata-PE** tổng quát tốt nhất
    (LOFO 5-family 0.972±0.017) và **≥** mô hình đồ thị BFBG (0.906±0.046) trên dev-set.
C2. **Chẩn đoán đường tắt**: embedding (kể cả **chưa train**) mã hóa toolchain/family (0.80/0.79 ≥ trained).
C3. **Bệnh lý cửa-sổ-đầu-vào**: cắt 150 hàm đầu bỏ 77–100% seed ATT&CK; chọn theo api-density giữ 72%
    (không dùng nhãn) — kết quả phụ thuộc thiết kế loader.
C4. **Bộ công cụ + giao thức đánh giá tái lập** (manifest+hash, within-bin, LOFO, holdout khóa) để
    cộng đồng tránh các confound này.

## Cấu trúc mục (định dạng TẠP CHÍ — dài hơn hội nghị)
1. **Giới thiệu** — vấn đề phát hiện xuyên-họ; câu hỏi nghiên cứu (RQ1 GNN có thêm giá trị trên baseline PE? RQ2 tín hiệu nằm ở đâu — confound hay cấu trúc? RQ3 thiết kế loader ảnh hưởng thế nào?); đóng góp; roadmap.
2. **Nền tảng & Related Work (ĐẦY ĐỦ, chuẩn tạp chí)** — (2.1) phát hiện malware bằng PE-metadata/EMBER/MalConv; (2.2) mô hình đồ thị/CFG/GNN cho binary; (2.3) confound & shortcut learning trong ML-security (Arp et al. "Dos and Don'ts"); (2.4) đánh giá xuyên-họ/temporal; (2.5) khoảng trống → bài này.
3. **Mối đe dọa confound (khung khái niệm)** — toolchain≈family, kích thước, cửa-sổ-đầu-vào; vì sao chúng bẫy đánh giá.
4. **Dữ liệu & thiết lập** — nguồn malware (5 family) + benign (ISO/choco/scoop/nirsoft); manifest v1/v2/v3 + hash; split group-aware (cụm near-dup); holdout khóa; thống kê mô tả (bảng).
5. **Phương pháp đo** — baseline (metadata/graph/bag-of-tokens/graph+API), BFBG (kiến trúc tóm tắt), giao thức: within-bin, LOFO 5-family, shortcut linear-probe, phân tích cửa-sổ/kích thước, cluster-bootstrap CI, tiền-đăng-ký tiêu chí.
6. **Thực nghiệm & Kết quả** — (6.1) baseline vs GNN; (6.2) within-MSVC14 (khử toolchain); (6.3) LOFO; (6.4) shortcut probe; (6.5) cửa-sổ-đầu-vào & api-density; (6.6) kích thước; (6.7) holdout cuối v3 (chạm một lần).
7. **Thảo luận** — diễn giải (cơ chế là GIẢ THUYẾT), hệ quả cho thiết kế benchmark, khuyến nghị thực hành đánh giá.
8. **Threats to Validity** — internal (confound chưa tách hết, n_neg nhỏ, 1 kiến trúc/1 sweep), external (benign lệch phân phối, chưa SOTA ngoài), construct (choco=dev, AUC trên benign dễ), reliability (nhiễu seed, đã khóa seed+hash).
9. **Artifact & Reproducibility** — manifest+hash, scripts sinh từng bảng (reproduce_tables.py…), môi trường, hướng dẫn chạy; tuyên bố artifact-available.
10. **Kết luận & hướng tương lai** — benign khớp-confound, mở rộng kiến trúc/seed.

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

## Venue đề xuất — TẠP CHÍ Q1/Q2 (2 ứng viên; TỰ XÁC MINH trước khi nộp — xem VENUE_CHECKLIST.md)
1. **Computers & Security (Elsevier, COSE)** — tạp chí bảo mật lâu đời, nhận empirical/measurement & đánh giá phương pháp; thường có mục artifact.
2. **Journal of Information Security and Applications (Elsevier, JISA)** — ML-security ứng dụng, nhận benchmark/cautionary study.
   (Dự phòng cần tự kiểm: IEEE TIFS, EURASIP J. Information Security.)
⚠️ Quartile/Aims&Scope/độ dài/artifact/thời gian phản biện **phải do tác giả tự xác minh** (checklist riêng); tôi KHÔNG điền số liệu chưa kiểm chứng.
