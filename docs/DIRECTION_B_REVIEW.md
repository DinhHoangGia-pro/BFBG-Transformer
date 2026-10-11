# Nhận xét DIRECTION_B_DRAFT (self-review, 2026-10-11)

Mục đích: kiểm kê bằng chứng để biết claim nào đứng được, còn thiếu gì, và câu nào KHÔNG được nói.

## A. Bằng chứng ĐÃ CÓ (đủ mạnh để trình, kèm caveat dev-set)
1. **Baseline đơn giản ngang/vượt GNN:** BFBG 4-seed 0.906±0.046 vs metadata 0.985, graph 0.904, bag-of-tokens 0.972, graph+API 0.950 (dev-set choco, n=306, CI cụm).
2. **LOFO 5-family:** metadata 0.972±0.017 tổng quát tốt & ổn định nhất; bag-of-tokens 0.876±0.082 (kém, nhiễu). → tín hiệu token đặc-thù-họ.
3. **Shortcut probe:** embedding mã hóa toolchain/family (trained 0.69/0.69; untrained random-init 0.80/0.79 ≥ trained) → confound nằm trong đầu vào/kiến trúc, không do training.
4. **Bệnh lý cửa-sổ-đầu-vào:** cắt "150 hàm đầu theo địa chỉ" bỏ 77–96% seed evidence (BumbleBee 100%); api-density giữ 72% (không dùng nhãn).
5. **Confound kích thước:** benign median 4255 hàm vs BumbleBee 394; num_functions một mình (oriented) AUC 0.821–0.825.
6. **Within-MSVC14 (khử toolchain):** mọi model vẫn 0.97–1.00 — nhưng n_neg=21 (yếu).
7. **Tính tái lập:** manifest + hash đóng băng (freeze-v2/v2.1), nhật ký pipeline-check đầy đủ.

## B. Bằng chứng CÒN THIẾU (cần trước khi nộp hướng B)
1. **Holdout kiểm định cuối CHƯA chạm** (holdout_nirsoft) — mọi số là dev-set choco; chưa có xác nhận ngoài-dev.
2. **choco benign n=45, nirsoft n=20** — quá nhỏ cho FPR/recall@FPR đáng tin; cần benign lớn & đa dạng hơn.
3. **Chưa có baseline SOTA ngoài** (EMBER/MalConv/gradient-boosting trên byte/PE) trên **cùng split** — claim "đơn giản ngang GNN" cần ít nhất 1 SOTA tham chiếu.
4. **Chưa có benign KHỚP-CONFOUND** (cùng toolchain/size/signed với malware) để chứng minh "bài toán dễ giả tạo" một cách nhân quả (hiện mới là tương quan).
5. **Within-bin mới MSVC14, n_neg=21**; chưa làm bin khác, chưa kiểm định AUC=1.0 trên neg lớn hơn.
6. **BFBG mới ≤4–6 seed, 1 cấu hình** — chưa quét siêu-tham-số; "GNN không vượt" bị giới hạn phạm vi.
7. **api-density chưa chứng minh** (§20 KHÔNG đạt +0.07; p=0.20) — không dùng làm "fix".

## C. Các CLAIM KHÔNG ĐƯỢC NÓI (quá tầm bằng chứng)
- ❌ "GNN/BFBG vô dụng cho phát hiện malware" — ta chỉ test 1 kiến trúc, 1 bài, dev-set; chỉ nói "trong phạm vi này, không vượt metadata".
- ❌ "metadata là đủ để phát hiện banking-trojan" — metadata cao vì **benign lệch phân phối**; không khái quát ra benign khớp-confound.
- ❌ "api-density cải thiện BFBG" — §20 KHÔNG đạt; chỉ là xu hướng dương yếu.
- ❌ bất kỳ con số nào trình như **kết quả cuối** — tất cả là pipeline-check/dev-set, phải gắn nhãn.
- ❌ "chúng tôi phát hiện confound mới" — confound toolchain/size là đã biết trong văn liệu; đóng góp là **đo lường hệ thống trên tác vụ xuyên-họ cụ thể + bệnh lý cửa-sổ**, không phải phát hiện nguyên lý mới.
- ❌ "đạt AUC ~0.95" như năng lực mô hình — phải nói rõ là **trên benign dễ (dev-set)**.
- ❌ Kết luận nhân quả "cắt-hàm GÂY ra thất bại" — mới có tương quan (coverage thấp) + 1 can thiệp (api-density) chưa đạt ngưỡng.

## D. Khuyến nghị tối thiểu để hướng B đứng được
1. Chạm holdout cuối MỘT lần với cấu hình ghi-trước (xem ước tính riêng).
2. Thêm ≥1 baseline SOTA ngoài trên cùng split.
3. Khung hóa là **measurement/cautionary study** (không phải "bộ phát hiện mới"), nhấn mạnh tái lập.
4. Mọi bảng gắn nhãn dev-set + n + CI; tách rõ "đã xác nhận ngoài-dev" vs "chỉ dev".
