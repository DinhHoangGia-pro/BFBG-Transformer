# Đề xuất cấu hình cuối cho lần CHẠM holdout_nirsoft DUY NHẤT (bản nháp — CHƯA chốt, CHƯA chạy)

> holdout_nirsoft **chỉ chạm MỘT lần**. Mọi lựa chọn dưới đây phải được **người dùng duyệt + commit**
> TRƯỚC khi chạm; sau khi chạm, **báo cả tốt lẫn xấu, không chạm lại, không tinh chỉnh theo kết quả**.
> Hiện nirsoft = **20 benign-only** → CI sẽ rộng; xem mục E về thu thêm trước khi chạm.

## A. Mô hình đem so (ghi trước, cùng tập/split)
Đề xuất so song song (người dùng chọn tập con):
- **BFBG** — phải chốt MỘT biến thể: (i) first-150 §17 **ensemble 4 seed** {101,202,303,404}, HOẶC
  (ii) api-density §17 ensemble 4 seed. *Khuyến nghị nêu rõ: api-density CHƯA đạt §20 (0.951<0.976) →
  nếu chọn api-density phải gắn nhãn "ứng viên chưa chứng minh". Mặc định an toàn = first-150 ensemble.*
  KHÔNG chọn "seed tốt nhất" (đó là chọn theo kết quả).
- **probe metadata** (RF 8 scalar) — baseline mạnh nhất hiện tại.
- **probe graph** (RF 7 scalar).
- **bag-of-tokens** (TF-IDF + RF, model-view).
Tất cả train trên **cùng train set đã khóa** (v2 train_pool, ISO cap 113), KHÔNG dùng nirsoft để train/chọn.

## B. Positives mượn (vì nirsoft benign-only)
- nirsoft (20) = **negatives**. Positives = **một family malware GIỮ LẠI** đã ghi trước — đề xuất **BumbleBee (262)**
  (đã là holdout family), hoặc công bố cả 5 family riêng. Ghi trước family nào, KHÔNG đổi sau.

## C. Metric (ghi trước)
1. **AUC(nirsoft vs positives)** + **cluster-bootstrap CI** (cụm near-dup; nirsoft 20 singleton).
2. **FPR tại ngưỡng CỐ ĐỊNH** — ngưỡng chọn từ **train/dev (choco)**, **KHÔNG từ nirsoft**
   (ví dụ ngưỡng TPR95 trên dev positives). Báo FPR trên nirsoft + **Wilson CI**.
3. Báo n, số cụm, và khoảng CI thô (dự kiến rất rộng ở n=20).
KHÔNG thêm metric sau khi nhìn số.

## D. Quy tắc báo cáo
- Báo **cả kết quả tốt lẫn xấu**, gắn nhãn "holdout cuối, chạm 1 lần, cấu hình đã commit <hash>".
- Dù AUC cao hay thấp: **không chạm lại**, không đổi cấu hình/metric, không thêm seed.
- Nêu rõ CI; nếu CI quá rộng (n=20), kết luận chỉ là "không mâu thuẫn dev", không phải xác nhận mạnh.

## E. Thu thêm benign cho holdout TRƯỚC khi chạm (tăng n để CI đủ hẹp)
- Nguồn: **NirSoft** (còn nhiều tool chưa lấy), **Scoop** bucket khác, PortableApps — giữ tách khỏi train
  theo nguồn/cụm (không trùng pilot).
- **Cỡ mẫu ước lượng (thô, Hanley-McNeil / Wilson):**
  - AUC CI nửa-rộng **±0.05** quanh AUC~0.95: cần **~80–120 benign** (giả định đủ positives).
  - AUC CI **±0.07**: **~45–60 benign**.
  - FPR Wilson ±0.05 quanh FPR~5%: **~75–150 benign**.
  → Đề xuất gom holdout benign lên **~100–150 mẫu** (giữ đa nguồn, tách cụm) rồi mới chạm MỘT lần.
- Lưu ý: thêm benign cho holdout **không được** rút từ train; phải ghi manifest + hash mới trước khi chạm.

## F. Checklist chốt (người dùng duyệt)
- [ ] Biến thể BFBG: first-150 ensemble / api-density ensemble / khác
- [ ] Family positives: BumbleBee / tất cả-5-riêng
- [ ] Metric: AUC + FPR@ngưỡng-dev (đã nêu)
- [ ] Có thu thêm benign (lên ~100–150) trước khi chạm không?
- [ ] Commit cấu hình + hash, rồi mới chạm 1 lần.
