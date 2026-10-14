# Đề xuất cấu hình cuối cho lần CHẠM holdout v3 DUY NHẤT (bản nháp — CHƯA chốt, CHƯA chạy)

> Holdout cuối = **v3 (166 benign)** đã đóng băng: manifest SHA256 `d0aae900…835bade2` (FREEZE_v3).
> Chạm **MỘT lần**. Mọi lựa chọn phải được **người dùng duyệt + commit** TRƯỚC khi chạm;
> sau khi chạm **báo cả tốt lẫn xấu, không chạm lại, không tinh chỉnh theo kết quả**.
> (holdout_v2_nirsoft 20 cũ giữ riêng; v3 đã dedup vs nó — xem FREEZE_v3.)

## A. Mô hình đem so (ghi trước, cùng train set đã khóa) — SO CẢ 5
1. **metadata probe** (RF 8 scalar).
2. **graph probe** (RF 7 scalar).
3. **bag-of-tokens** (TF-IDF + RF; nêu rõ BoT-full hay model-view, FREEZE/reproduce).
4. **BFBG first-150** — §17 **ensemble 4 seed** {101,202,303,404} (trung bình xác suất; KHÔNG chọn seed tốt nhất).
5. **BFBG api-density** — §17 ensemble 4 seed. **Gắn nhãn "ứng viên CHƯA chứng minh"** (§20 không đạt: 0.951<0.976).
- Tất cả train trên **v2 train_pool (ISO cap 113)** đã khóa; **KHÔNG dùng v3 để train/chọn/tune**.

## B. Positives cho AUC (v3 benign-only)
- v3 (166) = **negatives**. Positives = **BumbleBee holdout (holdout_family_bumblebee, 262)** — ghi trước,
  **nguồn rõ, KHÔNG từ train**. (Tùy chọn công bố thêm từng family 5 nhóm, ghi trước.)

## C. Metric (ghi trước)
1. **FPR là chính** (v3 benign-only): **ngưỡng CỐ ĐỊNH chọn từ TRAIN** (vd TPR95 trên train positives của từng model),
   **KHÔNG từ v3/dev**. Báo **FPR trên v3 + Wilson CI**, và **FPR TÁCH THEO BIN** (MSVC≤10/MSVC14/GNU/Go/Delphi/khác).
2. **AUC(BumbleBee vs v3)** + **cluster-bootstrap CI** (cụm; v3 chủ yếu singleton).
3. Báo n theo bin, số cụm, CI (MSVC14 n=41 → CI rộng; một số bin n nhỏ).
- KHÔNG thêm metric sau khi nhìn số. Một ngưỡng/model, ghi trước.

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
