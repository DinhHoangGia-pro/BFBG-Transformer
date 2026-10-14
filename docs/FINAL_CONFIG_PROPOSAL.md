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

---
## CẤU HÌNH CUỐI (KHÓA) — 9 điểm, CONFIG_HASH `a7945f94dc33c78428faa94c582ec48477dcf3dfb1c89679efdf58172e386b1c`
Spec tất định: `docs/v3_eval_config.json` (sha256 = CONFIG_HASH ở trên). Chạm v3 MỘT lần theo đúng spec này.

1. **Holdout negatives** = v3 (166 benign), manifest `d0aae900…`. Benign-only.
2. **AUC positives** = BumbleBee holdout (262), **ghi trước, KHÔNG từ train**.
3. **Train** = v2 train_pool (ISO cap 113), **LOẠI BumbleBee** (BumbleBee là holdout family → không bao giờ trong train; xác nhận excludes_bumblebee=true). Không dùng v3 để train/chọn/tune.
4. **5 model**: metadata_rf8, graph_rf7, bag_of_tokens (model-view), **BFBG first-150 ens4**, **BFBG api-density ens4** (nhãn **UNPROVEN**, §20 không đạt).
5. **Checkpoint BFBG** = **best-val_loss** của 4 seed {101,202,303,404}; ensemble = **trung bình softmax** qua 4 seed. File: `ckpt_v2es*.pt` (first-150) / `ckpt_v2api*.pt` (api-density). KHÔNG chọn seed tốt nhất.
6. **Ngưỡng OOF** (quan trọng): **probe** → group-kfold (k=5, theo cụm, seed 20261008) **out-of-fold** trên train_pool, ngưỡng tại **TPR95 trên OOF-positives**; **BFBG** → TPR95 trên **tập cluster-validation §17** (nằm ngoài train của mỗi seed), trung bình qua 4 seed. Ngưỡng **KHÔNG lấy từ v3**. Áp ngưỡng này lên v3 để đo FPR.
7. **Metric**: CHÍNH = **FPR@ngưỡng trên v3 + Wilson CI, TÁCH THEO BIN**; PHỤ = **AUC(BumbleBee vs v3) + cluster-bootstrap CI**.
8. **Chạm một lần**: `eval_v3.py` kiểm **file khóa** `~/bfbg_benign_work/eval_v3.lock` (chứa CONFIG_HASH); nếu đã có → **từ chối chạy lần hai**. Sau khi chạy ghi lock + hash kết quả.
9. **Kế hoạch báo KẾT QUẢ XẤU** (ghi trước): báo FPR/AUC của **CẢ 5 model y như số ra**, kể cả khi: BFBG FPR cao / không bằng metadata / api-density tệ / mọi model FPR cao trên v3. **Không** đổi cấu hình/ngưỡng/model theo kết quả, **không** chạm lại, **không** thêm metric. Kết quả xấu = kết quả (đưa vào Threats-to-Validity + bài).

> Chạy v3 CHỈ khi người dùng nói "chạy". Trước đó eval_v3.py chỉ chạy `--selftest` (dữ liệu giả).

## HẠN CHẾ + QUY TẮC LỖI (ghi trước, 2026-10-14)
- **Ngưỡng BFBG nhiễu:** ngưỡng BFBG lấy từ **validation §17** (189 mẫu: **~58 benign, N positives = 131**) bằng **TPR95 trên positives** → tập nhỏ nên ngưỡng **nhiễu**. ⇒ **AUC (threshold-free) là SỐ CHÍNH**; FPR@ngưỡng chỉ phụ, báo kèm CI rộng.
- **Config GIỮ NGUYÊN** (TPR95 trên positives của val) — KHÔNG đổi, KHÔNG khóa lại CONFIG_HASH.
- **Quy tắc lỗi khi chấm v3:** nếu lỗi GIỮA CHỪNG → `eval_v3.py` **DỪNG**, ghi `~/bfbg_benign_work/eval_v3.FAILED` + traceback, **KHÔNG tự sửa rồi chạy lại**, **KHÔNG ghi lock thành công**; báo người dùng, xử lý lỗi, chỉ chạy lại khi có lệnh "chạy" mới.

## XÁC MINH run_real trên tập thay thế test_indist (2026-10-14, KHÔNG chạm v3)
- (a) **Chạy HẾT đường**: cả 5 model (meta/graph/bag/BFBG first-150/api-density) + RESULT. negs=test_indist-benign (72), positives=BumbleBee (262).
- (b) **Độ lệch raw-trích vs cache** trên cùng mẫu: feature-vector meta/graph **max|lệch| = 0.00e+00** (extract() tái lập cache y hệt); AUC: meta cache 0.990 vs raw 0.992 (lệch 0.002), graph 0.938 vs raw 0.941 (0.003) — nhiễu RF, không đáng kể.
- (c) **Hash kết quả subtest** `eval_test_indist_result.json` = `6545b56a559ebc38db3e70069ae888dced534c6ba5406f484eac35575f213bca`.
- Số subtest (chỉ xác nhận đường, KHÔNG phải v3): meta AUC 0.992 FPR 0.014 · graph 0.941/0.069 · bag 0.959/0.347 · BFBG first-150 0.886/0.375 · api-density 0.931/0.292.
- → run_real self-contained hoạt động đúng; v3 vẫn CHƯA chạm (không lock). Chạy v3 chỉ khi người dùng nói "chạy".
