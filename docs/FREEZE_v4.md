# FREEZE v4 — manifest distinct + holdout (ĐÓNG BĂNG) 2026-10-21

## Hash (tất định)
- **docs/dataset_v4_manifest.jsonl** = `05e53c1d86bd0714735a8dff932fa22ba1554c5be7cfb3fa092ed9c5e9b8e54a` — **2208 malware distinct reps**.
- **docs/dataset_v4_benign_split.jsonl** = `755a5cc81373718c331c25c52d8a399e6d431b295030c079a720ae9f6c6bf3fb` — **207 benign v4** (neg holdout, 2 nhóm tách).
- Sinh tất định: seed **20261021**, global ppdeep union-find, rep = min(sha256)/cụm, sắp theo sha256, `json.dumps(sort_keys=True)`.
  Generator: `~/bfbg_benign_work/gen_v4_distinct.py` + benign-carve script (seed 20261021, shuffle rồi chia đôi).

## Split malware (manifest khóa, 2208)
| split | n | ghi chú |
|---|---|---|
| train_pool | 1006 | train chính (distinct, non-Zeus/non-downloader, trừ BumbleBee+BODMAS-temporal holdout) |
| holdout_bumblebee | 254 | holdout họ BumbleBee |
| holdout_bodmas_temporal | 150 | holdout cross-time BODMAS (2019-20) |
| zeus_separate | 767 | Zeus-lineage — báo cáo RIÊNG (không trộn train chính) |
| downloader_separate | 31 | Nymaim/downloader — báo cáo RIÊNG |
- **LOFO:** họ một-nguồn (qakbot, carberp, latrodectus, pikabot, zloader, ramnit, spyeye, retefe) đặt `lofo_exclude=true` → loại khỏi leave-one-family-out (family ≡ source, không tách được family khỏi source).

## Neg holdout (benign v4 = 207 → HAI nhóm tách)
| nhóm | n | ghép với |
|---|---|---|
| holdout_bumblebee_neg | 103 | holdout_bumblebee (254 pos) |
| holdout_bodmas_temporal_neg | 104 | holdout_bodmas_temporal (150 pos) |
- **benign v4 cho train = 0** — toàn bộ 207 benign v4 (mới, sạch) dùng làm neg holdout; **train-benign lấy từ v1/v2 non-holdout** (không chạm v3/holdout v2).
- Carve tất định: sắp sha256, shuffle seed 20261021, chia đôi (103/104).

## Lực thống kê (cluster-bootstrap trên manifest THẬT, giả định AUC 0.90)
- Mẫu pos là distinct cluster-reps (1/cụm) → cluster-bootstrap ≈ bootstrap chuẩn.
- **holdout_bumblebee** (pos 254 / neg 103): 95% CI = [0.880, 0.941], **±0.030**.
- **holdout_bodmas_temporal** (pos 150 / neg 104): 95% CI = [0.905, 0.963], **±0.029**.
- B=3000, seed 20261021 (`roc_auc_score` trên điểm giả định μ=√2·Φ⁻¹(0.9)).

## Quy tắc đóng băng (bắt buộc tuân thủ)
1. **Holdout chạm MỘT LẦN:** holdout_bumblebee + holdout_bodmas_temporal (và neg tương ứng) chỉ chấm **đúng một lần** ở báo cáo cuối. KHÔNG tuning, KHÔNG model selection, KHÔNG chấm lặp trên các holdout này.
2. **Zeus-lineage + downloader báo RIÊNG** — không gộp vào train/metric chính.
3. **Tất định:** mọi re-sinh phải cho đúng hash trên. Không sửa manifest sau freeze; thay đổi = manifest mới (v5), không ghi đè.
4. **Nguồn/năm/lineage/stratum** recoverable từ các trường trong manifest.
5. **KHÔNG chọn mẫu theo kết quả mô hình** — tập = toàn bộ distinct reps đã lift; split theo lineage/nguồn/năm (quy tắc ghi trước §24-§26), không phụ thuộc điểm.

## HẠN CHẾ (§26.4 — threats to validity, bắt buộc ghi trong bài)
1. **BumbleBee ĐÃ DÙNG TRONG PHÁT TRIỂN** (probe §17, các pilot, quyết định split trước) → KHÔNG phải holdout "chưa từng chạm" hoàn toàn → điểm trên holdout_bumblebee **lạc quan hơn** holdout sạch; nêu rõ.
2. **holdout_bodmas_temporal GỘP confound:** nguồn (BODMAS disarm/re-arm) + năm (2019-20) + nhãn-yếu → không tách được là do cross-time / cross-source / label-noise. Diễn giải thận trọng; kèm probe source/year (§24: AUC 0.72-0.77 trong bin).
3. **Nhãn họ BODMAS yếu** (82% None trên VT; Qakbot/Carberp ~toàn None) → family attribution nhánh BODMAS kém tin cậy.
4. **raw loader/bodmas đã xóa** (`raw_status=recoverable_no_relift`) → feature đã lift sẵn; nếu cần raw phải re-extract từ MB/DATA (meta_disarm.csv) **TRƯỚC khi lift/train** — chưa thực hiện ở bước freeze này.
5. **Neg holdout bin-mismatch:** benign v4 là MSVC14 (Scoop) → khớp bin với holdout_bumblebee (MSVC14 loaders) nhưng LỆCH bin với holdout_bodmas_temporal (phần lớn MSVC≤10) → một phần tách được ở bodmas-temporal có thể do khác bin toolchain, không chỉ cross-time.
6. Mục tiêu 1.500 train chính không đạt (1.416 distinct non-Zeus; §24.3; non-Zeus banking cạn nguồn).

## Trạng thái cổng
- **CỔNG DỮ LIỆU 🔴 ĐÓNG.** Freeze v4 KHÔNG mở cổng train. Train/GRL/chấm holdout CHỈ khi DATA_EXPANSION_PLAN.md §0.1 ghi ngưỡng đã đạt.
- Freeze này: chốt manifest + hash + quy tắc. KHÔNG re-extract raw, KHÔNG train, KHÔNG xóa gì.
