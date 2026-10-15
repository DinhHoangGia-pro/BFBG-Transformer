# Gradient-reversal (toolchain-invariant) design — PRE-REGISTERED

Design only (phần thiết kế dưới GIỮ NGUYÊN); **ask the user before any training run.**

## Run thăm dò biến thể 1 — BỊ DỪNG SỚM (2026-10-15)
- **Trạng thái: DỪNG BẰNG TAY bởi người dùng** (`systemctl --user stop bfbg-grl.service`, 07:56:32).
  Không phải lỗi code, không phải crash, không phải gate-fail.
- **Đã chạy:** ~13 phút 51 giây wall; hoàn tất **epoch 0** (`det_loss=0.5061 adv_loss=1.5499
  val_loss=0.5033 lambda=0.245 t=616s`), đang vào epoch 1 thì bị dừng. systemd ghi `8G memory peak`
  (chạm cap `MemoryMax=8G`). **KHÔNG sinh result JSON** (`grl_v1_s101.json`/`grl_v1_s202.json` không có).
- **Holdout:** run chỉ dùng `train_pool` + `holdout_family_bumblebee` (positives) + `holdout_source_chocolatey`
  (dev negatives). **KHÔNG chạm v3 benign, KHÔNG chạm holdout v2 (nirsoft)** — xác nhận trong `grl_run.py`
  (không nạp v3/nirsoft; chỉ 3 split trên).
- **Lý do dừng (theo người dùng):** chạy quá sớm khi **dữ liệu chưa đủ** — chưa có benign khớp-confound
  (toolchain×size, xem `HOLDOUT_V4_MATCH_ESTIMATE.md` + `DATA_EXPANSION_PLAN.md`), nên bất-biến đo trên split
  hiện tại sẽ lẫn với lệch phân phối nguồn/kích thước. Thu thập dữ liệu trước, chạy GRL sau.
- **KẾT QUẢ DỞ DANG KHÔNG DÙNG LÀM BẰNG CHỨNG.** 1 epoch, không có AUC chéo nguồn, không có linear-probe,
  không có recall-theo-bin → không báo cáo bất kỳ con số nào từ run này. Gate (mục dưới) **chưa áp dụng**
  vì run chưa hoàn tất; đây **không** phải kết quả "không đạt".

---

Design only. No training is started; **ask the user before any training run.**

## Architecture change
- Base: the existing BFBG hierarchical graph-transformer; program embedding = `pooled_program`
  (128-d, the input to `fc1`, with `num_global_features=0`).
- Add a **domain-adversarial head** with a Gradient Reversal Layer (GRL, DANN-style):
  `pooled_program --GRL(lambda)--> MLP(128->64->K)` predicting the **toolchain bin** (K=7).
  Optionally a second GRL head predicting **family** (5 classes, malicious only) with its own weight.
- Detector head (`fc1->fc2`) is unchanged. Semantic/seed branch unchanged.

## Training objective
`L = CE_detect + lambda_sem * BCE_sem  -  (adv is handled by GRL sign flip)`,
with the adversary trained to predict toolchain and GRL multiplying its gradient by `-lambda_grl`
into the shared embedding. Schedule `lambda_grl` with the usual DANN ramp
`lambda_grl(p) = 2/(1+exp(-gamma*p)) - 1`, `gamma=10`, `p` = training progress in [0,1];
cap `lambda_grl <= lambda_max` (start `lambda_max=1.0`, also try 0.3).
Keep section-17 schedule otherwise (early stopping on val loss, grad-clip 1.0, 4 seeds per config).

## Positions / variants to try (one change at a time)
1. GRL on `pooled_program` (program-level), toolchain adversary only.
2. + family adversary (separate weight).
3. + **learned function selection** (replace first-150; e.g. top-k by a learned saliency or the
   API-density selector already measured) — run only after (1) is characterised.

## Pre-registered SUCCESS criteria (both must hold; written before the run)
- **(A) Invariance:** a cluster-CV linear probe on the (frozen) post-GRL embedding predicts
  **toolchain near chance** and **family near chance**, where "near chance" = within +0.05 accuracy
  of the majority-class baseline, for BOTH toolchain and family.
- **(B) Utility preserved:** cross-source detection AUC (BumbleBee positives vs dev/choco negatives,
  and vs v3 negatives) **does not drop by more than 0.03 AUC** relative to the non-adversarial BFBG
  ensemble (first-150) on the same split.
- Report mean +/- std over **>=4 seeds**; per-seed paired deltas. If (A) holds but (B) fails (AUC
  drops > 0.03), the method fails the utility bar; if (A) fails, invariance is not achieved -> rename
  per PAPER_OUTLINE_MODEL.md.
- choco stays the development set; v3 is touched only under its existing one-shot lock rules.

## GPU / time estimate (NOT run)
- Per seed: BFBG training was ~2h30--3h20 (section 17). Adding a small GRL head + adversary is a minor
  compute overhead (one extra MLP + one backward path); estimate **~3--4h/seed**.
- Variant (1): 4 seeds ~ **12--16h**. Variants (1)+(2): ~**24--32h**. Variant (3) adds a selection
  pass (feature re-read) ~ +several h. Plus the invariance linear-probe eval (~30--60 min, CPU-ish).
- Thermal: CPU-heavy feature loading hits ~100C on this machine (user handles cooling); guard is
  report-only per prior runs.

## What is needed before training
- Confirm GRL variant order and `lambda_max`.
- Confirm the invariance/utility thresholds above (0.05 near-chance margin; 0.03 AUC drop bar).
- Decide whether to collect a confound-matched v4 first (HOLDOUT_V4_MATCH_ESTIMATE.md) or evaluate
  invariance on existing splits.
- Explicit "train" instruction (long run > 30 min requires approval).

## "Không đạt" là kết quả HỢP LỆ (ghi trước 2026-10-15)
- Nếu biến thể 1 KHÔNG đạt gate (linear-probe toolchain KHÔNG giảm vào trong 0.05 của majority-chance,
  HOẶC AUC dev giảm > 0.03 so BFBG không-adversarial cùng seed) → **DỪNG, báo, KHÔNG chạy biến thể 2--3**.
- Kết quả "không đạt" là hợp lệ và được báo cáo thẳng; khi đó **bài QUAY VỀ tên/định hướng audit**
  ("A Shortcut-Aware Evaluation Protocol and Benchmark ..."; PAPER_OUTLINE_B.md) — tên "Toolchain-Invariant"
  chỉ giữ nếu gate đạt.
- Run thăm dò: biến thể 1 (GRL trên pooled_program, adversary toolchain), lambda_max=1.0, 2 seed
  {101,202}, fold BumbleBee, dev choco, §17 early-stop, trần 8h. Báo: AUC chéo nguồn, linear-probe
  toolchain/family (CV cụm) + majority-chance, recall theo bin. KHÔNG chạm v3/holdout v2.
