# PAPER_OUTLINE_EVAL — Static PE banking-trojan detection: evidence, audit, outline
_Dev / post-hoc working document. 2026-10-23. Dataset khóa: `dataset_v4_manifest.jsonl` SHA256 `05e53c1d86bd0714735a8dff932fa22ba1554c5be7cfb3fa092ed9c5e9b8e54a`, git tag `freeze-v4`._

Tất cả số dưới đây: val **in-dist cố định 209** (phân tầng) hoặc **LOFO test fold**, cluster-bootstrap 95% CI (mẫu distinct → bootstrap ~ cụm). Global features model = 0 → **không `vex_vocab_size`** (artifact, xem Pitfall P3). Nhãn: **dev, post-hoc** (chưa chốt báo cáo cuối; holdout CHƯA chạm).

## 0. Tên đề xuất (3 phương án)
1. **"When Simple Features Win: A Confound Audit of Graph-Transformer Banking-Trojan Detection"** — nhấn kết quả âm + audit.
2. **"Provenance Shortcuts in Static PE Malware Detection: A Reproducible Leave-Family-Out Benchmark"** — nhấn benchmark + shortcut.
3. **"BFBG-Transformer under Scrutiny: Honest Baselines and Source/Size Confounds for Windows Banking Trojans"** — nhấn mô hình + tính trung thực.

## 1. Bảng bằng chứng (mỗi bảng: script · nhãn)

### E1 — Learning curve in-dist (BFBG vs baseline rẻ, cùng split)
_script: `~/bfbg_benign_work/{lc_train,probe_curve,bfbg_rescore_embed}.py` · TRAINING_DESIGN §21d-§21e · dev/post-hoc_
| fraction (n_train) | BFBG (last-ep) | metadata-RF | graph-RF | bag-tokens |
|---|---|---|---|---|
| 0.25 (295) | 0.842 | 0.922 | **0.929** | 0.765 |
| 0.50 (592) | 0.880 | 0.947 | **0.954** | 0.781 |
| 1.00 (1184) | 0.913 | 0.956 | **0.966** | 0.790 |
→ **graph/metadata-RF VƯỢT BFBG ở mọi fraction.** Learning curve BFBG chưa bão hòa (bước +0.027/+0.034 > nhiễu-seed 0.012; §21d).

### E2 — LOFO SẠCH cross-family, họ IcedID-lineage (encoder không thấy họ)
_script: `~/bfbg_benign_work/lc_lofo.py` · TRAINING_DESIGN §26 · dev/post-hoc · test = IcedID 197 + benign 59_
| mô hình (cùng fold) | AUC | CI cụm 95% |
|---|---|---|
| **BFBG (leave-encoder-out, 20ep)** | **0.673** | [0.590, 0.749] |
| metadata-RF | **0.915** | [0.874, 0.950] |
| graph-RF | 0.909 | [0.868, 0.946] |
| bag-tokens | 0.636 | [0.558, 0.708] |
→ BFBG thua baseline rẻ ~0.24 (CI không chồng). **Chỉ 1 họ, 1 seed, 20ep chưa hội tụ → 0.67 là cận dưới** (§26a).

### E3 — Probe provenance trên embedding BFBG (mô hình có mã hóa nguồn/năm?)
_script: `~/bfbg_benign_work/{prov_probe,emb_only}.py` · TRAINING_DESIGN §21e-§21f · dev/post-hoc_
| đo | embedding | metadata | graph | bag |
|---|---|---|---|---|
| nguồn mb-vs-v1 within-IcedID (1 họ) | 0.76 | — | — | — |
| provenance năm-trong-họ, TB 4 họ | **0.732** | 0.688 | 0.697 | 0.809 |
→ Embedding mã hóa provenance vừa phải (0.73), **không hơn** feature rẻ, **thấp hơn bag-tokens**; CI rộng. Ngưỡng GRL (<0.75) nhạy với định nghĩa.

### E4 — Confound holdout (chưa chạm để chấm; probe provenance)
_script: probe nội tuyến · FREEZE_v4 §C · dev/post-hoc_
| holdout | probe metadata/static AUC | ý nghĩa |
|---|---|---|
| holdout_bumblebee | 0.998 (PE-metadata) | neg Scoop vs pos BumbleBee tách gần hoàn toàn bằng import/CRT |
| holdout_bodmas_temporal | 0.896 (static, bỏ vex) | tách bằng size/complexity trùng nguồn |
→ Holdout bị source-confound nặng → điểm holdout là **cận trên lạc quan**; chạm **một lần** sau khi khử confound (GRL).

## 2. Đóng góp (trung thực)
1. **Dataset v4 tất định, có hash** (`freeze-v4`): split theo lineage, phân tầng nguồn/năm, benign khớp bin, holdout cô lập; raw recoverable. Tái lập được.
2. **Audit confound/pitfall có hệ thống** cho static PE detection (toolchain-bin, source/year, artifact pipeline, frozen-embedding inflation) — xem §3.
3. **Baseline rẻ mạnh trên CÙNG split** (6-feature RF, bag-tokens) + **giao thức LOFO sạch** (leave-encoder-out) + learning curve + cluster-bootstrap CI.
4. **Kết quả âm/robustness tiền-đăng-ký:** graph-transformer **chưa vượt** RF 6-feature in-dist (mọi fraction) và cross-family (họ IcedID, 20ep) — với ngưỡng ghi trước.
5. **Thiết kế GRL khử-nguồn tiền-đăng-ký** (adversary = stratum nguồn/năm, class-wise; tiêu chí probe<0.70 & val drop≤0.03) cho công việc tiếp theo.

## 3. Pitfalls đã bắt được (nhật ký trung thực)
- **P1 tc_bin bug:** `pefile.PE(fast_load=True)` không parse Rich → MSVC yêu-cầu-Rich-hoặc-CRT bỏ nhầm malware pack → MSVC14 đếm thiếu (15). Sửa LINKER-PRIMARY (DATA_EXPANSION_PLAN §15-§16).
- **P2 source-probe sai kết luận:** AUC<0.5 cross-family = **bất ổn**, không phải "không lộ nguồn"; sửa thành per-family OOF-by-cluster (0.63-0.995) (§23 plan).
- **P3 artifact `vex_vocab_size`:** khác theo batch-lift (420-425 / 587-588 / 588 / 573) → tách nguồn AUC=1.0 **giả**. Loại khỏi mọi feature/model. Sửa bodmas-holdout 0.994→0.896; source-probe 1.0→0.42/0.79 (FREEZE_v4 §D-§E).
- **P4 frozen-embedding LOFO thổi phồng:** encoder đã train trên họ "để ngoài" → frozen IcedID 0.934 **giả cross-family**; LOFO-retrain sạch chỉ 0.67 (§24→§26).
- **P5 ISO 39.2% > cap 35%:** subsample loader giữ 138/166 (seed 20261021) → 34.9% (FREEZE_v4 §F).
- **P6 BODMAS disarm:** Machine=0/Subsystem=0 → phải re-arm trước angr.
- **P7 mẫu-số lẫn:** 675(raw) vs 437/528/540(distinct-incl-holdout) vs ~297-305(eval pos) — thống nhất (DATA_EXPANSION_PLAN §25).
- **P8 split-bug Zeus-lineage:** `lin=='Zeus'` trượt (chuỗi 'Zeus-lineage') → sửa `'Zeus' in lin`.

## 4. Hạn chế (threats to validity)
- **Mô hình chưa vượt baseline rẻ** ở in-dist (mọi fraction) và cross-family (1 họ, 20ep) → tuyên bố accuracy không giữ được; chỉ còn hướng robustness/khử-shortcut (chưa chứng minh).
- **Cross-family: chỉ 1 họ (IcedID), 1 seed, 20ep CHƯA hội tụ** → 0.67 là cận dưới; không tổng quát; cần nhiều họ + nhiều seed + train hội tụ.
- **val in-dist = cận trên lạc quan** (base, chưa GRL, source-confound).
- **Dữ liệu:** train chính 1416 distinct, non-Zeus banking cạn nguồn; learning curve chưa bão hòa → có thể thiếu dữ liệu.
- **Holdout bị confound** (BumbleBee dev-used; BODMAS gộp nguồn+năm+nhãn-yếu; neg toàn Scoop bin-mismatch) → chạm một lần, diễn giải thận trọng.
- **GPU 8GB** → BATCH=2, vài batch OOM bị bỏ (~1/epoch) → val chấm ~208/209.
- **benign v4 = 0 trong train** (toàn bộ làm neg holdout); train-benign từ v1/v2.

## 5. Bước tiếp đề xuất (chưa chạy, chờ duyệt)
- (a) LOFO sạch họ 2-3 (Gozi, Tinba) + ≥2 seed + train tới hội tụ → kết luận cross-family vững.
- (b) GRL khử-nguồn (§22) nếu muốn theo hướng robustness; tiêu chí tiền-đăng-ký đã ghi.
- (c) Chỉ chấm holdout MỘT LẦN sau khi (a)/(b) đạt tiêu chí.
