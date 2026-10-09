# Thiết kế src/training/ (CHƯA viết code — bản thiết kế)

Dựa trên các probe/kiểm chứng (Phần A, Task 1–5, 2026-10). Ràng buộc rút ra từ dữ liệu:
seed-rule và metadata **bị confound mạnh với bin toolchain** (T1497 ≈ nhãn MSVC14; benign-ISO fire T1547 cao hơn malware trong cùng bin); loader cũ nạp toàn bộ JSON → **OOM 26GB**. Thiết kế phải xử lý cả hai.

## 1. Loader — STREAMING, bộ nhớ hằng số
- Đọc `docs/dataset_v1_manifest.jsonl` (sha, label, source, split, cluster) làm chỉ mục; **KHÔNG** nạp toàn bộ JSON.
- `Dataset.__getitem__` nạp **một** `features_graph/<sha>_static.json`, dựng `torch_geometric.Data` (node = token embedding, edges_cfg/edges_seq nội hàm, call graph liên hàm), rồi giải phóng. Collate theo batch.
- Lý do: lesson OOM — giữ bộ nhớ ~một mẫu/worker; không `[json.load(...) for all]`. Dùng `num_workers` nhỏ + `MemoryMax` ở runner (xem `run_build_batch.sh`).

## 2. Split — group-aware theo cụm near-dup (đóng băng v1)
- Dùng field `split` đã đóng băng: `train_pool` / `test_indist` / `holdout_family_bumblebee` / `holdout_source_chocolatey`. **Không tự chia lại** v1.
- Val: **k-fold group-aware** TRÊN `train_pool`, nhóm = `cluster` (near-dup) **và** vendor/source; **không bao giờ** tách một cụm qua train/val. (Cụm từ `near_duplicate_clusters.jsonl` / field `cluster`.)
- Hai holdout là **một chiều** → khi đánh giá ghép mẫu đối nhãn từ `test_indist` (ghi caveat phân phối, xem DATASET.md).

## 3. Weights theo bin toolchain (chống confound)
- Mỗi mẫu gắn `toolchain_bin` (bộ phân loại đã kiểm: Rich/linker + section + CRT; **không** nhãn "Rust?"; GNU chỉ khi `.eh_frame`/mingw).
- **Loss weight = nghịch tần suất bin** (reweight) để model không tách lớp bằng bin (vì benign v1 lệch MSVC14, malware trải MSVC≤10+14). Tùy chọn: thêm **domain-adversarial** trên bin (để sau).
- Lý do: Task 1 cho thấy trong cùng bin MSVC14, malware và benign fire T1497 ngang nhau → nếu không reweight, model dễ học "bin" thay vì "hành vi".

## 4. Báo cáo — THEO BIN và THEO NGUỒN, kèm holdout
- Mọi metric (AUC, FPR+Wilson/cluster-bootstrap, recall) báo **phân tầng theo toolchain-bin** và **theo nguồn**.
- **Bắt buộc** báo trên: `test_indist`, `holdout_source_chocolatey` (FPR chéo nguồn), `holdout_family_bumblebee` (recall cross-family). CI dùng **cluster-bootstrap** (Task 3: CI cụm rộng hơn Wilson, trung thực hơn khi có near-dup).

## 5. Đầu vào head — KHÔNG gồm global_features
- `num_global_features = 0`: head = `pooled_program` (TransformerConv call graph) **mà thôi**, bỏ `global_features` (entropy toàn cục, has_any_external_call).
- Lý do: entropy/size là **confound nguồn** (Phần A: metadata-only AUC 1.0 in-dist nhưng FPR 53% chéo nguồn; Task 2 bỏ entropy+packed giảm FPR choco 18→9%). Giữ entropy **chỉ như một ablation** riêng, không phải input mặc định. (Eq.16 nêu 2 global feature nhưng code đặt 4 → chưa định nghĩa; quyết định: bỏ hẳn.)

## 6. So sánh với baseline probe (để chứng minh BFBG hơn confound-exploiter)
Báo BFBG cạnh hai baseline đã đo, trên CÙNG holdout:
| model | AUC test_indist | FPR holdout_choco | FPR/recall holdout khác |
|---|---|---|---|
| **metadata-only** (RF, linker/year/entropy…) | 1.000 | **53%** | — (confound thuần) |
| **graph-feature** (RF, num_func/api/imports/size/entropy/packed/nodes) | 0.976 | 18% (bỏ entropy+packed: 9%) | FPR NirSoft 35% |
| **BFBG (đề xuất)** | *đo khi train* | *mục tiêu < graph-probe* | *đo trên bumblebee/choco/nirsoft* |
- **Claim chỉ đứng vững nếu BFBG đạt FPR chéo-nguồn THẤP HƠN graph-probe** (tức học cấu trúc BFBG, không chỉ lặp lại confound toolchain/entropy mà baseline đã khai thác). Nếu không hơn → phải hedge claim (xem 3 phương án trong DATASET.md).

## 7. Hiệu chỉnh (Task 4, 2026-10)
- **Clip trọng số theo ô (bin × nhãn):** weight = nghịch tần suất ô, nhưng **clip** vào [0.25, 4.0] (tránh ô hiếm như benign-MSVC≤10 n=13 làm nổ gradient). Ghi rõ hệ số clip.
- **Loại ô thiếu lực khỏi loss:** ô có **< N benign** (đề xuất N=30) **không đưa vào loss train** và được đánh dấu **"không đủ lực (underpowered)"** trong báo cáo thay vì cho điểm. (Hiện benign-MSVC≤10 train=13 < 30 → underpowered.)
- **LOFO 5 family:** thay holdout BumbleBee đơn lẻ bằng **leave-one-family-out** (train 4 family, test family thứ 5; lặp 5 lần), báo 5 kết quả — vì toolchain-bin ≈ proxy family (DATASET.md), một holdout đơn lẫn tín hiệu.
- **Tiêu chí THẮNG ghi trước (pre-registered):** BFBG "thắng" nếu **FPR@TPR=0.95 trên holdout_source_chocolatey (và trung bình LOFO) THẤP HƠN graph-probe ≥ 5 điểm phần trăm tuyệt đối** (khoảng cluster-bootstrap không chồng), đo trên **cùng split/CV**. Nếu không → hedge claim (3 phương án DATASET.md). Test chính: `holdout_source_chocolatey` (FPR) + LOFO (recall@FPR).
- **Chẩn đoán đường tắt (shortcut):** (i) **train-trong-bin** (chỉ MSVC14): nếu BFBG vẫn tách được malware/benign trong một bin thì không chỉ học toolchain; (ii) **dự đoán toolchain từ embedding**: train một linear probe trên embedding BFBG để đoán toolchain-bin — nếu đoán tốt (acc cao) thì embedding đang mã hóa toolchain (đường tắt), phải báo và điều chỉnh.

## 8. Sửa SAU KHI thấy baseline probe (2026-10)
Baseline đo được trên CÙNG split (FPR@TPR95, bootstrap≈Wilson sau khi sửa bug cluster):
metadata — choco FPR **8.9%** [3.5,20.7], BumbleBee recall **53%**; graph — choco FPR **17.8%** [9.3,31.3], BumbleBee recall **94%**.

- **(a) Tiêu chí thắng HAI VẾ, so với CẢ hai probe:** BFBG phải (i) **recall cross-family (LOFO/BumbleBee) ≥ graph-probe** (graph đã 94% — đây là phép khó mà metadata gục 53%) VÀ (ii) **FPR chéo-nguồn (choco + NirSoft-holdout) ≤ min(metadata, graph)**. Thắng = hơn ở (i) mà không tệ hơn ở (ii) so với **cả metadata lẫn graph**.
- **(b) BỎ điều kiện "CI không chồng", thay bằng PHÂN TÍCH LỰC:** để phát hiện chênh 5pp FPR (vd 18%→13%) ở power 80%, α=.05 cần **~800 mẫu âm/nhóm** (two-proportion). Holdout_choco n=45 → **không đủ lực cho 5pp** (chỉ phát hiện ~20pp). ⇒ hoặc tăng benign holdout lên ~800, hoặc **báo MDE thực tế theo n** thay vì đòi CI rời nhau. Ghi rõ n và MDE mỗi test.
- **(c) NirSoft dư làm source-holdout THỨ HAI:** NirSoft cap ≤35% bin MSVC≤10 cho train; **phần dư giữ nguyên làm holdout nguồn thứ 2** (song song choco) → hai phép FPR chéo-nguồn độc lập (choco=đa-vendor, NirSoft=một-vendor cũ).
- **(d) Đặc tả LOFO:** 5 fold, mỗi fold train 4 family + toàn bộ benign train; **ngưỡng @TPR95 đặt trên validation của CÁC family train** (không nhìn family test); **negative mỗi fold = benign test_indist** (ghi caveat phân phối). Báo recall@ngưỡng cho family bị giữ + trung bình 5 fold.
- **(e) Phân tích CHÍNH = train TRONG bin MSVC14** (mal-MSVC14 vs ben-MSVC14, loại confound toolchain ở gốc; n mal 565 / ben 204, ben-non-ISO 42 kèm CI); **phân tích PHỤ = train toàn bộ** (reweight theo bin). **Báo CẢ HAI** — nếu chỉ thắng ở "toàn bộ" mà thua "trong bin MSVC14" thì tín hiệu là toolchain, không phải hành vi.

## 9. Sửa về kiểm định & phân tích chính (2026-10, sau khi xem lực mẫu)
- **(a) Vế recall — kiểm định GHÉP CẶP trên CÙNG mẫu (paired bootstrap theo cụm)** thay cho "~800 mẫu âm" (vốn là two-proportion độc lập). Hai model dự đoán trên **cùng** tập dương (BumbleBee n=262 / LOFO) → so **hiệu recall per-sample**, resample theo CỤM near-dup (B≥2000), báo phân phối hiệu + CI. Ghép cặp mạnh hơn nhiều: **MDE recall ở n=262 ≈ ~5pp** (so ~12pp nếu không ghép), tùy mức đồng thuận hai model (ghi kèm số cặp bất đồng).
- **(b) Vế FPR chéo-nguồn — UNDERPOWERED:** holdout_choco n=45 (+ NirSoft-holdout), **chỉ báo FPR kèm khoảng tin cậy (bootstrap+Wilson), KHÔNG dùng làm tiêu chí pass/fail**; chỉ để quan sát xu hướng cho tới khi v2 tăng benign holdout.
- **(c) LOFO chỉ báo RECALL** (family giữ ra chỉ có mẫu dương); **FPR đo RIÊNG trên holdout benign** (choco + NirSoft), không trộn vào LOFO.
- **(d) Phân tích CHÍNH = train TRONG bin MSVC14 (số thật, ĐÁNH DẤU underpowered):**
  - train: malicious MSVC14 `train_pool` = **274** vs benign MSVC14 **non-ISO** `train_pool` = **15** (python-embeddable 10, notepad++ 5).
  - test: test_indist MSVC14 — malicious **40** / benign non-ISO **3**.
  - negative = benign MSVC14 non-ISO (loại ISO để bỏ confound một-nguồn).
  - ⚠️ **benign non-ISO MSVC14 quá ít (train 15 / test 3) → phân tích chính hiện UNDERPOWERED**; chỉ chạy được khi v2 bổ sung benign non-ISO MSVC14. Trước đó dùng phân tích phụ (train toàn bộ + reweight) làm tham chiếu, luôn báo kèm cảnh báo lực.

## 10. Smoke train — chi tiet (2026-10)
- **Chon 400 mau:** `random.seed(42)` shuffle `train_pool` (1091) → lấy 400 đầu (tái lập được). Batch 2, 3 epoch, GPU, global_features=0.
- **Số hàm & tiêu chí CẮT:** cap `max_functions_per_sample` = 100 (smoke) → lấy **100 hàm đầu theo thứ tự addr** mỗi program; **318/400 (80%) bị cắt** (#func RAW med=744, p75=1753, max=28168). Mỗi hàm: chuỗi token-node cắt tại `max_len=512` trong TokenSequenceTransformer (max node/func med=360, max=71683). ⇒ phần lớn malware lớn **mất đa số hàm** ở cap 100 — cần cân nhắc cap cao hơn / lấy mẫu hàm khi train thật.
- **Loss vs entropy prior:** smoke cuối = **0.281**; prior CE lệch-lớp (train_pool ~84% malicious) ≈ **0.44**, prior cân bằng = ln2 = **0.693**. 0.281 < cả hai → **học thật sự vượt prior** (không chỉ đoán lớp đa số).
- **Batch size theo bộ nhớ:** batch **2** chạy ổn trong cap RAM 8G + GPU 8GB (RTX 2080). Yếu tố giới hạn = **padding của token transformer** (pad mọi hàm trong batch tới max node-count ≤512). Khuyến nghị batch 2–4 kèm cap max_funcs; batch lớn hơn nên **sort theo kích thước** hoặc giảm max_funcs để tránh OOM trên mẫu nhiều hàm lớn.

## 11. Vocab & token mode (2026-10, ĐÓNG BĂNG)
- **Chế độ token = INSTRUCTION (insn)**, khớp `configs/model.yaml: model.tokenizer_mode=insn` và token mà `bfbg_builder` ghi (vd `mov_reg_mem`). `data/vex_vocab.json` là **VEX-mode (cũ, 497 token) → gây UNK 100%** khi dùng cho node insn ⇒ **deprecated cho training**.
- **Vocab training ĐÓNG BĂNG:** dựng từ `train_pool` bằng `src/training/build_vocab.py` → `data/insn_vocab_v2.json` (gitignore; tái tạo tất định từ split v1 đã khóa). **size = 1322**, **SHA256 = `af69e190e0c9eed0e39b8b30fc88238b6389fe5033222d4aa00c45c83f9d1bc8`**. Token phổ biến nhất: mov_reg_mem, mov_reg_reg, call_imm, push_reg, lea_reg_mem… `<UNK>`=0. Mọi train/eval BFBG dùng vocab này (không rebuild per-run).

## 12. Metric chính = AUC threshold-free (bản sửa lần 2, 2026-10)
Sau LOFO: ngưỡng OOB@5% không ổn định giữa fold (Emotet thr bão hòa 1.0 → FPR_choco 0% giả, recall≈0). ⇒
- **Tiêu chí CHÍNH = AUC threshold-free** (family giữ-lại vs benign holdout), kèm cluster-bootstrap CI. Báo riêng AUC vs choco, vs NirSoft-dư (khi có), vs test_indist (n=34, ghi rõ n nhỏ).
- **FPR@ngưỡng-OOB là CHỈ SỐ PHỤ**, chỉ đọc **tương đối giữa các mô hình trên cùng fold/cùng ngưỡng**, không coi là tuyệt đối (artifact bão hòa).
- Phụ trợ: **recall@FPR cố định {1,5,10}%** trên benign holdout của fold (threshold-free theo nghĩa quét FPR).
- Baseline graph hiện tại (AUC vs choco): Emotet 0.81 (yếu nhất) → Dridex 0.94; BFBG phải **vượt AUC-vs-choco của graph trên fold yếu (Emotet/IcedID)**, không chỉ in-dist.

## 13. Subsample ISO ở loader (v2, 2026-10-08)
v2 train benign = 351 (ISO 141 = 40% > cap 35%). **Cap ÁP Ở LOADER, không sửa manifest:**
- Mỗi epoch: giữ **K=113 ISO** (để K/(non_ISO 210 + K) ≤ 0.35), **drop 28 ISO** còn lại.
- **Seed cố định** cho phép chọn: `random.Random(20261008 + epoch)` (tái lập, nhưng đổi tập drop mỗi epoch để không bỏ hẳn 28 mẫu). Tùy chọn thay bằng **inverse-weight** nguồn (ISO weight = 113/141) nếu không muốn drop.
- Số thật tính từ v2 manifest `e2e2c67a` (không ước lượng). Non-ISO train = 210; MSVC≤10 train 55.

## 14. Quy tắc loại mẫu num_functions=0 (áp CHUNG hai phía, 2026-10-08)
Mẫu có `num_functions==0` (angr/CFGFast không trích được hàm → đồ thị rỗng) **bị loại ở loader cho CẢ benign lẫn malicious**, không phân biệt nhãn, để tránh thiên lệch một phía.
- Kiểm kê hiện tại (chỉ benign bị dính, 0 malicious):
  - v1: 2 mẫu (label0): chocolatey 1, windows11-eval-iso 1.
  - v2: 4 mẫu (label0): chocolatey 1, scoop 2, windows11-eval-iso 1.
- Loại ở loader (BFBGDataset→collate trả None→bỏ batch), KHÔNG sửa manifest; đếm số bị loại ghi vào log mỗi lần chạy. Áp cho mọi split khi dùng BFBG. Probe RF vẫn có vector đặc trưng cho các mẫu này; khi so sánh ghép đôi thì bỏ chúng khỏi tập chung để 3 model cùng mẫu.

## 15. Quy tắc chọn số epoch (ghi trước, 2026-10-08)
- **Số epoch CỐ ĐỊNH = 20** (ghi trong config, `training.epochs`). KHÔNG early-stopping, KHÔNG dùng validation/choco để chọn epoch.
- Validation theo cụm (carve từ train_pool, seed 20261008) chỉ để **chẩn đoán overfit** (vẽ val-AUC theo epoch); tuyệt đối không dùng để chọn epoch, tune siêu tham số, hay chọn mô hình.
- choco (holdout_source_chocolatey) là tập đánh giá cuối, KHÔNG dùng cho bất kỳ lựa chọn nào.
- Nếu sau này đổi sang chọn epoch theo validation: phải ghi trước quy tắc (vd. epoch có val-AUC cao nhất trong 20, tie-break epoch nhỏ hơn) TRƯỚC khi nhìn kết quả, và đóng băng lại.

## 16. Số seed tối thiểu & tiêu chí báo cáo cho mọi so sánh BFBG (2026-10-08)
Bằng chứng pipeline-check cho thấy AUC(BumbleBee vs choco) của BFBG dao động 0.680–0.884
chỉ do đổi seed (graph/metadata probe ổn định). Do đó:
- **Mọi so sánh liên quan BFBG PHẢI dùng ≥5 seed** (model init + shuffle). Một-seed bị CẤM làm cơ sở kết luận.
- **Báo cáo bắt buộc:** trung bình ± độ lệch chuẩn qua các seed; VÀ hiệu ghép đôi (BFBG−probe) tính RIÊNG TỪNG seed rồi tổng hợp (trung bình ± std, hoặc khoảng), không gộp điểm.
- CI cho mỗi seed vẫn là cluster-bootstrap; nhưng kết luận dựa trên phân bố qua seed, không dựa tron một seed may/rủi.
- Seed cố định, ghi trước danh sách seed TRƯỚC khi chạy; không chọn seed sau khi xem kết quả.

## 17. Lịch huấn luyện có early-stopping (POST-HOC, thay §15 cho RUN MỚI; 2026-10-09)
Nhãn POST-HOC: áp cho các run mới sau freeze-v2, KHÔNG sửa design đã khóa. Thay §15 (epoch cố định 20)
cho những run dùng lịch này; các kết quả §15 cũ giữ nguyên.
- **max_epochs = 40** (trần, KHÔNG phải 20 cố định).
- **Theo dõi val_loss** trên **validation theo cụm trong train_pool** (cross-entropy). KHÔNG dùng choco,
  KHÔNG dùng holdout_nirsoft. val-AUC chỉ ghi kèm (không dùng để dừng).
  - Tách validation: 15% theo cụm (group_key near-dup), seed 20261008. Với v2 (sau ISO cap 113):
    val n=189, **benign=58 (≥40 → không cần tăng)**. Train còn 1049.
    Nếu một cấu hình khác cho <40 benign thì tăng dần phần validation (theo cụm, cùng seed) tới ≥40.
- **Cải thiện** = val_loss giảm ≥ **min_delta=0.002** so với tốt nhất từ trước.
- **ReduceLROnPlateau**: 5 epoch liên tiếp không cải thiện → lr *= 0.5; **tối đa 2 lần** giảm.
- **Early stop**: 10 epoch liên tiếp không cải thiện → dừng, **nạp lại checkpoint tốt nhất theo val_loss**.
- **Bỏ cosine**; giữ **grad-clip 1.0**.
- Log mỗi epoch: val_loss, val_auc, lr, bộ đếm (no_improve, số lần giảm lr).

## 18. Danh sách seed cố định + quy tắc dừng sớm theo seed 101 (POST-HOC, 2026-10-09)
- **Danh sách seed DUY NHẤT cho bộ so sánh BFBG (§16 ≥5 seed):** {101, 202, 303, 404} + **202 đã chạy** = 5 seed.
  (202 chạy trước dưới §17; 101/303/404 + 20261008? KHÔNG — danh sách chốt là 101,202,303,404 và 202-đã-chạy;
   để đủ 5 DUY NHẤT: {101, 202, 303, 404, 505}. 202 đã có kết quả §17; còn lại 101,303,404,505.)
  Ghi trước, không đổi sau khi xem kết quả.
- **Quy tắc dừng sớm theo seed 101 (gate):** chạy seed 101 TRƯỚC (1 run, §17). Chỉ chạy các seed còn lại
  (303,404,505) NẾU **AUC(choco) của seed 101 ≥ 0.90** VÀ người dùng duyệt. Nếu <0.90: dừng, báo, không chạy tiếp.
- Nhãn: **POST-HOC** (sau freeze-v2), không dùng chỉnh design đã khóa. Mọi run dùng §17.
