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
- **Danh sách seed DUY NHẤT (ghi trước, không đổi sau khi xem kết quả):** {101, 202, 303, 404}.
  - **Lưu ý mâu thuẫn trong lệnh gốc:** lệnh ghi "(101,202,303,404 + 202 đã chạy = 5)", nhưng 202 đã nằm
    trong tập này → {101,202,303,404} chỉ là **4 seed duy nhất**. §16 yêu cầu ≥5. **CHƯA chốt seed thứ 5**
    (không tự ý bịa); cần người dùng xác nhận seed thứ 5 (vd. 505) trước khi tuyên bố đủ bộ ≥5.
  - 202 đã chạy dưới §17 (AUC choco 0.950). Còn lại trong danh sách 4: 101, 303, 404.
- **Quy tắc gate theo seed 101 (cập nhật 2026-10-09, AUC = best-val_loss checkpoint):**
  - **< 0.85** → DỪNG, báo, không chạy tiếp.
  - **0.85 ≤ AUC < 0.90** (vùng xám) → **HỎI người dùng** trước khi chạy thêm (không tự chạy).
  - **≥ 0.90** → **HỎI người dùng** trước khi chạy thêm.
  → Tóm lại: < 0.85 dừng; ≥ 0.85 hỏi. Không bao giờ tự chạy seed khác mà chưa duyệt.
  - **Kết quả seed 101 (post-hoc):** best-val_loss AUC = **0.891** ∈ [0.85,0.90) → vùng xám → hỏi (không tự chạy).
- Nhãn: **POST-HOC** (sau freeze-v2), không dùng chỉnh design đã khóa. Mọi run dùng §17.

## 19. Quy tắc so sánh BFBG (POST-HOC, 2026-10-10)
- **≥4 seed mỗi cấu hình** cho mọi con số BFBG đem so sánh (nới từ "≥5 lý tưởng" của §16 xuống sàn thực thi ≥4;
  báo trung bình ± std qua seed + hiệu ghép đôi theo seed, như §16). Một-seed vẫn CẤM làm cơ sở kết luận.
- **MỘT thay đổi mỗi lần** (one-change-at-a-time): mỗi thí nghiệm chỉ đổi đúng một yếu tố so với baseline đã khóa,
  ghi trước tiêu chí thắng/thua, để quy được nhân quả. Không gộp nhiều thay đổi.
- **choco (holdout_source_chocolatey) = tập PHÁT TRIỂN** (development set): được phép nhìn để chọn hướng/so sánh
  post-hoc; KHÔNG phải tập kiểm định cuối. Kết luận cuối cần tập giữ riêng chưa đụng (vd. holdout_nirsoft — hiện KHÔNG đụng).

## 20. H1 SẠCH — chọn 150 hàm theo api-density (POST-HOC, ghi trước 2026-10-10, CHƯA chạy)
Động cơ: §#3 cho thấy first-150-theo-địa-chỉ chỉ giữ 17.6% seed evidence; **api-density giữ 71.7% mà KHÔNG dùng nhãn seed**.
- **MỘT thay đổi:** loader đổi `list(ipg.values())[:150]` → **chọn 150 hàm có mật độ call/API cao nhất** (đếm node có `api` hoặc `mnemonic=="call"`), tie-break theo địa chỉ. **KHÔNG dùng seed_edges** để chọn (tránh rò rỉ nhãn/mạch seed). Mọi thứ khác giữ nguyên §17 (early-stop, best-val_loss, grad-clip 1.0, global_features=0).
- **Số seed & lực:** **6 seed** {101,202,303,404,505,606}, ghi trước.
- **Tiêu chí thắng (ghi trước):** mean choco AUC (6 seed) tăng **≥ +0.07** so baseline first-150 (0.906 → **≥0.976**); VÀ hiệu ghép đôi api-density−first **theo từng seed** có CI (cluster-bootstrap) loại trừ 0 ở ≥5/6 seed. Thua nếu không đạt.
- **Phụ (bắt buộc báo):** (a) seed-coverage thực tế trong cửa sổ (kỳ vọng ~72%); (b) **train-trong-bin MSVC14** (so cột BFBG đã bỏ ở #1a); (c) **LOFO tối thiểu 2 family** (Emotet + IcedID — hai family seed-nhiều); (d) **theo dõi lệch kích thước** (nodes-kept ben/mal, #3 cảnh báo 2.83) để biết có đổi confound.
- **choco = dev set (§19)**; kết luận cuối vẫn cần holdout chưa đụng. Nhãn POST-HOC.
- **Ước tính:** ~2h30–3h20/seed (có thể chậm hơn vì api-density giữ hàm lớn) × 6 ≈ **15–22h** (dừng sớm) đến ~48h/trần. Train-in-bin + 2 LOFO fold thêm ~3–4 run ≈ +8–12h.

## 20b. Quy tắc dừng dãy seed cho H1 api-density (GHI TRƯỚC 2026-10-10, trước khi xem kết quả api-density)
Chạy 2 seed đầu {101, 202}. Sau khi CẢ HAI xong, áp quy tắc (AUC = choco, best-val_loss, chính):
- **DỪNG dãy** (không chạy seed tiếp) nếu **cả 2 seed có AUC ≤ 0.906** (không vượt baseline trung bình first-150).
- **TIẾP TỤC** (được phép chạy các seed còn lại trong danh sách ghi trước) nếu **≥1 trong 2 seed có AUC ≥ 0.95**.
- **Ở GIỮA** (max 2 seed ∈ (0.906, 0.95)) → **HỎI người dùng**, không tự quyết.
- **KHÔNG thêm seed mới** sau khi thấy kết quả; chỉ dùng danh sách ghi trước (§18/§20). Không đổi tiêu chí sau khi xem.
- Seed baseline để so ghép đôi (first-150 §17): {101:0.891, 202:0.950, 303:0.934, 404:0.848}. Hiệu tính THEO TỪNG seed (api−first cùng seed).

## 20c. Quy tắc dừng sau 4 seed (POST-HOC, ghi 2026-10-11 sau khi thấy 2 seed đầu)
Nhãn POST-HOC (ghi SAU khi thấy kết quả 2 seed api-density {101:0.971, 202:0.942}). Chạy thêm {303,404} cho đủ 4 seed api-density, rồi:
- **DỪNG sau 4 seed** (KHÔNG chạy 505/606) nếu **mean choco AUC (4 seed, best-val_loss) < 0.95**.
- (≥0.95 thì vẫn hỏi người dùng trước khi chạy tiếp — không tự chạy.)
- Vì là post-hoc (quyết sau khi thấy 2 seed), KHÔNG dùng để tuyên bố §20 "thắng"; §20 gốc vẫn cần 6 seed + mean +0.07. 20c chỉ giới hạn chi phí.

## 20d. Kết luận §20 (2026-10-11): KHÔNG đạt tiêu chí
- api-density 4 seed: mean choco AUC **0.951 ± 0.018** vs first-150 0.906 ± 0.046 (Δ+0.046).
- Tiêu chí §20 (+0.07 ⇒ ≥0.976): **KHÔNG đạt** (0.951 < 0.976).
- std giảm (0.046→0.018) chỉ là **xu hướng n=4**; unpaired MWU **p=0.20**; mean vượt ngưỡng-hỏi 0.95 chỉ **+0.001**.
- Không tuyên bố "api-density cải thiện BFBG". Giữ first-150 là baseline; api-density là ứng viên chưa chứng minh.

## 20e. Ghi chú phương pháp + quyết định không chạy (post-hoc, 2026-10-12)
- §20 KHÔNG đạt (mean 0.951 < 0.976; vượt ngưỡng-hỏi 0.95 chỉ 0.001). std 0.046→0.018 là XU HƯỚNG (n=4, MWU p=0.20).
- **Khi đổi cửa sổ đầu vào (first-150↔api-density), KHÔNG ghép cặp theo seed** — chỉ so phân phối (unpaired).
- api-density: không tách được "giữ nhiều hành vi hơn" vs "đổi confound kích thước (1.48→2.83)"; hạn chế vì n_neg=21.
- KHÔNG chạy (a) train-in-bin (n_neg=21 → vô kết luận, hạn chế DỮ LIỆU) và (b) chạm nirsoft (chưa chốt cấu hình cuối) ở bước này. KHÔNG chạy 505/606.

## 21. Learning-curve RÚT GỌN v4 — nhãn phương pháp (ghi TRƯỚC khi chạy, 2026-10-21)
**DUYỆT chạy** (người dùng, phiên 2026-10-21): base, BATCH=2 + grad-accum 2 (effective 4), KHÔNG AMP, 3 fraction {0.25/0.5/1.0} × 2 seed {20261021,20261022}.
- **Cấu hình:** train_pool v4 (998/1006 có feature) + benign v2-non-holdout sau ISO-subsample (395, `docs/iso_subsample_v4.txt`); val **in-dist phân tầng** (15%, cố định theo seed, tầng = lineage cho mal / source cho benign). Input model global=0 → **không có `vex_vocab_size`** (và không global feature nào) — tránh artifact §FREEZE_v4 D. Vocab INSN dựng tất định 1 lần từ tập train fraction-1.0, dùng chung mọi run.
- **NHÃN DIỄN GIẢI (bắt buộc, ghi trước khi thấy số):**
  1. Đường cong learning-curve **chỉ mô tả XU HƯỚNG**, KHÔNG kết luận "bão hòa dữ liệu" nếu chênh val giữa các fraction **< nhiễu giữa 2 seed**. Cần n>2 seed mới nói mạnh.
  2. **KHÔNG chạm holdout v4/v3** trong learning-curve — chỉ val in-dist. Holdout chạm MỘT LẦN ở báo cáo cuối (FREEZE_v4 quy tắc).
  3. Val AUC in-dist là **cận trên lạc quan** (cùng phân phối train); không phải năng lực cross-family/cross-source.
  4. base (không GRL) → chưa khử shortcut nguồn (§FREEZE_v4 E/C: nội-họ 0.79, holdout 0.90-1.0) → điểm cao có thể do confound.
- **Vận hành:** mỗi run lưu kết quả riêng ngay khi xong; checkpoint `ckpt_last.pt` + resume; trần 8h/run (cả systemd RuntimeMaxSec lẫn tự-dừng); cgroup systemd-run --user (MemoryMax, nice idle). Run đầu (f=1.0, s=20261021) đo giây/epoch + VRAM + #OOM(BATCH=2); **dừng & báo nếu ước >6h/run**; dừng sau run đầu, hỏi trước 5 run còn lại.

### 21a. Run đầu — kết quả (f=1.0, seed=20261021, 2026-10-21)
- BATCH=2 + accum 2, no AMP, global=0 (không vex), train=1184 / val=209 (in-dist phân tầng), cgroup 8h.
- **giây/epoch ≈ 668s** (ổn định) → **tổng 3.73h/20 epoch** (< cổng 6h). **peak VRAM 6.13/8 GB**; OOM BATCH=2: train 0 / **val 1 mỗi epoch** (1 graph lớn bị bỏ → val AUC trên ~208/209; cần giảm max_funcs cho mẫu đó nếu muốn trọn).
- **best val_auc = 0.9223 @ep15**; ep19 = 0.917. Đường cong val: 0.79→0.84→0.85→0.86→0.88→0.87→0.89→0.896→0.894→0.898→0.913→... dao động quanh 0.90-0.92 từ ~ep10 (plateau mềm, 1 seed).
- Lưu: `~/bfbg_benign_work/lc_runs/f1.0_s20261021/{summary,curve,estimate,ckpt_last}` + log.
- ⚠️ val in-dist + base (chưa GRL) → **cận trên lạc quan, chưa khử shortcut nguồn**; 1 seed → CHƯA kết luận bão hòa.

### 21b. Run 2 — f=1.0 seed=20261022 + nhiễu-seed (2026-10-21)
- best val_auc = **0.9102 @ep17** (668s/epoch, 3.73h, peak VRAM 6.88GB, OOM train 1/val 0 mỗi epoch).
- **Nhiễu 2 seed ở f=1.0:** seed1 0.9223 / seed2 0.9102 → **chênh 0.0121** (mean 0.9163). 
- ⇒ **NGƯỠNG nhiễu-seed ≈ 0.012**: theo nhãn §21, chênh val giữa các fraction **< 0.012** KHÔNG được coi là khác biệt thật/bão hòa (n=2 seed, cần thêm seed mới nói mạnh).

### 21c. TẠM DỪNG — checklist chạy tiếp (người dùng: "ngày mai chạy tiếp khi tôi nói tiếp tục", 2026-10-21)
- **Đã xong:** f1.0×seed21 (0.9223) + f1.0×seed22 (0.9102); nhiễu-seed 0.0121.
- **CÒN LẠI 4 run** (chỉ chạy KHI người dùng nói "tiếp tục"):
  - f0.5 ×20261021, f0.5 ×20261022  (~1.9h/run)
  - f0.25 ×20261021, f0.25 ×20261022  (~0.95h/run)
- **Lệnh mỗi run** (cgroup 8h, ckpt+resume, vocab chung đã có `lc_runs/vocab_insn.json`):
  ```
  systemd-run --user -u lc_runX -p MemoryMax=14G -p Nice=19 -p IOSchedulingClass=idle \
    -p CPUWeight=20 -p RuntimeMaxSec=28800 --working-directory="$HOME/Work/Defi/BFBG-Transformer" \
    bash -lc "~/bfbg_venv/bin/python -u ~/bfbg_benign_work/lc_train.py --fraction <F> --seed <S> \
      > ~/bfbg_benign_work/lc_runs/f<F>_s<S>.log 2>&1"
  ```
- Script `~/bfbg_benign_work/lc_train.py`; chỉ-mục feature `/tmp/claude-1001/featidx.json` (nếu mất → dựng lại từ 8 dir features_graph*/v4_benign_features).
- Giữ nguyên: base, BATCH=2+accum2, no AMP, global=0 (không vex), val in-dist phân tầng, ISO subsample. **KHÔNG chạm holdout v4/v3.**

### 21d. Learning-curve ĐẦY ĐỦ — kết quả cuối (6/6 run, 2026-10-22)
val in-dist cố định 209 (phân tầng), best val AUC:
| fraction | n_train | seed20261021 | seed20261022 | mean | chênh-seed |
|---|---|---|---|---|---|
| 0.25 | 295 | 0.8510 | 0.8584 | **0.8547** | 0.0074 |
| 0.50 | 592 | 0.8803 | 0.8834 | **0.8819** | 0.0031 |
| 1.00 | 1184 | 0.9223 | 0.9102 | **0.9163** | 0.0121 |

- **Bước tăng (mean):** 0.25→0.50 = **+0.0272**; 0.50→1.00 = **+0.0344**. Cả hai **> ngưỡng nhiễu-seed 0.012** → khác biệt THẬT.
- **KẾT LUẬN (theo nhãn §21):** đường cong **vẫn dốc lên tới 1184 mẫu, CHƯA bão hòa** — thêm dữ liệu train (nếu có) **vẫn còn giúp**; KHÔNG có bằng chứng bão hòa ở mức dữ liệu hiện tại. (Mâu thuẫn nhẹ với kỳ vọng "dừng 1416 là đủ": thực ra 1416 chưa tới điểm phẳng, nhưng non-Zeus banking đã cạn nguồn (§24.3) → giới hạn DỮ LIỆU, không phải lựa chọn tối ưu.)
- **GIỚI HẠN:** (a) val in-dist + base (chưa GRL) = **cận trên lạc quan, chưa khử shortcut nguồn** (§FREEZE_v4 C/E: nội-họ 0.79, holdout 0.90-1.0) → điểm tuyệt đối 0.92 KHÔNG phải năng lực phát hiện thật; (b) n=2 seed → ngưỡng nhiễu thô; (c) 20 epoch cố định, không tuning; (d) 1 val-batch OOM bị bỏ ở vài run (~208/209). **KHÔNG chạm holdout v4/v3.**
- Vận hành thực tế: 668s/epoch (f1.0) BATCH=2+accum2 no AMP, peak VRAM ≤6.9/8GB, tổng 6 run ≈ 13.6 GPU-giờ (khớp ước ~14).

### 21e. PHÂN TÍCH probe vs BFBG + source-probe embedding (2026-10-22)
**Cùng split, cùng val in-dist 209 (phân tầng), cluster-bootstrap 95% CI (mẫu distinct → bootstrap ~ cụm). Fig: `docs/figs/learning_curve_probes.png`.**

**(1+2) Learning curve — mean val AUC 2 seed (probe = train trên CHÍNH split BFBG):**
| fraction | n_train | **BFBG** (model) | metadata (RF,6f) | graph (RF,6f) | bag-of-tokens (LogReg,1088) |
|---|---|---|---|---|---|
| 0.25 | 295 | 0.842 | 0.922 | **0.929** | 0.765 |
| 0.50 | 592 | 0.880 | 0.947 | **0.954** | 0.781 |
| 1.00 | 1184 | 0.913 | 0.956 | **0.966** | 0.790 |
- CI từng điểm (vd BFBG f1.0 s21 [0.866,0.957]; graph f1.0 s21 [0.950,0.990]) — xem `lc_runs/{bfbg_rescore,probe_curve}.json`.
- ⚠️ **KẾT QUẢ THEN CHỐT: đặc trưng TĨNH tầm thường (graph/metadata, RF 6 feature) VƯỢT BFBG ở MỌI fraction** (graph 0.966 vs BFBG 0.913 @f=1.0). Chỉ bag-of-tokens (0.79) thua BFBG.
- **Diễn giải:** val in-dist bị chi phối bởi **kích thước/độ-phức-tạp** (num_functions, num_api_calls, total_nodes) mà RF nắm trực tiếp và tốt hơn graph-transformer. ⇒ (a) BFBG **chưa chứng minh được giá trị trên baseline rẻ tiền** ở val in-dist; (b) "learning curve dốc lên" của BFBG chủ yếu bám cùng tín hiệu size/complexity (yếu hơn). **Bắt buộc: báo cáo BFBG KÈM baseline graph/metadata; mọi tuyên bố năng lực phải vượt baseline này.**

**(3) Source-probe trên EMBEDDING run f1.0 s21 (pooled_program 128-dim):**
- LogReg, OOF-cụm, **trong từng họ 2-nguồn, trung bình** → chỉ IcedID-lineage đủ 2 nguồn (mb83/v1114): **AUC = 0.7606**.
- Tham chiếu group-by-lineage (qua họ) = 0.4696 (<0.5, nguồn không tổng quát qua họ).
- ⇒ **embedding CÓ mã hóa nguồn nội-họ (0.76)**, hơi thấp hơn static features (0.79) nhưng vẫn **> ngưỡng 0.75** → cần GRL khử nguồn.

## 22. Thiết kế GRL khử nguồn — BẢN SỬA (ghi trước, CHƯA chạy, 2026-10-22)
- **Adversary (sửa):** KHÔNG dùng nhị phân mb-vs-v1. Thay bằng dự đoán **stratum nguồn/năm (4 lớp)** cho malware + **nguồn** cho benign; huấn luyện **CÓ ĐIỀU KIỆN THEO LỚP** (conditional/class-wise: adversary + GRL áp riêng theo nhóm nhãn malware/benign, không trộn) để không khử nhầm tín hiệu malware↔benign.
- **Vị trí:** GRL trên `pooled_program` (128-dim, trước fc1). Adversary MLP dim→64→(4 hoặc K nguồn-benign), softmax CE.
- **λ:** `λ(p)=λ_max(2/(1+e^{-10p})-1)`, **λ_max=1.0**; warm-up λ=0 vài epoch đầu.
- **Loss:** `CE(label) + λ_sem·BCE(sem) − λ·CE_adv(stratum)` (class-wise).
- **Probe nguồn CHỐT ĐỊNH NGHĨA (áp cho cả baseline lẫn GRL):** LogReg, OOF-cụm, trong từng họ 2-nguồn, trung bình (hiện chỉ IcedID). **Baseline non-GRL = 0.7606** (đo cùng cách, ở trên).
- **Tiêu chí thành công (ghi TRƯỚC):** (a) probe nguồn embedding **< 0.75**; (b) val AUC in-dist **không giảm quá 0.03** so với base (base f1.0 last-ep mean 0.913 → sàn 0.883). Đạt cả 2 mới đủ điều kiện chấm holdout (một lần).
- **Kế hoạch rút gọn:** f=1.0, **2 seed {20261021,22}**, λ_max=1.0, **1 biến thể** (adversary=stratum nguồn/năm). Ước **~4.0-4.7h/run × 2 ≈ ~9 GPU-giờ**. **CHƯA chạy — hỏi người dùng trước.**
- Giữ cố định: BATCH=2+accum2, no AMP, global=0 (không vex), val in-dist cùng split, ISO subsample. **KHÔNG chạm holdout v4/v3.**

### 21f. Provenance-probe mở rộng (≥4 họ 2-nhóm, năm-trong-họ) — embedding vs feature rẻ (2026-10-22)
Probe provenance = dự đoán nhóm NĂM (2 nhóm lớn nhất ≥5) TRONG từng họ, LogReg OOF-cụm (mẫu distinct), cluster-bootstrap 95% CI; **trung bình 4 họ** (QakBot 2023v2024, Gozi 2023v2022, IcedID 2021v2025, Ramnit 2021v2020). train_pool, KHÔNG chạm holdout.
| feature | avg AUC | QakBot | Gozi | IcedID | Ramnit |
|---|---|---|---|---|---|
| **embedding (BFBG f1.0)** | **0.732** | 0.725[.57,.87] | 0.838[.78,.89] | 0.811[.73,.89] | 0.554[.29,.80] |
| metadata (RF-feats) | 0.688 | 0.885[.75,.98] | 0.660[.59,.73] | 0.800[.69,.90] | 0.405[.16,.67] |
| graph (RF-feats) | 0.697 | 0.713[.51,.89] | 0.477[.40,.56] | 0.893[.83,.94] | 0.703[.44,.93] |
| bag-of-tokens | 0.809 | 0.806[.65,.93] | 0.843[.78,.90] | 0.878[.80,.95] | 0.711[.46,.92] |
- **Nhận định:** embedding mã hóa provenance năm-trong-họ ở **0.73 (TB)** — vừa phải, **KHÔNG cao hơn** đáng kể so với feature rẻ (meta 0.69, graph 0.70) và **thấp hơn bag-of-tokens (0.81)**. CI rộng (n/họ nhỏ, Ramnit n=22 → không tin cậy).
- **Phụ thuộc ĐỊNH NGHĨA tiêu chí:** probe nguồn mb-vs-v1 within-IcedID = **0.76** (§21e); probe năm-trong-họ TB-4-họ = **0.73**. Hai số nằm hai phía ngưỡng 0.75 → **tiêu chí GRL phải ghi rõ định nghĩa + CI**.

### 22 (SỬA). Tiêu chí GRL kèm CI + hệ quả BFBG<RF
- **Probe-nguồn CHỐT:** provenance năm-trong-họ, LogReg OOF-cụm, TB ≥4 họ (QakBot/Gozi/IcedID/Ramnit), cluster-bootstrap CI. **Baseline non-GRL = 0.732** (CI từng họ ở §21f).
- **Tiêu chí thành công (kèm CI, ghi TRƯỚC):**
  (a) provenance-probe embedding (TB-4-họ) **điểm < 0.70 VÀ cận trên CI-tổng-hợp < 0.75** (siết hơn baseline 0.732, tránh "đạt nhờ nhiễu"); 
  (b) val AUC in-dist **không giảm > 0.03** so base (f1.0 last-ep mean 0.913 → **sàn 0.883**, so bằng CI-overlap);
  (c) báo CI cho cả (a),(b).
- **HỆ QUẢ cho CLAIM (bắt buộc):** BFBG val in-dist (0.84/0.88/0.91) **< graph-RF (0.93/0.95/0.97) ở MỌI fraction** (§21e). ⇒ **KHÔNG được claim BFBG là bộ phát hiện in-dist tốt hơn**. Claim hợp lệ phải là: (i) **khử provenance/shortcut** (provenance-probe thấp hơn baseline rẻ) và/hoặc (ii) **tổng quát hóa cross-family/cross-source** (LOFO + holdout — nơi feature size/complexity rẻ gãy), KÈM baseline RF trong mọi bảng.

### 23. Kịch bản "GRL thành công nhưng BFBG vẫn < probe rẻ" → đóng góp là gì (ghi trước)
Nếu GRL đạt (a)+(b) nhưng val BFBG (~0.91) vẫn < graph-RF (~0.97):
- **Đóng góp KHÔNG phải accuracy in-dist** (RF thắng). Đóng góp = **robustness/invariance**: một detector có biểu diễn **ít phụ thuộc provenance/size-shortcut hơn** (provenance-probe < RF), kỳ vọng **giữ điểm tốt hơn khi phân phối đổi** (holdout cross-time/cross-family, nơi RF dựa size/complexity sẽ sụp).
- **Phép thử quyết định (chạm holdout MỘT LẦN, chỉ sau khi GRL đạt tiêu chí):** so **ΔAUC(in-dist → holdout)** của BFBG-GRL vs graph-RF. Nếu RF rơi mạnh còn BFBG-GRL giữ → đóng góp THẬT (robustness). Nếu cả hai rơi như nhau → **thừa nhận BFBG không có lợi thế** và báo trung thực (không cố cứu claim accuracy).
- Nếu GRL KHÔNG đạt (a) hoặc (b): không chấm holdout; báo "chưa khử được confound" như kết quả âm.

### 24. Cross-family LOFO-detection trên FEATURE ĐÔNG CỨNG (Hướng 2, 2026-10-22)
Leave-one-malware-lineage-out: train head trên (mal họ≠F + benign_train 333), test (mal họ F + benign_test 59). Head tuyến tính trên embedding BFBG đông cứng (f1.0 s21) vs RF/LogReg trên feature rẻ. **KHÔNG train BFBG, KHÔNG chạm holdout.** AUC phát hiện họ "để ngoài head":
| feature | avg | QakBot | TrickBot | Gozi | Tinba | IcedID | Emotet | Dridex | Ramnit |
|---|---|---|---|---|---|---|---|---|---|
| **embedding BFBG** | **0.966** | 0.944 | 0.979 | 0.979 | 0.972 | 0.934 | 0.961 | 0.984 | 0.979 |
| graph (RF) | 0.944 | 0.963 | 0.943 | 0.967 | 0.924 | 0.897 | 0.897 | 0.992 | 0.968 |
| metadata (RF) | 0.893 | 0.968 | 0.900 | 0.930 | 0.732 | 0.875 | 0.818 | 0.987 | 0.934 |
| bag-tokens | 0.813 | 0.826 | 0.881 | 0.850 | 0.770 | 0.599 | 0.834 | 0.856 | 0.889 |
- **ĐẢO NGƯỢC so với in-dist (§21e, nơi graph-RF thắng BFBG):** ở cross-family, **embedding BFBG thắng mọi feature rẻ** (0.966 > graph 0.944 > meta 0.893 > bag 0.813), thắng 7/8 họ. → gợi ý biểu diễn BFBG mang tín hiệu TỔNG QUÁT HƠN size/complexity.
- ⚠️ **CAVEAT NẶNG (chưa phải cross-family sạch):** encoder BFBG f1.0 **ĐÃ train trên TẤT CẢ họ (kể cả F)**; chỉ HEAD là leave-F-out. ⇒ số 0.966 **lạc quan/upper-bound**, KHÔNG phải tổng quát sang họ CHƯA TỪNG THẤY. feature rẻ là extractor cố định (không "học" F) nên LOFO của chúng sạch → so sánh **thiên vị BFBG**.
- **Để kết luận sạch cần:** train BFBG **leave-F-out cả ENCODER** (đắt: ~3.5-3.7h/họ × 8 ≈ ~30h; hoặc rút gọn 3 họ × 1 seed ≈ ~11h). Chỉ khi đó mới so cross-family công bằng với RF.
- **Tạm kết Hướng 2:** có TÍN HIỆU DƯƠNG cho BFBG (ngược in-dist) → **đáng làm phép thử sạch trước khi quyết GRL**; nhưng chưa đủ bằng chứng (caveat encoder-thấy-F).

### 25. LOFO retrain SẠCH (leave-lineage-out encoder) — nhãn tiền-đăng-ký (dev, post-hoc, 2026-10-22)
**Thứ tự cố định (ghi trước, không đổi):** 1) IcedID-lineage (icedid+latrodectus, n=197), 2) Gozi-lineage (gozi+isfb+ursnif, n=268), 3) Tinba (n=90).
- Mỗi họ: train BFBG **leave-lineage-out** (loại khỏi CẢ train và val của encoder); test fold = (mal họ đó) + benign_test (15%, seed 20261021). 1 seed=20261021, BATCH=2+accum2, no AMP, global=0 (không vex), ISO subsample. Baseline graph-RF/metadata-RF/bag-tokens **cùng fold**, AUC + cluster-boot CI.
- **Ngưỡng đọc (ghi TRƯỚC):** chênh AUC(BFBG − baseline tốt nhất) **< 0.05 = KHÔNG phân biệt**; chỉ coi BFBG có lợi thế cross-family nếu **dẫn ≥0.05 ở ≥2/3 họ**.
- **Vận hành:** chạy theo PHIÊN 4h/họ, checkpoint last mỗi epoch + --resume, kết quả lưu riêng `lc_lofo/<lineage>/`. Hết phiên dừng sạch, báo bảng, KHÔNG tự bắt đầu họ tiếp. **KHÔNG chạm holdout v4/v3.** Nhãn: **dev, post-hoc**.
