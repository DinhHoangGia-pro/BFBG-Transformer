# (Hướng B — bản nháp 1 trang) Confounds trong phát hiện banking-trojan xuyên-họ trên PE

> Diễn giải của tôi về "hướng (B)": thay vì công bố một bộ phát hiện BFBG mới (hướng A),
> B biến chính các phát hiện tiêu cực/kiểm toán thành đóng góp **phương pháp luận + benchmark**.
> Chưa chọn hộ A/B. Mọi số là **dev-set (choco), post-hoc**, chưa đụng holdout kiểm định cuối.

## Tiêu đề (nháp)
"Confound hơn cấu trúc: vì sao mô hình đồ thị/transformer không vượt baseline metadata-PE
trong phát hiện banking-trojan xuyên-họ, và một bệnh lý cửa-sổ-đầu-vào"

## Đóng góp (claim)
1. **Kiểm toán confound có hệ thống** trên tác vụ malicious-family vs benign: cho thấy baseline
   **metadata-PE thô** (signed/linker/year/#sections/entropy/size) đạt AUC rất cao và **tổng quát hóa
   tốt nhất** qua họ (LOFO 5-family **0.972 ± 0.017**), trong khi mô hình đồ thị học sâu (BFBG) chỉ
   ~**0.906 ± 0.046** (4 seed) — **không vượt** metadata (dAUC −0.079 ± 0.046, âm mọi seed).
2. **Chẩn đoán đường tắt**: linear-probe trên embedding dự đoán **toolchain-bin/family** cao
   (trained 0.69/0.69; **untrained random-init 0.80/0.79 ≥ trained**) → confound **nằm trong biểu diễn
   đầu vào/kiến trúc**, không do training tạo ra.
3. **Bệnh lý cửa-sổ-đầu-vào**: quy tắc cắt "150 hàm đầu theo địa chỉ" **vứt 77–96% bằng chứng seed
   (ATT&CK)** (BumbleBee 100%, Emotet 97%); chọn lại theo **api-density** giữ **72%** mà không dùng nhãn —
   cho thấy kết quả phụ thuộc mạnh vào thiết kế loader, không phải năng lực mô hình.
4. **Khuyến nghị đánh giá**: (i) luôn báo baseline metadata + bag-of-tokens; (ii) đo trong-bin-toolchain
   và LOFO theo họ; (iii) cần **benign khớp confound** (cùng toolchain/size/signed) để bài toán có ý nghĩa.

## Bảng bằng chứng (đã có, dev-set choco; n ghép đôi 306 trừ khi ghi khác)
| Bằng chứng | Số |
|---|---|
| BFBG 4-seed (best-val_loss, §17) | AUC 0.906 ± 0.046 |
| graph probe / metadata probe | 0.904 / 0.985 |
| dAUC BFBG−metadata (4 seed) | −0.079 ± 0.046 (âm mọi seed) |
| LOFO 5-family (mean±std): metadata / graph+API / graph / bag-tokens | 0.972±0.017 / 0.935±0.013 / 0.908±0.037 / 0.876±0.082 |
| Within-MSVC14 (khử toolchain): metadata/graph+API/bag-tokens/graph | 1.000* / 0.994 / 0.976 / 0.974 (*n_neg=21) |
| Shortcut probe toolchain/family (trained vs untrained) | 0.69/0.69 vs 0.80/0.79 |
| Seed evidence bị cắt bởi "150 hàm đầu" (benign/malicious) | 95.8% / 76.6% |
| Nhiễu seed BFBG (AUC, fixed-epoch v1 / §17 v2) | 0.68–0.88 / 0.85–0.95 |
| Baseline đơn giản (bag-of-tokens / graph+API) | 0.972 / 0.950 |

## Hạn chế
- Mọi số trên **dev-set choco (post-hoc)**; **chưa đụng holdout kiểm định cuối** (holdout_nirsoft).
- Within-MSVC14 n_neg=21 (AUC=1.0 không phải bằng chứng mạnh). choco n nhỏ → recall@FPR nhiễu.
- BFBG mới ≤6 seed, chưa quét siêu-tham-số rộng; "không vượt" là trong phạm vi cấu hình đã khóa.
- Benign (choco/scoop/nirsoft/iso) lệch phân phối mạnh với malware (kích thước ~10×, toolchain) →
  tác vụ dễ một cách giả tạo; chưa có benign khớp-confound.
- Chưa so với SOTA ngoài (EMBER/MalConv) trên cùng split.

## Venue phù hợp (gợi ý, chưa chọn)
- **Bảo mật hệ thống/thực nghiệm:** USENIX Security, ACM CCS, NDSS (mục measurement/empirical),
  **DIMVA**, **RAID**, **ACSAC** — hợp với kiểm toán confound + benchmark.
- **ML-security/datasets:** **DLS (Deep Learning & Security, IEEE S&P workshop)**, **AISec (CCS workshop)**,
  **NeurIPS Datasets & Benchmarks** (nếu kèm bộ benign khớp-confound + bộ công cụ đo).
- Dạng bài: "measurement study" / "cautionary tale + benchmark", nhấn mạnh tái lập (manifest + hash đã có).
