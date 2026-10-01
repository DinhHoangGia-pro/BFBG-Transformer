# Bài học từ codebase EVM (T-CFBG cho smart contract)

BFBG-Transformer kế thừa kiến trúc từ dự án T-CFBG phát hiện lỗ hổng smart contract EVM. Tài liệu này ghi lại hai bài học từ dự án đó mà pipeline PE-malware phải tuân theo. Số liệu trích từ comment trong code cũ: `scripts/extract_evm_features.py`, `scripts/v2_function/` và các script audit trước đây ở `scripts/v1/` (vẫn còn trong lịch sử git).

## 1. Luật seed đúng trên lý thuyết có thể gần như không bao giờ khớp dữ liệu thật

**Chuyện đã xảy ra.** Bản EVM dùng 5 luật SWC (Bảng 1 của bài báo) để sinh `seed_sem_edges`, tức nhãn yếu cho Learned Semantic Dependency Predictor. Mỗi luật là một cặp opcode (nguồn → đích), ví dụ `CALL → SSTORE` cho reentrancy, `ORIGIN → EQ` cho tx.origin. Trên lý thuyết các luật này hợp lý. Sau khi đo trên toàn bộ 10.513 file đã trích xuất:

| Luật | Số hợp đồng khớp |
|---|---|
| `reentrancy_call_before_sstore` | 4 / 5.797 (**0,07%**) |
| `tx_origin_authorization` | 0 / ~2.613 (**0%**) |

Trong khi đó Slither báo cáo hàng nghìn hợp đồng thực sự mắc hai loại lỗi này.

**Nguyên nhân.** Luật cũ đòi hai opcode phải nằm **liền kề tuyệt đối** (`instrs[j]` và `instrs[j+1]`). Compiler Solidity gần như không bao giờ sinh ra mẫu như vậy:

```
tx.origin == owner  →  ORIGIN, PUSH20 <addr>, EQ           (PUSH20 chen giữa)
CALL trước SSTORE   →  CALL, ISZERO, PUSH<dest>, JUMPI, ...  (nhiều lệnh xen giữa)
```

Lỗi này không làm gì crash. Pipeline vẫn chạy, mô hình vẫn train, chỉ là predictor gần như không nhận được nhãn dương nào cho 2/5 luật quan trọng nhất.

**Cách đã sửa.** Quét trong cửa sổ `SEMANTIC_WINDOW = 8` lệnh, vẫn giới hạn trong một basic block để không sinh quá nhiều cạnh giả. Giới hạn còn lại vẫn được ghi nhận: reentrancy kinh điển (CALL ở một block, SSTORE ở block khác sau JUMPI) vẫn có thể bị bỏ sót.

**Áp dụng cho PE-malware.** Bảng luật ATT&CK (`src/semantic/seed_rules_attck.py`) sẽ gặp đúng rủi ro này, có khi còn nặng hơn. Mã x86 sau khi lift sang VEX IR có rất nhiều lệnh trung gian (tính địa chỉ, nạp tham số API, temp của VEX), và mỗi compiler, mỗi mức tối ưu, mỗi packer lại sinh ra một dạng khác. Vì vậy:

- Sau mỗi lần trích xuất hoặc đổi bảng luật, chạy [`experiments/qa/check_seed_rule_fire_rate.py`](../experiments/qa/check_seed_rule_fire_rate.py). Script cảnh báo mọi luật fire dưới 1% mẫu dương.
- Danh sách luật phải lấy từ bảng luật chứ không suy ra từ dữ liệu. Một luật fire 0% sẽ không bao giờ xuất hiện trong dữ liệu, nên chỉ nhìn dữ liệu thì không thể phát hiện nó.
- Fire rate cao ở cả hai lớp cũng là lỗi, nhưng theo chiều ngược lại: luật đó là nhiễu chứ không phải tín hiệu. [`check_label_confidence.py`](../experiments/qa/check_label_confidence.py) (phần 2) kiểm tra trường hợp này.

## 2. Nguồn nhãn phải độc lập với detector

**Chuyện đã xảy ra.** Bản contract-level (v1) gán nhãn `vulnerable/safe` bằng Slither, một detector tĩnh tự động. Độ chính xác chững lại ở khoảng **0,75–0,80**. Các script audit thời đó đặt giả thuyết trần này nằm ở **chất lượng nhãn** chứ không phải ở kiến trúc, và kiểm chứng bằng:
- một baseline chỉ dùng đặc trưng thống kê (Logistic Regression, Random Forest, không dùng đồ thị): nếu baseline cũng chạm cùng trần, vấn đề nằm ở nhãn;
- đo tỉ lệ mẫu "vulnerable" không có seed edge nào. Nhãn của những mẫu này chỉ đến từ Slither, nên mô hình không có bằng chứng ở mức opcode để học;
- đo từng luật trên cả hai lớp để phát hiện luật khớp ngang nhau ở safe lẫn vulnerable.

Gốc rễ vấn đề: khi nhãn do một detector tự động sinh ra, mô hình học cách **bắt chước detector đó**, kể cả lỗi của nó, chứ không học hiện tượng thật.

**Hướng đã thử (`scripts/v2_function/`).** Bỏ hẳn nhãn Slither và chuyển sang nhãn cấp hàm từ **người audit thật**: SmartBugs-Curated + DAppSCAN, gồm 2.165 hàm vulnerable + 2.165 hàm safe = 4.330 hàm. Nhãn cấp hợp đồng chỉ còn là giá trị suy ra (có ít nhất một hàm vulnerable hay không).

**Đã chốt cho PE-malware: nguồn nhãn ≠ baseline engine.** Pipeline mới không port code v2. Nó chỉ kế thừa nguyên tắc:

- Nhãn malicious/benign lấy từ **sự đồng thuận của nhiều engine trên VirusTotal**, theo ngưỡng số engine. Mức tin cậy nhãn bằng số engine đồng thuận; xem `--agreement-key`, `--high-min`, `--medium-min` trong `check_label_confidence.py`.
- Engine hoặc mô hình nào dùng làm **baseline** để so sánh thì **không được** góp vào nguồn nhãn của chính phép so sánh đó. Nếu vi phạm, baseline được đánh giá trên nhãn do chính nó tạo ra.
- Luật seed ATT&CK là **tín hiệu giám sát yếu cho cạnh E_sem**, không phải nguồn nhãn lớp. Không được dùng việc một luật fire để suy ra nhãn malicious.
- Mẫu có ít engine đồng thuận (vùng xám) được báo cáo riêng theo từng tầng tin cậy, không gộp im lặng vào lớp dương.
