# Kế hoạch mở rộng dữ liệu v4 (benign khớp-confound + malware đa dạng hơn)

> **Written for:** đồng tác giả + người dùng (tài liệu kế hoạch nội bộ). Mọi con số "trần nguồn" là
> **ước lượng trước-thu-thập** (metadata hoặc pilot cũ); **chưa tải hàng loạt**. **Hỏi người dùng trước
> khi tải.** Không chạm v1/v2/v3/holdout; v4 là tập MỚI (bất biến "không sửa tập cũ", xem `DATASET.md`).

Ngày: 2026-10-15. Động lực: run GRL biến thể 1 bị dừng sớm vì **benign chưa khớp-confound**
(xem `GRL_DESIGN.md` mục "Run thăm dò … BỊ DỪNG SỚM"). Trước khi thử lại bất-biến toolchain, cần một
holdout/benign khớp phân phối toolchain×size của malware để phép đo bất-biến không lẫn với lệch nguồn.

---

## 0. CỔNG DỮ LIỆU (DATA GATE) — quy tắc chi phối
**CHỈ được train / chạy GRL / chấm holdout KHI mục 0.1 dưới đây ghi rõ các ngưỡng ĐÃ ĐẠT.**
Khi cổng **đóng** (chưa đạt), chỉ được: **thu thập, lift, dedup, khóa manifest, viết tài liệu**.
**KHÔNG tự đề xuất train/GRL/holdout khi cổng chưa mở.** Mỗi báo cáo cuối phiên PHẢI nêu: ngưỡng nào đã
đạt, ngưỡng nào chưa, còn thiếu bao nhiêu. Ngưỡng định nghĩa ở §5.5; trạng thái sống cập nhật ở §0.1.

### 0.1 Snapshot cổng (cập nhật 2026-10-15; ngưỡng benign cũ) — **ĐÓNG** 🔴
| Ngưỡng (§5.5) | Mục tiêu | Hiện tại | Còn thiếu | Đạt? |
|---|---|---|---|---|
| Malware khác biệt (ppdeep) | ~1500 | **708** | ~792 | ❌ |
| Benign ô #1 MSVC≤10×256KB-1MB | ≥100 | 23 | 77 | ❌ |
| Benign ô #2 MSVC14×256KB-1MB | ≥100 | 57 | 43 | ❌ |
| Benign ô #3 MSVC14×1-4MB | ≥100 | 87 | 13 | ❌ |
| Benign ô #4 MSVC11-12×256KB-1MB | ≥20 | 6 | 14 | ❌ |
| Benign ô #5 MSVC11-12×1-4MB | ≥20 | 3 | 17 | ❌ |
| Benign ô #6 MSVC11-12×<256KB | ≥20 | 0 | 20 | ❌ |
| Nhãn family v4 đã xác minh | có | chưa | — | ❌ |
| Holdout v4 đã khóa (manifest+hash+split) | có | chưa | — | ❌ |

→ Cổng **ĐÓNG**: phiên này và tới khi mọi ô trên "đạt", chỉ thu thập/lift/dedup/khóa-manifest/viết-docs.
Benign hiện tại từ v1/v2/v3 (chưa có mẫu v4 nào). Cập nhật bảng này sau mỗi đợt thu thập + dedup.

**Lưu ý cập nhật 2026-10-18:** bảng trên là snapshot lịch sử trước khi mục tiêu benign được sửa ở §5.1/§5.5;
không dùng các ô MSVC≤10×size-vừa và MSVC11-12 làm ngưỡng hiện hành. Theo số khóa, malware vẫn **708**;
§19 và §20.4 ghi candidate malware chưa khóa. Hai ô benign MSVC14 đã đạt **100 kept mỗi ô** (99 lift-OK mỗi ô,
§13), nhưng nhãn family v4 và manifest/split holdout vẫn chưa khóa. Vì vậy cổng vẫn **ĐÓNG**; không cộng
candidate BODMAS hoặc candidate v4 vào số khóa ở bảng này.

**Full pull 2026-10-15 (đo thật, §4.6):** đã tải+lift+dedup đủ Zeus/Gozi/Zloader/Ramnit → **559 mẫu KHÁC BIỆT**
(ppdeep≥90, 0 trùng 708 cũ), lưu thư mục RIÊNG. **CHƯA khóa vào v4** nên dòng "malware khác biệt = 708" ở bảng trên
**giữ nguyên cho trạng thái cổng**. Khi khóa v4 (manifest+hash+split theo dòng mã nguồn) → **708 + 559 = 1267 distinct**.
- **Còn thiếu để mở cổng (tính cả 559 nếu khóa):** malware khác biệt **1267/1500 → thiếu ~233** (cần thêm family
  banking/loader đúng loại, vd Qakbot qua VX/VirusShare, hoặc mở rộng alias); benign 6 ô vẫn thiếu
  **77/43/13/14/17/20**; nhãn v4 chưa xác minh; holdout v4 chưa khóa.
- **Không khóa v4, không train** phiên này (cổng vẫn ĐÓNG). 559 là availability đã chứng minh, chưa phải v4 đã khóa.

---

## 1. Trạng thái run GRL (tóm tắt)
- Dừng bằng tay 2026-10-15 07:56:32 sau ~13'51" / **1 epoch** (epoch 0: det 0.5061, val 0.5033, λ=0.245).
  Không result JSON. **Không chạm v3/holdout v2** (chỉ train_pool + BumbleBee fold + choco dev).
- **Kết quả dở dang KHÔNG dùng làm bằng chứng.** Chi tiết: `GRL_DESIGN.md`.

---

## 2. Xếp ô (toolchain-bin × khoảng kích thước) theo mức THIẾU benign — chọn 6 ô thiếu nhất
Nguồn: `HOLDOUT_V4_MATCH_ESTIMATE.md` (malware v1/v2 n=1382 vs benign v1/v2 n=504, mẫu số `feat_cache`).
Thiếu = (malware trong ô) − (benign trong ô), chỉ xét ô dương (cần thêm benign để khớp 1:1).

| Hạng | Ô (bin × size) | malware | benign | **thiếu** | Ghi chú |
|---|---|---|---|---|---|
| 1 | **MSVC≤10 × 256KB–1MB** | 634 | 23 | **+611** | ô trội tuyệt đối; malware MSVC≤10 tập trung ở đây |
| 2 | **MSVC 14 × 256KB–1MB** | 275 | 57 | **+218** | benign ISO/OSS lệch sang size lớn hơn |
| 3 | **MSVC 14 × 1–4MB** | 248 | 87 | **+161** | |
| 4 | **MSVC 11-12 × 256KB–1MB** | 30 | 6 | **+24** | bin gần như TRỐNG ở benign |
| 5 | **MSVC 11-12 × 1–4MB** | 27 | 3 | **+24** | bin gần như TRỐNG ở benign |
| 6 | **MSVC 11-12 × <256KB** | 15 | 0 | **+15** | benign = 0 (cấu trúc, không chỉ thiếu số lượng) |

Tiếp theo (không trong top-6): MSVC≤10×1-4MB +6; Delphi×<256KB +5, Delphi×1-4MB +5, other×256KB-1MB +5.
**Tổng thiếu để khớp 1:1 theo ô ≈ 1085** (v1/v2; v3 thêm benign theo bin nhưng không có cột size).

**Đọc bảng:** ô 1–3 là thiếu-số-lượng-lớn (MSVC các đời, size nhỏ–vừa); ô 4–6 (MSVC 11-12) thiếu
tuyệt đối nhỏ nhưng **gần như trống** ở benign → ưu tiên lấp để bin tồn tại được chia train/test.
"Khớp 1:1 toàn bộ" khó khả thi (benign dễ-tìm lại rơi vào size lớn / MSVC14); mục tiêu thực dụng ở §5.

---

## 3. Pilot benign ngẫu nhiên — GIAO THỨC (chưa tải mới trong phiên này)
Mục tiêu: đo **yield / tỉ lệ native / tỉ lệ trùng v1–v3** cho mỗi nguồn ứng viên, bằng **mẫu ngẫu nhiên
seed cố định** (không chọn tay — pilot chọn tay cũ cho yield lệch, xem cảnh báo `DATASET.md`).

### 3.1 Giao thức (sẵn sàng chạy khi được duyệt)
- **Seed cố định: 20261015** (ghi vào tên run + manifest pilot). Công cụ: `experiments/dataset/pilots/pilot_random.py`
  (đã có; dùng cho pilot seed 20261007). Mỗi nguồn: liệt kê toàn bộ app/manifest → `random.Random(20261015)`
  chọn **25** → tải payload PE (quy tắc `benign-installer-payload-only`: giữ .exe/.dll bên trong, KHÔNG giữ
  installer gốc) → lift → phân bin bằng `validate_tc.py` (bộ đã kiểm 80%) → ppdeep vs v1/v2/v3 + holdout.
- **Báo theo:** (a) yield = #JSON hợp lệ / 25; (b) tỉ lệ native (loại .NET/CIL); (c) **tỉ lệ trùng v1–v3**
  (`ppdeep≥90` hoặc sha256 trùng — theo quy tắc dedup `DATASET.md`); (d) phân bố theo 6 ô thiếu ở §2;
  (e) timeout (Rust/Go cần `--timeout 900`).
- **Dừng/loại:** `ppdeep=100` hoặc sha trùng **holdout/mẫu-đã-fail** → loại; `90≤ppdeep<100` → kế thừa split.

### 3.2 Nguồn ứng viên (4–5), và ô kỳ vọng lấp
| Nguồn | Kỳ vọng ô (bin×size) | Vì sao | Rủi ro |
|---|---|---|---|
| **Scoop Versions/Extras** (bản cũ) | MSVC≤10 & 11-12 × nhỏ–vừa | pin version cũ → linker cũ | yield thấp (pilot Main random 44%), lẫn Go/Rust |
| **PortableApps.com** (app cũ) | MSVC≤10 × 256KB–1MB (ô #1) | app đời cũ, có ký, 0 trùng ở thử trước | trích URL tự động yield thấp; nhiều DLL bundle |
| **SourceForge / GitHub release cũ (2008–2015 tags)** | MSVC≤10 & 11-12 × nhỏ–vừa | release lịch sử → toolchain đúng đời | nhiều project .NET/Java (loại); link chết |
| **Freeware cũ (IrfanView 8, 7-Zip cũ, Notepad++ cũ…)** | MSVC≤10/11-12 × nhỏ | binary nhỏ gọn MSVC đời cũ | ít vendor → **cap vendor theo bin** |
| **(bổ sung) Scoop Main random** | MSVC14/Go/GNU | đa vendor, đã có pilot | → bin GNU/Go **cap ≤10%** tổng benign |

### 3.3 Pilot ĐÃ ĐO (đã commit, dùng lại — không tải mới)
Từ `DATASET.md` (2026-10-07), **số thật**:
- **Scoop Main, random seed 20261007:** yield **11/25 (44%)**, đa toolchain (MSVC14/≤10/Go/GNU/Rust), 0 near-dup.
- **NirSoft, random seed 20261007:** yield **23/25 (92%)**, **100% MSVC≤10 (linker 6-8)**, native, 0 near-dup, 0 timeout.
  → NirSoft là nguồn tốt nhất cho **ô #1 (MSVC≤10 × nhỏ)** nhưng **một vendor** → cap vendor mạnh (≤35%/bin).
- **Scoop chọn-tay (22 GNU/C tool):** yield 86% — **KHÔNG ngoại suy** (chọn tay lệch).

> Phiên này **không tải mẫu benign mới**. Các dòng yield cho Scoop Versions/PortableApps/SourceForge/freeware
> ở §5 là **mục tiêu/giả định**, sẽ thay bằng số pilot seed 20261015 **sau khi người dùng duyệt tải**.

---

## 4. Khảo sát malware — trần từng family (metadata, KHÔNG tải)
Nguồn: MalwareBazaar qua `scripts/fetch_malware_samples.py --dry-run` (metadata `get_siginfo`, lọc
exe/dll size≤12MB, **dedup sha256**, **TRƯỚC** near-dup/ppdeep). Chạy 2026-10-15, `--list-limit 500`.

| Family | meta | PE≤12MB (sha-unique) | Loại hình | Trong phạm vi? |
|---|---|---|---|---|
| **Zeus (Zbot)** | 360 | **357** | banking trojan kinh điển | ✅ banking, đời cũ → **MSVC≤10** (khớp ô #1) |
| **Gozi** | 500* | **157** | banking (dòng Gozi/ISFB/Ursnif) | ✅ banking |
| **Zloader** | 500* | **90** | banking/loader | ✅ banking/loader |
| **Ramnit** | 39 | **31** | banking worm | ✅ banking (ít) |
| Ursnif / ISFB / Zbot | 0 | 0 | — | MB không trả dưới tên này (dùng umbrella "Gozi"/"Zeus") |
| QakBot | 0 | 0 | — | ❌ không lấy được (xác nhận lại khảo sát cũ) |
| SystemBC | 500* | 484 | proxy/backdoor | ❌ **KHÔNG phải banking** → loại (construct-validity, như cũ) |

`*` meta chạm `--list-limit 500` (trần thực dụng API; `limit=1000` từng trả 502) → trần thật có thể **cao hơn**
cột PE (chỉ 500 dòng đầu được lọc size). Zeus/Ramnit **không chạm 500** → số PE là đầy đủ.

### 4.1 Ước lượng mẫu KHÁC BIỆT sau dedup ppdeep (ƯỚC LƯỢNG, chưa lift)
Banking family nặng biến thể-chiến-dịch → tỉ lệ near-dup cao. Dải tham chiếu từ family đã lift (`DATASET.md`):
TrickBot 52.5% / Dridex 82.0% / IcedID 56.2% trùng (BumbleBee/Emotet gần 0, cá biệt). Áp dải **50–80% trùng**
cho family mới (→ khác biệt ≈ 20–50% số mẫu). **Đây là ước lượng, số thật chỉ có sau lift + `check_sample_similarity.py`.**

| Family | PE≤12MB | ước lượng khác biệt (20–50%) | Giá trị cho confound |
|---|---|---|---|
| Zeus | 357 | ~71–178 | **cao** — lấp malware **MSVC≤10** (đời 2007–2013) |
| Gozi | 157 | ~31–78 | banking đa đời |
| Zloader | 90 | ~18–45 | loader hiện đại (MSVC14 nhiều) |
| Ramnit | 31 | ~6–15 | ít, bổ sung đa dạng |
| **Cộng (mới)** | **635** | **~125–315 khác biệt** | so với **708** khác biệt hiện có |

Trùng chéo-family (ppdeep≥90 giữa Zeus và TrickBot…) kỳ vọng ~0 (family khác nhau hiếm khi near-dup) → cộng gần như trực tiếp.

**Khác biệt ước tính THEO NGUỒN** (áp cùng dải 20–50% sau ppdeep; xác minh sau lift):
- **MalwareBazaar** (Zeus+Gozi+Zloader+Ramnit = 635 PE) → **~125–315 khác biệt**. Nguồn chính, PE thật, lift được.
- **VX-Underground / VirusShare / MalShare**: trần **chưa xác minh** (không khảo sát tự động được) → ước tính sau khi
  xin truy cập + tải thử; dùng cho **Qakbot** và Ursnif/ISFB mà MB không trả. Khác biệt chỉ ước được sau tải+dedup.
- **SOREL-20M / BODMAS**: có **nhãn family** → lọc tập con banking được, nhưng SOREL **disarmed** (cần xác minh lift) và
  BODMAS binary **theo yêu cầu** → coi là **phương án dự phòng**, không phải nguồn chính. Khác biệt chưa ước được.

### 4.2 Khảo sát nguồn quy mô lớn (2026-10-15, qua web — KHÔNG tải; "chưa xác minh" khi không chắc)
So sánh điều kiện truy cập / có **PE thật** không (hay đặc trưng/binary bị vô hiệu hóa) / quy mô / giấy phép.

| Nguồn | Truy cập | PE thật? | Quy mô / theo family | Giấy phép |
|---|---|---|---|---|
| **MalwareBazaar** (đang dùng) | API key (đã có) | ✅ PE thật, zip AES "infected" | theo signature (get_siginfo); trần đã khảo sát §4 | TOS abuse.ch; nghiên cứu |
| **VX-Underground** | Công khai, miễn phí; mẫu nén có mật khẩu (công bố trên site/Twitter — **không chép vào đây**) | ✅ PE thật (mẫu sống), **không** vô hiệu hóa | tự nhận "lớn nhất", ~**35M** mẫu (chưa xác minh); có collection **"Families"**, InTheWild, mirror VirusShare/VirusSign | **Không có license mã-nguồn-mở rõ ràng**; chỉ disclaimer trách nhiệm; "research/edu" là tóm tắt bên thứ ba → **chưa xác minh** |
| **VirusShare** | **Mời riêng**: email xin ("access") → link mời; cấm scraping; có thể thu hồi | ✅ PE thật (mẫu sống), zip mật khẩu "infected"; định dạng EXE | rất lớn (hàng chục triệu, chưa xác minh con số); **không lọc theo family sẵn** (phải tự map hash) | Không license chính thức; TOS: nghiên cứu, cấm tải quá mức/scraping |
| **SOREL-20M** (Sophos/ReversingLabs) | Bucket AWS S3 mở (theo Terms of Use trên GitHub) | ⚠️ **PE "disarmed"** (~10M malware): **zero 2 cờ header** `optional_headers.subsystem` + `file_header.machine` → không chạy trực tiếp. **Benign CHỈ đặc trưng** (EMBER2.0, không có binary benign) | ~10M malware disarmed; nhãn/tag ReversingLabs → có thể lọc **tập con banking** | Terms of Use (GitHub README) — **chưa xác minh chi tiết** |
| **BODMAS** (UIUC/Blue Hexagon) | Đặc trưng/metadata công khai (`bodmas.npz`, `bodmas_metadata.csv`); **binary malware theo yêu cầu** | ⚠️ có **binary malware thật theo request**; benign chỉ hash+feature | 57.293 malware + 77.142 benign PE, **Aug2019–Sep2020**; **581 family** (`bodmas_malware_category.csv`) | Hạn chế bản quyền (binary benign không phát hành); chi tiết **chưa xác minh** |
| **EMBER** | Công khai | ❌ **CHỈ đặc trưng** (vector 2381-d), **không có PE thô** ở bản chuẩn → **KHÔNG dùng được cho BFBG** (cần PE thô để angr lift) | 2017/2018 | mở (BSD-ish, chưa xác minh) |
| **theZoo** | GitHub công khai; zip "infected" | ✅ PE thật (mẫu sống), tập **curated nhỏ** | nhỏ (không quy mô lớn); test gần nhất 2022 | GPL repo; mẫu "chỉ nghiên cứu" |
| **MalShare** | Đăng ký miễn phí → API key; hạn ngạch ~1000–2000/ngày (chưa xác minh) | ✅ PE thật | cộng đồng từ 2013; **không lọc family sẵn** | community, phi lợi nhuận |
| **Malpedia** (FKIE) | **Chưa xác minh** policy mẫu (thường gated cho researcher đã duyệt) | — | tốt làm **tham chiếu phân loại family**, chưa xác nhận là nguồn mẫu ở đây | nghiên cứu, chưa xác minh |

**Hệ quả cho BFBG:** cần **PE thô lift được** → ưu tiên MalwareBazaar (đang dùng), VirusShare, VX-Underground, MalShare.
**EMBER loại** (chỉ feature). **SOREL** chỉ dùng nếu xác minh được binary disarmed (cờ header bị zero) vẫn **lift ra mã x86**
bằng angr/CFGFast và bộ phân-bin toolchain (`validate_tc.py`) không vỡ vì machine=0 — **CHƯA XÁC MINH, cần thử 1 mẫu trước**.
**BODMAS/SOREL có nhãn family** → có thể lọc tập con banking thay vì tải mù.

### 4.3 Phân loại từng family ứng viên (nguồn phân loại; đúng loại banking/loader?)
Trần mẫu = khảo sát MalwareBazaar §4 (metadata, 12MB, sha-dedup). Toolchain **dự kiến** (chưa lift → chưa xác minh).

| Family | Đúng loại? (nguồn) | Trần MB (PE≤12MB) | Khoảng thời gian | Toolchain dự kiến | Ô toolchain lấp |
|---|---|---|---|---|---|
| **Zeus/Zbot** | ✅ banking trojan kinh điển (Malpedia `win.zeus`; nhiều nguồn) | **357** | ~2007–2013 | **MSVC đời cũ (≤10/11-12)** | malware MSVC≤10 (khớp đời benign ô #1) |
| **Gozi/ISFB/Ursnif/Snifula** | ✅ banking lineage; Gozi v1.0 2006, v2.0=ISFB, rò source 2010 → GozNym/Vawtrak; sau chuyển hướng backdoor (Mandiant) — Malpedia `win.isfb` | **157** (tên "Gozi"); Ursnif/ISFB=0 dưới tên đó (umbrella "Gozi") | ~2006–nay | MSVC đời cũ→vừa | MSVC≤10/11-12 |
| **Zloader** (Terdot/DELoader/Zeus Sphinx) | ✅ loader giao payload (có module Zeus) — Malpedia `win.zloader` / MISP banker | **90** | ~2016–nay | **MSVC14** (hiện đại) | malware MSVC14 |
| **Qakbot/Qbot** | ✅ banking trojan (2007) → loader/IAB mô-đun; #1 loader 2023 (ReliaQuest); Trend Micro, Microsoft "Gold Lagoon" | **0 qua MB** (get_siginfo không trả) → cần VX/VirusShare/MalShare | ~2007–2023 | MSVC14 | malware MSVC14 |
| **Ramnit** | banking trojan (gốc là worm) — **phân loại chưa xác minh lần tra này**; xác minh Malpedia `win.ramnit` | **31** | ~2010–nay | MSVC đời vừa | MSVC11-12/14 |
| **Carbanak/Anunak** | ⚠️ **phần lớn nguồn gọi BACKDOOR** của FIN7/Cobalt (dựng trên source Carberp); MITRE G0008/G0046; vài nguồn gọi banking/RAT → **KHÔNG phải banking-trojan kinh điển** | — | ~2013–nay | — | **ĐỀ XUẤT LOẠI** (construct-validity, như SystemBC) |

**Kết luận phân loại:** nhận **Zeus, Gozi, Zloader, Qakbot** (banking/loader đúng loại). **Ramnit** nhận **sau khi xác minh**
Malpedia. **Carbanak LOẠI** (backdoor APT, lệch lớp hành vi — lặp lỗi RQF-02/SystemBC). SystemBC vẫn loại (proxy).

### 4.4 VX-Underground theo family (nguồn phụ, thủ công)
- Đã có **8 mẫu VX import thủ công** (`DATASET.md`). VX phát hành theo **collection/family** dạng file-share
  (không có API `get_siginfo`) → **trần = ước lượng sau khi tải thủ công từng collection**, không khảo sát tự động được.
- **Danh mục (CHƯA XÁC MINH):** nguồn thứ ba liệt kê collection top-level gồm ATM Malware, Argus, Bazaar,
  **Families**, InTheWild, Twitter IOC, VirusSign, VirusShare. Site `vx-underground.org` **chặn fetch tự động (403)**
  → không liệt kê được nội dung bộ **Families** cụ thể ở đây; cần duyệt thủ công trên site.
- **CHƯA tải bộ Qakbot nào trong phiên này.** Tải VX cần thao tác thủ công + xác minh mật khẩu/nhãn + đúng loại banking
  → **hoãn, hỏi trước**. Hữu ích để lấy family MB **không trả** (Qakbot, Ursnif/ISFB dưới tên riêng) sau khi xác minh.
  Ghi nguồn + hash như mẫu VX hiện có.

### 4.5 Pilot tải thử MalwareBazaar — ĐO THẬT (seed 20261015, 2026-10-15) — KHÔNG khóa vào v4
Tải 25 mẫu/họ vào `data/raw/pilot_v4_malicious/<family>` (**RIÊNG**, không chạm v1/v2/v3). Lift: workers=4,
MemoryMax=14G, nice 19, timeout 900, `--append`, OOM (ProcessCrash exit-9) tách Timeout. Out-dir riêng
`data/features_graph_pilot_v4`. Scripts: `pilot_malware_v4_fetch.py` / `pilot_malware_v4_report.py`.
Quy tắc loại/dedup khóa **trước** khi tải (sha256 vs **1967** sha cũ, size≤12MB, .NET loại ở lift, rơi không thay thế).

| họ | tải | lift OK | .NET | rơi | native% | rơi% | trùng sha256 (cũ) | trùng ppdeep≥90 (5 họ cũ) |
|---|---|---|---|---|---|---|---|---|
| Zeus | 25 | 25 | 0 | 0 | 100% | 0% | 0 | 0 |
| Gozi | 25 | 23 | 2 | 0 | 92% | 0% | 0 | 0 |
| Zloader | 25 | 22 | 1 | 2 | 96% | 8% | 0 | 0 |
| **TỔNG** | **75** | **70** | **3** | **2** | **96%** | **3%** | **0** | **0** |

- **Rơi:** 2× `UnicodeDecodeError` (Zloader; cle/pe `forwarder.decode`) — **0 Timeout, 0 OOM/ProcessCrash**.
- **Linker major (pefile):** Zeus **nghiêng cũ** (v9×10, v10×5, v1–v8 còn lại → **MSVC≤10** đúng dự kiến);
  Gozi hỗn hợp (v9/v10 trội + v14×6); Zloader **lưỡng cực** (v1–v8 cũ + v14×9 hiện đại).
- **Đọc kết quả:** yield cao (native 96%, .NET 4%, rơi 3%, 0 timeout/OOM) → MB là nguồn tốt, lift ổn định.
  **0 trùng sha256 + 0 trùng ppdeep≥90 với 5 họ hiện có** → 3 họ mới KHÁC BIỆT dataset cũ.
- **CHƯA đo near-dup NỘI BỘ từng họ mới** (chỉ 25 mẫu) → khác biệt sau pull đầy đủ **vẫn theo dải §4.1 (20–50%)**,
  cần ppdeep nội bộ khi tải thật. Pilot chỉ xác nhận **yield + khác biệt chéo-họ**, **KHÔNG khóa vào v4** (cổng vẫn đóng).

### 4.6 Full pull (ĐO THẬT, 2026-10-15) — tải đủ Zeus/Gozi/Zloader/Ramnit, lift, ppdeep cụm — KHÔNG khóa v4
Tải hết candidate (`get_siginfo` ≤500/alias, size≤12MB, loại sha trùng 1967 cũ) vào thư mục RIÊNG; lift
workers=4/14G/nice19/timeout900/RuntimeMaxSec=7h30, OOM(ProcessCrash exit-9) tách Timeout, resumable
(stage symlink mẫu chưa lift). Scripts: `pilot_malware_v4_fetch_full.py` / `pilot_malware_v4_report_full.py`.
Mạng serial (≤3 luồng), backoff 429/502/503 trong `api_query`. **Ramnit thêm vì xác minh banking** (Malpedia/Check Point).

| họ | tải | lift OK | .NET | rơi (nguyên nhân) | **distinct nội bộ (ppdeep≥90)** | trùng 5 họ cũ |
|---|---|---|---|---|---|---|
| Zeus | 357 | 353 | 1 | 3 Timeout | **337** | 0 |
| Gozi | 157 | 145 | 8 | 3 Timeout, 1 IndexError | **131** | 0 |
| Zloader | 90 | 86 | 1 | 2 UnicodeDecodeError, 1 Timeout | **61** | 0 |
| Ramnit | 31 | 30 | 0 | 1 CLEError | **30** | 0 |
| **TỔNG** | **635** | **614** | **10** | **11** | **559** | **0** |

- **Chéo toàn bộ (gộp 4 họ):** 614 → **559 cụm khác biệt, 0 cụm lẫn >1 họ** → 4 họ tách biệt nhau ở ppdeep≥90.
- **Distinct theo DÒNG MÃ NGUỒN (cho gán split):** Zeus-lineage (Zeus+Zloader) 439→**398**; Gozi-lineage 145→**131**;
  Ramnit **30**. (398 = 337+61 → Zeus↔Zloader **không** near-dup nhau ≥90 dù cùng dòng Zeus.)
- **0 trùng ppdeep≥90 với 708 mẫu cũ** → toàn bộ **559 khác biệt** so dataset hiện có.
- **Linker major:** Zeus **trội MSVC≤10** (v9×102, v10×53, v8×40, v6×41, v7×31 ≈ 267/353; vài giá trị rác
  v161/v242/v255 = header pack/hỏng); Gozi v9/v10/v14; Zloader v14×38 (hiện đại) + đời cũ; Ramnit v9/v6/v8.
- **Yield** cao (lift-OK 614/635 = 96.7%; .NET 1.6%; rơi 1.7%, trong đó Timeout 7 = mẫu pack/nhiều hàm).
- **Khác biệt THẬT thu được: 559** (đã tải+lift+dedup, **CHƯA khóa vào v4**). Nếu khóa → 708 + 559 = **1267 distinct**.
  **Rơi KHÔNG thay thế** (yield phản ánh thật).

---

## 5. KẾ HOẠCH v4 (mục tiêu, nguồn, thứ tự, thời gian, rủi ro, ngưỡng khóa)

### 5.1 Mục tiêu theo ô (benign) — thực dụng, KHÔNG ép khớp 1:1
> **CHỐT 2026-10-16 (a) — chuyển sang mục tiêu CẤP BIN (theo pilot §10).** Pilot cho thấy ô MSVC≤10×256K-1M
> (yield 7%) và MSVC11-12 (0) **không lấp được** ở quy mô mục tiêu bằng nguồn tải tự động. → **Bỏ ràng buộc
> SIZE cho các bin cũ; đặt mục tiêu theo BIN toolchain** (gộp mọi size), dùng reweight theo bin ở loader:
> - **MSVC≤10 (mọi size):** gom hết thu được (NirSoft phủ `<256K`); **KHÔNG ép ≥100 ở 256K-1M**.
> - **MSVC11-12:** gộp vào bin **"MSVC-cũ (≤12)"** khi đánh giá; **không mục tiêu số riêng**.
> - **MSVC14 × 256K-1M và MSVC14 × 1-4M:** giữ **≥100 mỗi ô** (khả thi từ Scoop — đang thu, §9/§11).
> **HẠN CHẾ (ghi trong bài):** bin **MSVC≤10 benign** gồm chủ yếu mẫu **nhỏ (<256K)** và **gần một vendor (NirSoft)**
> → **không kiểm được bất biến toolchain TRONG bin này** (lệch vendor + size); bất biến chỉ đánh giá được ở bin MSVC14.

(Lịch sử — mục tiêu theo-ô ban đầu, đã thay bằng cấp-bin ở trên:) Khớp 1:1 cần ~1085 benign (§2) — khó khả thi.
Mục tiêu cũ: mỗi ô LỚN có ≥100 benign/phía; ô nhỏ ≥20.

| Ô thiếu (§2) | benign hiện | mục tiêu v4 | nguồn chính |
|---|---|---|---|
| #1 MSVC≤10 × 256KB–1MB | 23 | **≥100** | NirSoft (cap vendor) + PortableApps cũ + freeware cũ + SourceForge/GitHub tag cũ |
| #2 MSVC14 × 256KB–1MB | 57 | **≥100** | GitHub OSS release có ký (dư MSVC14) + Scoop |
| #3 MSVC14 × 1–4MB | 87 | **≥100** | như #2 |
| #4 MSVC11-12 × 256KB–1MB | 6 | **≥20** | Scoop Versions, GitHub tag 2012–2015 |
| #5 MSVC11-12 × 1–4MB | 3 | **≥20** | như #4 |
| #6 MSVC11-12 × <256KB | 0 | **≥20** | như #4 (khó nhất — bin đang rỗng) |

### 5.2 Mục tiêu malware
- Từ **708 khác biệt** hiện có → thêm Zeus/Gozi/Zloader/Ramnit (~125–315 khác biệt ước lượng) →
  **~833–1023 khác biệt**. Ưu tiên **Zeus** (lấp malware MSVC≤10, cân với benign ô #1).
- Ngưỡng đề xuất: hướng tới **~1500 mẫu malware KHÁC BIỆT** (sau ppdeep) → có thể cần thêm 1–2 family banking
  đúng loại nữa (ví dụ qua VX-Underground: Ursnif/ISFB/QakBot nếu xác minh được nhãn).

### 5.3 Thứ tự thực hiện (đề xuất)
1. **Pilot benign seed 20261015** (4–5 nguồn × 25) → chốt nguồn nào cho ô nào theo yield thật. *(cần duyệt tải)*
2. **Lift + ppdeep benign pilot** → cập nhật §3.3 bằng số thật; loại nguồn yield thấp.
3. **Thu benign theo ô** (ưu tiên ô #1→#3), áp cap vendor ≤35%/bin + cap GNU/Go/Rust ≤10% tổng.
4. **Thu malware Zeus** (lấp MSVC≤10) → Gozi → Zloader → Ramnit; lift + ppdeep; báo **khác biệt** theo family.
5. **(tuỳ chọn) VX-Underground** cho family MB thiếu, nếu xác minh nhãn.
6. **Đóng băng v4** (manifest + hash + split group-aware) khi đạt ngưỡng §5.5; rồi **mới** chạy lại GRL.

### 5.4 Ước lượng thời gian build (dựa trên nhịp đã quan sát)
- **Lift (angr/CFGFast):** ~vài phút–15'/mẫu (timeout 900s cho Rust/Go/pack). ~500 mẫu mới ≈ **1–2 ngày máy**
  (CPU chạm ~100°C dưới tải — người dùng lo tản nhiệt; guard report-only).
- **ppdeep dedup:** nhanh (phút) trên vài trăm–nghìn file.
- **Tải:** benign payload (giải nén lồng) chậm hơn malware (zip AES "infected" giải trong RAM); ~nguồn/buổi.
- **Tổng tới khi khóa v4:** ước lượng **~1 tuần máy** nếu nguồn benign ô #1 đạt yield đủ; **rủi ro kéo dài** nếu ô #1/#6 thiếu.

### 5.5 Ngưỡng ĐỦ để khóa v4 (đề xuất — chốt với người dùng)
- **Benign (CHỐT 2026-10-16 (a) — CẤP BIN, không ép size cho bin cũ):**
  - **MSVC14 × 256K-1M ≥100** và **MSVC14 × 1-4M ≥100** (ô khả thi), chia train/test qua group-aware CV.
  - **MSVC≤10 (mọi size):** gom hết thu được (không ngưỡng số cứng); **bin này KHÔNG dùng để kiểm bất biến toolchain**
    (lệch <256K + một vendor NirSoft — xem hạn chế §5.1).
  - **MSVC11-12:** gộp vào bin "MSVC-cũ (≤12)"; không ngưỡng riêng.
  - Ràng buộc chung: **không vendor nào >35%/bin**; **không Microsoft/ISO >30–40% tổng**; GNU/Go/Rust **≤10% tổng**.
- **Malware:** **~1500 mẫu khác biệt** (sau ppdeep), trải đủ MSVC≤10 / 11-12 / 14 để cân với benign; mỗi family
  báo **(số mẫu, số khác biệt, % trùng)** — không báo số thô mà không kèm số khác biệt.
- **Bất biến dedup:** 0 cụm lẫn nhãn; không mẫu v4 nào `ppdeep≥90` với holdout v2/v3; v4 không sửa v1/v2/v3.

### 5.6 Ô có NGUY CƠ không đủ
- **#6 MSVC11-12 × <256KB** (benign đang = 0): toolchain đời 2012–2015, size rất nhỏ — hiếm cả benign lẫn
  nguồn ổn định. Có thể **không đạt ≥20** → phương án B: gộp MSVC11-12 vào một bin "MSVC-cũ" khi đánh giá, hoặc
  **reweight theo bin** ở loader thay vì ép đủ số.
- **#1 MSVC≤10 × 256KB–1MB** (+611): quá lớn để khớp 1:1 bằng benign dễ-tìm (đa số rơi vào size khác / MSVC14).
  Phụ thuộc nặng NirSoft → **rủi ro confound một-vendor** (kiểu ISO-65% nhưng ở cấp bin) nếu không đủ vendor khác.

---

## 6. Trước khi tải — CẦN người dùng duyệt
- [ ] Duyệt **pilot benign seed 20261015** (4–5 nguồn × 25, chỉ pilot, chưa bulk).
- [ ] Duyệt **tải malware** Zeus/Gozi/Zloader/Ramnit (và/hoặc VX-Underground).
- [ ] Chốt **ngưỡng khóa v4** ở §5.5 (≥100/ô lớn/phía, ~1500 malware khác biệt) hoặc điều chỉnh.
- [ ] Không chạm v1/v2/v3/holdout; v4 là tập mới; không push (người dùng push).

---

## 7. Xác minh nhãn bằng VirusTotal — TIỀN-ĐĂNG-KÝ (ghi 2026-10-15, TRƯỚC khi tra)
Tài khoản VT (key chỉ trong `.env`, không commit/không in). **Tier free: chỉ TRA CỨU** (500/ngày, 240/giờ,
4/phút; **intelligence_downloads=0 → KHÔNG tải mẫu qua VT**). Không train, không chạm holdout. Cổng vẫn ĐÓNG.

### 7.1 Malware mới (614 mẫu lift-OK, §4.6)
- Tra `GET /api/v3/files/{sha256}` → lấy `last_analysis_stats.malicious`, `popular_threat_classification`
  (`suggested_threat_label` + `popular_threat_name`). **Đối chiếu nhãn MalwareBazaar** (family fetch).
- **Chỉ BÁO** mức đồng thuận family (khớp / lệch / không thấy trên VT). Các mẫu này **chưa khóa v4** nên
  không xóa gì; dùng để **củng cố ngưỡng "nhãn v4 đã xác minh"** trước khi khóa.

### 7.2 Benign v1–v3 (~669 = 504 raw v1/v2 + 165 v3) — NGƯỠNG LOẠI CHỐT TRƯỚC KHI TRA
- Tra hash → `last_analysis_stats.malicious` (số engine gắn cờ).
- **NGƯỠNG TIỀN-ĐĂNG-KÝ: `malicious ≥ 3 engine` → ĐÁNH DẤU "benign-nghi-ngờ".**
- **KHÔNG xóa khỏi v1/v2/v3 đã khóa** (bất biến immutable). Chỉ: (a) **báo** danh sách + số engine;
  (b) tính lại **metric PHỤ** (ví dụ FPR/AUC khi loại/giữ các mẫu bị đánh dấu) như một **ablation**, không
  thay số liệu v1/v2/v3 gốc. 1–2 engine gắn cờ = **không** đủ ngưỡng (nhiễu/heuristic) → chỉ ghi chú.
- Lý do chọn ≥3: giảm dương-tính-giả của một engine đơn lẻ; ngưỡng chốt **trước** khi nhìn kết quả để tránh
  chọn ngưỡng theo số liệu.

### 7.3 Vận hành
- Rate-limit **4/phút** (sleep ~16s), **<500/ngày**, **resumable** (bỏ qua hash đã tra), lưu **kết quả thô**
  (`data/vt/raw/<sha>.json`) + tóm tắt (`data/vt/vt_summary.jsonl`). Xử lý 429 (chờ), 404 = không thấy.
- Thứ tự: (1) malware 614 trước, (2) benign 669 sau. Vì cap 500/ngày < 1283 → chạy **nhiều ngày**, resume.
- Script: `experiments/dataset/pilots/vt_lookup.py`. Key đọc từ `.env`, **không bao giờ in/commit**.
- `data/vt/*` nằm trong `data/*` → **gitignored** (không commit mẫu/thô); chỉ commit script + báo cáo tổng hợp.

---

## 8. Khảo sát BODMAS (CHỈ khảo sát, 2026-10-15) — KHÔNG tải mẫu, KHÔNG khóa v4
Clone `github.com/whyisyoung/BODMAS` (shallow) vào `~/bfbg_benign_work/bodmas_survey/` (ngoài `data/`,
ngoài `v4_benign/`). Không dừng/sửa unit `bfbg-v4benign`/VT.

### 8.1 Cấu trúc & truy cập
- **Repo git = chỉ CODE + README + LICENSE** (BSD 2-Clause cho code). **KHÔNG có** danh sách sha/nhãn,
  **KHÔNG có** binary trong repo.
- Dữ liệu ở **Google Drive** (trang `whyisyoung.github.io/BODMAS`): `bodmas_metadata.csv` (12.1MB:
  cột `sha, timestamp, family`; family rỗng = benign), `bodmas_malware_category.csv` (3.9MB),
  `bodmas.npz` (249MB, feature). **Binary malware CHỈ xin qua email** (disarmed — README repo ghi
  "binaries (disarmed malware only)"; trang Download **không** nhắc lại "disarmed" → **chưa xác minh** disarmed).
- **Xin binary (nguyên văn trang):** email **Pirouz Naghavi `pirouz.naghavi@gmail.com`**, CC **Dr. Gang Wang
  `gangw@illinois.edu`** (liminy2@illinois.edu, zhic4@illinois.edu đã tốt nghiệp). Điều kiện: không chia sẻ
  lại; nêu vài câu kế hoạch; academic dùng email + webpage trường; industrial dùng email công ty + thư PDF;
  kèm địa chỉ Gmail để được add vào Drive. License dữ liệu: **trang không nêu** (README repo ghi BSD-2) → **chưa xác minh**.
- Mình chỉ tải **2 CSV metadata** (không phải mẫu); npz 261MB lỡ tải đã **xóa**.

### 8.2 Họ banking/loader trong BODMAS (lọc từ metadata; 134.435 dòng, 582 họ, 77.142 benign)
| họ (nhãn BODMAS) | số sha | trùng dữ liệu cũ | MB `get_info` có | MB không |
|---|---|---|---|---|
| zbot (Zeus) | 473 | 0 | 0 | 473 |
| emotet | 56 | 0 | 1 | 55 |
| ursnif (Gozi) | 43 | 0 | 0 | 43 |
| qakbot | 42 | 0 | 1 | 41 |
| pwszbot (Zeus) | 34 | 0 | 0 | 34 |
| tinba | 23 | 0 | 0 | 23 |
| carberp | 14 | 0 | 0 | 14 |
| trickbot (+crypt) | 14 | 0 | 1 | 13 |
| gozi | 13 | 0 | 0 | 13 |
| dridex | 10 | 0 | 0 | 10 |
| qbot | 9 | 0 | 0 | 9 |
| nymaim | 8 | 0 | 0 | 8 |
| icedid | 5 | 0 | 0 | 5 |
| spyeye | 2 | 0 | 0 | 2 |
| vawtrak | 1 | 0 | 0 | 1 |
| **TỔNG** | **747** | **0** | **3** | **744** |

- **0/747 trùng sha256** với toàn bộ dữ liệu cũ (v1-v3 + 614 malware mới; 2813 sha) — BODMAS 2019-2020, mẫu khác.
- **MalwareBazaar chỉ có 3/747** (`get_info`, không `get_file`) → **BODMAS KHÔNG lấy được qua MB**; muốn binary
  phải qua **email BODMAS** (disarmed, chưa xác minh). (SpyEye/Tinba/Carberp/Nymaim/Vawtrak không tìm được ở MB.)

### 8.3 Ước lượng & ô toolchain (chưa có binary → chưa bin được)
- **Khác biệt sau dedup (ƯỚC LƯỢNG):** không có binary → **không ppdeep được** → chỉ áp dải near-dup họ
  banking 20–50% → ~**150–375 khác biệt** (CHƯA XÁC MINH; sha-dedup chính xác đã 0 trùng).
- **Giá trị bổ sung:** **Qakbot 51 (qakbot 42 + qbot 9)** — họ MB **không trả** qua `get_siginfo` (§4) → BODMAS
  là một đường lấy Qakbot (nhưng phải qua email). **Họ MỚI** chưa có trong tập: **tinba 23, carberp 14, nymaim 8,
  spyeye 2, vawtrak 1**. zbot/pwszbot 507 (dòng Zeus, bổ sung lớn); ursnif/gozi 56 (dòng Gozi).
  trickbot/dridex/icedid/emotet trùng loại đã có (mẫu khác).
- **Ô toolchain dự kiến (CHƯA XÁC MINH — cần binary để bin):** zbot/pwszbot/carberp/tinba/gozi/ursnif → dự kiến
  **MSVC đời cũ (≤10/11-12)**; qakbot/trickbot/dridex/icedid → dự kiến **MSVC14**.
- **Họ còn thiếu để chạm ~1500:** Qakbot và các họ banking cũ (tinba/carberp/...) — BODMAS lấp được **nếu** xin
  được binary qua email; nếu không, phải tìm nguồn khác (VX-Underground/VirusShare).

### 8.4 Kết luận & trạng thái
BODMAS = nguồn **có nhãn family tốt** (**747 banking, 0 trùng** dữ liệu cũ) nhưng **binary chỉ qua email**
(**disarmed — CHƯA XÁC MINH**; MB chỉ có 3/747). Dùng làm **phương án nếu được cấp Drive**; không phải nguồn
tải tự động như MB.
- **Trạng thái: CHỜ PHẢN HỒI** — yêu cầu binary gửi qua email (`pirouz.naghavi@gmail.com`, CC `gangw@illinois.edu`);
  **tính đến 2026-10-15 CHƯA gửi/ chưa có phản hồi** (mình không gửi email thay; người dùng gửi). Điều kiện xin:
  không chia sẻ lại, nêu vài câu kế hoạch, academic email + webpage trường / industrial email + thư PDF, kèm Gmail
  để được add Drive.
- **KHÔNG tính ~150–375 (ước lượng khác biệt) vào cổng dữ liệu §0.1** — chưa có binary, chưa lift, chưa dedup
  ppdeep, chưa khóa. Dòng "malware khác biệt" ở §0.1 **giữ nguyên 708**; BODMAS chỉ cộng vào cổng **sau khi** xin
  được binary + lift + ppdeep + khóa manifest.

### 7.4 Kết quả VT malware (490/614 đã tra, 2026-10-15) — ngưỡng §7.1 khóa trước khi tra
Đối chiếu `popular_threat_name`/`suggested_threat_label` của VT với nhãn family MalwareBazaar (theo dòng mã nguồn).
Script `vt_report.py`. Chưa tra thêm tới ngày mai (hạn mức 500/ngày đã dùng).

| họ (nhãn MB) | đã tra | khớp họ | khác-họ | mẫu <3 engine | không trên VT |
|---|---|---|---|---|---|
| Zeus | 277 | 226 | 51 | 0 | 0 |
| Gozi | 119 | 58 | 60 | 0 | 1 |
| Zloader | 74 | 46 | 28 | 0 | 0 |
| Ramnit | 20 | 9 | 11 | 0 | 0 |
| **TỔNG** | **490** | **339 (69%)** | **150** | **0** | **1** |

- **0 mẫu <3 engine** → **mọi mẫu đều malicious** (≥3 engine gắn cờ); không có mẫu lành/giả. Nhãn "malware" vững.
- **339/490 (69%) khớp family** ở mức token (zbot/zeus; gozi/ursnif; zloader; ramnit).
- **150 "khác-họ" KHÔNG = nhãn MB sai**: VT `popular_threat_name` thường gán nhãn **generic/đồng-xuất-hiện** khác
  (vd Zeus→`upatre`/`waski`/`katusha`; Ramnit→`loki`/`zenpak`/`carberp`; Gozi→`stop`/`azorult`/`fragtor`).
  Việc **đặt tên family không đồng thuận giữa engine** là đã biết; vài nhãn lệch (vd `locky`) gợi ý MB-tag
  **không phải ground-truth tuyệt đối** cho mọi mẫu → **cần VT cross-check trước khi khóa nhãn v4**.
- **Mẫu nghi (benign):** chưa — chưa tra benign (ưu tiên malware trước; benign 669 tra ngày mai).
- Còn lại: **124 malware + 669 benign** tra **ngày mai** (quota reset), resumable từ `vt_summary.jsonl`.

---

## 9. Harvest benign v4 — PHIÊN 1 (2026-10-15, Scoop only) — KHÔNG khóa v4
Quy tắc `V4_BENIGN_RULES_FROZEN.md`, seed 20261015, isolation `~/bfbg_benign_work/v4_benign*`. Nguồn phiên này:
**Scoop Main+Extras+Versions** (các nguồn khác chưa viết fetcher — xem pilot §10). Dừng sạch giữa chừng (resumable).

| ô mục tiêu | kept (pre-lift) | lift-OK | mục tiêu | thiếu (§2) |
|---|---|---|---|---|
| MSVC≤10 × 256K-1M (ô #1) | **7** | 3 | 100 | 77 |
| MSVC14 × 256K-1M | 37 | 21 | 100 | 43 |
| MSVC14 × 1-4M | 86 | 60 | 100 | 13 |
| MSVC11-12 × 256K-1M | 0 | 0 | 20 | 14 |
| MSVC11-12 × 1-4M | 0 | 0 | 20 | 17 |
| MSVC11-12 × <256K | 0 | 0 | 20 | 20 |

- 338 app xử lý · **130 kept** (pre-lift) · **84 lift-OK** (46 kept chưa lift do dừng giữa chừng — resumable,
  0 nf0/.NET/build_fail trong phần đã lift) · dedup loại **43** (37 sha256 + 6 ppdeep≥90) · **skip_nontarget 2.520**
  · app_fail 31 · ~124 phút.
- **Linker major (kept): 123×v14, 7×v2** → Scoop (kể cả Versions) **gần như chỉ ra MSVC14 hiện đại**.
- **Đọc kết quả:** MSVC14 (ô #2/#3) **đạt/vượt mức thiếu** (kept 37 & 86 vs thiếu 43 & 13). **Ô #1 MSVC≤10
  gần như không nhích (7)** và **MSVC11-12 = 0** từ Scoop → cần nguồn khác (NirSoft/PortableApps/GitHub-cũ/freeware).
- **Cổng vẫn ĐÓNG:** 130 benign này ở thư mục riêng, **chưa khóa v4**, chưa tính vào §0.1.

---

## 10. PILOT nguồn mới cho ô #1 & MSVC11-12 (seed 20261016, 2026-10-15) — chỉ đo yield
Pilot NirSoft + PortableApps (isolation `~/bfbg_benign_work/v4_pilot2/`, không đụng v4_benign/). Quy tắc dedup
`V4_BENIGN_RULES_FROZEN.md`. **Sửa lỗi binning:** old-MSVC (linker 6-8, không Rich, import `msvcrt`) trước bị
`tc_bin` phân nhầm GNU/MinGW; đã sửa (chỉ gọi GNU khi có `.eh_frame`/mingw-dll) — áp cho pilot này và các phiên sau.

### NirSoft (nguồn MSVC≤10 chính) — 25 app random
- 25 app → **15 giữ** (9 loại `dedup_sha256` = đã có trong v2/v3 holdout). **13/15 = MSVC≤10** (đúng, sau sửa bin).
- **Phân bố size MSVC≤10: `<256K`=11, `256K-1M`=1, `1-4M`=1** → **ô #1 (MSVC≤10 × 256K-1M) yield = 1/15 = 7%** (<10%).
- **MSVC11-12 = 0**.
- **Lý do cấu trúc:** tiện ích MSVC đời cũ (NirSoft) **gần như toàn <256K** (tí hon); binary **256K-1M** lại
  chủ yếu **MSVC14 hiện đại** → ô #1 là **mismatch toolchain-cũ × size-vừa**.

### PortableApps / GitHub-SourceForge cũ / freeware cũ
- **PortableApps**: build **hiện đại = MSVC14** (vd IrfanView 4.75) → **không lấp MSVC≤10**; server download bị
  throttle (~11KB/s) → pilot không hoàn tất (không đáng theo đuổi vì sai bin đích).
- **GitHub/SourceForge release cũ + freeware cũ**: cần **URL phiên-bản-cũ thủ công (2008–2012)**; không tự động
  hóa trong pilot gọn; dự kiến yield thấp, công sức cao.

### KẾT LUẬN — ô #1 & MSVC11-12 KHÔNG lấp được ở quy mô mục tiêu (khả thi thu thập)
- **Ô #1 (MSVC≤10 × 256K-1M)**: yield 7% từ nguồn tốt nhất (NirSoft) → **không đạt ≥100** bằng nguồn tải tự động.
- **MSVC11-12 (mọi size)**: 0 từ mọi nguồn thử → toolchain 2012–2015 đời ngắn, **hiếm**.
- **KHÔNG viết fetcher quy mô lớn** cho các nguồn này (theo lệnh).

### Mục tiêu THỰC TẾ đề xuất (sửa §5.1/§5.5)
1. **Bỏ ép ≥100 cho MSVC≤10 × 256K-1M**. Thay bằng: (a) **gộp theo bin toolchain, bỏ ràng buộc size**
   (MSVC≤10 mọi size — NirSoft phủ tốt `<256K`), và/hoặc (b) **reweight theo bin ở loader** thay vì khớp từng ô size.
2. **MSVC11-12**: **gộp vào bin "MSVC-cũ (≤12)"** khi đánh giá; **không** đặt mục tiêu số riêng.
3. Giữ **≥100 chỉ cho ô khả thi**: MSVC14 × 256K-1M và MSVC14 × 1-4M (đã gần đạt từ Scoop, §9).

### HẠN CHẾ cần nêu trong bài (threats to validity)
- Benign v4 **không khớp 1:1 toolchain×size** với malware ở các ô MSVC≤10/11-12 × size-vừa → **confound toolchain/size
  còn dư** ở những ô đó; đây là **giới hạn khả thi của thu thập**, không phải lựa chọn theo kết quả.
- Benign MSVC≤10 **lệch về `<256K` và một vendor (NirSoft)** → confound **vendor + size** (giống rủi ro ISO-65% nhưng ở cấp bin).
- Cổng dữ liệu §0.1: giữ nguyên; các ô MSVC≤10/11-12 **đánh dấu "không khả thi đạt mục tiêu"** thay vì treo mãi.

---

## 11. Cập nhật 2026-10-16 — Zeus-lineage nhóm riêng + nguồn benign cũ thủ công

### 11.1 Đề xuất: Zeus-lineage là NHÓM RIÊNG, KHÔNG vào train chính
- Malware mới (§4.6): **Zeus-lineage (Zeus+Zloader) = 398 distinct**, **nghiêng mạnh MSVC≤10** (linker v6–v10,
  §4.6). Benign MSVC≤10 lại **yếu + lệch một vendor (<256K, NirSoft)** và **không lấp được ô size-vừa** (§10).
- **Rủi ro nếu đưa Zeus-lineage vào train/test chính:** mô hình có thể **tách theo toolchain** (MSVC≤10 ≈ malware
  Zeus-lineage vs benign MSVC14) → **confound toolchain lặp lại** đúng thứ đang cố khử. Benign không cân được bin
  MSVC≤10 → không trung hòa được.
- **Đề xuất:** giữ **Zeus-lineage như một NHÓM ĐÁNH GIÁ RIÊNG** (cross-lineage holdout / tập "confound-stress"),
  **KHÔNG trộn vào train chính cân-bin**. Train/test chính dùng family có thể cân benign (nghiêng MSVC14:
  TrickBot/Dridex/IcedID/BumbleBee hiện tại + Zloader phần MSVC14 nếu tách được). Zeus (MSVC≤10) báo riêng.
- **Gán split theo DÒNG MÃ NGUỒN** vẫn giữ (Zeus+Zloader cùng nhóm, không tách qua train/test) — §4.6.
- Chốt cuối khi khóa v4; đây là đề xuất, **chưa khóa, chưa train**.

### 11.2 Nguồn benign CŨ thủ công cần người dùng tìm (cho bin MSVC≤10/11-12 × 256K-1M)
Pilot §10: nguồn tự động (Scoop/NirSoft/PA) **không** cho MSVC≤10 ở size 256K-1M. Cần **URL phiên-bản-cũ ổn định**
(2008–2015, build MSVC gốc, chưa repack). Gợi ý nơi tìm (người dùng xác minh URL + tính hợp pháp + chưa xác minh):
- **oldversion.com**, **FileHippo "older versions"**, **Softpedia (old builds)**, **MajorGeeks**, **SourceForge
  "Files/OldFiles"** của từng project.
- Project MSVC đời cũ có bản 256K-1M: **7-Zip 9.20 (2010)**, **Notepad++ 5.x (2009)**, **IrfanView 4.2x–4.3x**,
  **PuTTY 0.60–0.62**, **WinSCP 4.x**, **FileZilla 3.3–3.5**, **Pidgin 2.6–2.10**, **Audacity 2.0.x**,
  **VLC 1.1.x**, **GIMP 2.6 (một phần)**, **HeidiSQL (Delphi, cho bin khác)**.
- **Yêu cầu khi gửi mình:** link tải trực tiếp (.exe/.zip payload, KHÔNG installer web), ghi phiên bản + năm.
  Mình sẽ áp đúng `V4_BENIGN_RULES_FROZEN.md` (dedup sha+ppdeep, size≤12MB, loại installer/forwarder/3rd-party/.NET,
  bin bằng bộ đã sửa) và báo yield theo bin — **chỉ khi bạn cấp URL** (không tự cào quy mô lớn).
- **Lưu ý cap vendor:** tránh lại dồn một vendor; ưu tiên **đa dự án** để bin MSVC≤10 không lệch một nguồn.

---

## 12. Harvest benign v4 — PHIÊN 2 (2026-10-16, chỉ 2 ô MSVC14) + cap vendor trên số thật
Resume phiên 1, bộ bin đã sửa (GNU chỉ khi `.eh_frame`/mingw-dll), chỉ nhắm MSVC14×256K-1M & ×1-4M. Dừng sạch
(resumable). Số là **tích lũy v4 benign** (phiên 1+2).

| ô | kept (pre-lift) | lift-OK (sau khi lift nốt 61) | mục tiêu | còn |
|---|---|---|---|---|
| MSVC14 × 1-4M | **95** | **94** | 100 | +6 |
| MSVC14 × 256K-1M | **43** | **43** | 100 | +57 |
| MSVC≤10 × 256K-1M | 7 | **7** | (bỏ ép, §5.1) | — |

**Lift-OK thật (2026-10-16): 144/145** (lift nốt 61 mẫu tồn; 0 rơi trong kept, 1 mẫu không tạo feature — bỏ qua).

- 381 app xử lý · **145 kept** · 84 lift-OK (61 chưa lift — resumable, 0 nf0/.NET/fail trong phần đã lift)
  · nguồn Extras 97 / Main 28 / Versions 20 · dedup loại **53** (47 sha256 + 6 ppdeep≥90) · skip_nontarget 3.093 · app_fail 33.

### 12.1 Cap vendor ≤35%/bin + ISO ≤35% — TÍNH TRÊN SỐ THẬT (kept v4)
(vendor = app Scoop, proxy; publisher thật không track nhưng app Scoop đa dạng)
- **bin MSVC14 (n=138):** vendor nhiều nhất = `skylark` 3 mẫu = **2%** (56 app khác nhau) → **≤35% ✓** (rất phân tán).
- **bin MSVC≤10 (n=7):** vendor nhiều nhất = `tsukimi` 3 mẫu = **43% > 35%** — NHƯNG n=7 (quá nhỏ) và bin này
  **không dùng kiểm bất biến** (§5.1); khi gom MSVC≤10 đầy đủ phải siết cap lại. **Ghi cờ.**
- **ISO (Windows ISO): 0%** trong v4 (v4 là Scoop-only; ISO chỉ nằm ở train v1/v2 cũ). Cap ISO ≤35% **đạt** cho v4.

### 12.2 Malware đưa vào TRAIN CHÍNH (không tính Zeus-lineage) + cổng còn thiếu
Theo §11: **Zeus-lineage (Zeus 337 + Zloader 61 = 398 distinct) = NHÓM RIÊNG, KHÔNG vào train chính.**
- **Train chính (distinct, không Zeus-lineage):**
  - Đã khóa (v1-v3, 5 family cũ): **708**.
  - Mới khả dụng không-Zeus-lineage (§4.6): **Gozi 131 + Ramnit 30 = 161** (CHƯA khóa).
  - → **Tiềm năng train chính = 708 + 161 = 869 distinct** (nếu khóa).
- **Nhóm riêng Zeus-lineage:** 398 distinct (báo riêng, không trộn train chính).
- **Cổng (mục tiêu ~1500 distinct train chính):** hiện khóa **708/1500**; nếu khóa 161 mới → 869/1500 →
  **còn thiếu ~631 distinct** cho train chính (cần thêm family đúng loại không-Zeus-lineage: Qakbot/Gozi-mở-rộng/
  tinba/carberp… — phần lớn phải qua VX/VirusShare/BODMAS-email, xem §4/§8).
- **Benign:** MSVC14×1-4M gần đủ (95/100), MSVC14×256K-1M **43/100 (thiếu 57)**; MSVC≤10/11-12 theo mục tiêu
  cấp-bin (§5.1, bỏ ép size). **Chưa khóa v4.**

### 7.5 VT malware consensus — HOÀN TẤT 614/614 (2026-10-16)
| họ | tra | khớp họ | khác-họ | <3 engine | ko-VT |
|---|---|---|---|---|---|
| Zeus | 353 | 294 | 59 | 0 | 0 |
| Gozi | 145 | 72 | 72 | 0 | 1 |
| Zloader | 86 | 53 | 33 | 0 | 0 |
| Ramnit | 30 | 14 | 16 | 0 | 0 |
| **TỔNG** | **614** | **433 (71%)** | **180** | **0** | **1** |
- **0 mẫu <3 engine** → toàn bộ 614 đều malicious (nhãn "malware" vững). **71% khớp family** (Zeus 83% cao nhất,
  Gozi 50% thấp nhất — phân tán). 180 khác-họ = VT gán nhãn generic/đồng-xuất-hiện (upatre/loki/stop/azorult…),
  không phải MB sai — xem §7.4. → dùng VT cross-check trước khi khóa nhãn v4.
- **Benign screen (§7.2, ngưỡng ≥3 engine):** đang tra (benign 67/669 lúc ghi; budget 365/ngày → phần còn lại
  ~242 benign tra ngày mai). `vt_report.py` sẽ ghi số nghi-ngờ khi xong batch benign.

---

## 13. Harvest benign v4 MSVC14 — HOÀN TẤT 2 ô (2026-10-16)
Resume (bin đã sửa), chỉ nhắm 2 ô MSVC14; **tự dừng khi cả 2 đạt 100** (cells_full). Nhịp 256K-1M sau khi 1-4M
đầy: ~**13–20 kept/10 phút** (lấp tốt — KHÔNG phải ô không-lấp-được như MSVC≤10×256K-1M §10).

| ô | kept | **lift-OK** | mục tiêu |
|---|---|---|---|
| **MSVC14 × 256K-1M** | **100** | **99** | 100 ✅ |
| **MSVC14 × 1-4M** | **100** | **99** | 100 ✅ |
| MSVC≤10 × 256K-1M | 7 | 7 | (bỏ ép, §5.1) |
| **TỔNG v4 benign** | **207** | **205** | — |

- 2 mẫu/207 không tạo feature (nf0/nặng) — bỏ qua. **Cả 2 ô MSVC14 đạt mục tiêu ≥100.**
- Cap vendor (§12.1) giữ nguyên tính chất: bin MSVC14 rất phân tán (≤35% ✓); ISO 0%.
- **Chưa khóa v4, không train, cổng ĐÓNG.** Benign v4 = 207 (ở thư mục riêng).

### 7.6 VT benign screen — 365/669 (2026-10-16, ngưỡng TIỀN-ĐĂNG-KÝ ≥3 engine)
Benign v1-v3 ĐÃ KHÓA (immutable). Chỉ ĐÁNH DẤU, KHÔNG xóa; dùng cho ablation metric phụ.

| mức | số |
|---|---|
| **nghi-ngờ (malicious ≥3 engine)** | **17** |
| 1–2 engine (dưới ngưỡng, chỉ ghi chú) | 51 |
| sạch (0 engine) | 293 |
| không trên VT | 4 |
| **đã tra** | **365 / 669** (304 còn lại → ngày mai) |

- **17 mẫu nghi chủ yếu là tiện ích NirSoft "dual-use"** bị một số engine gắn `hacktool`/`pua`/`pswtool`
  (productkey, pswtool, cookieview, smartsniff, wirelessnetworkwatcher, contactsviewer) + vài `mupx` (packed,
  mal 6–12). Cao nhất: `hacktool.nirsoft/productkey` (38 engine), `trojan.kepavll/pswtool` (32).
- **Diễn giải:** đây là **nhiễu nhãn benign do công cụ dual-use** (recovery/password/network tools hợp pháp nhưng
  bị gắn cờ) — **đã biết** (DATASET.md: tập dual-use stress). **KHÔNG xóa khỏi v1-v3 khóa**; khi báo cáo sẽ
  tính **metric phụ (ablation)**: FPR/AUC khi loại 17 mẫu nghi vs giữ, để đo độ nhạy với nhiễu nhãn.
- Danh sách sha đầy đủ: `data/vt/vt_summary.jsonl` (tag=benign, malicious≥3). Phần còn lại 304 benign tra ngày mai
  (resumable; quota 489/500 đã dùng hôm nay).

---

## 14. Cập nhật 2026-10-16 (chiều) — cap v1-v4, VT benign hoãn, malware train chính

### 14.1 Cap vendor ≤35%/bin + ISO ≤35%/bin — GỘP v1-v4 (876 benign, số thật)
Bin v1/v2 từ raw (bộ đã sửa), v3 dùng `tbin`, v4 từ state. "vendor đơn" = nguồn một-vendor nhận diện được
(MS-ISO, NirSoft, app lẻ); scoop/chocolatey coi **đa-vendor** (không gộp).

| bin | n | ISO | ISO% | vendor đơn lớn nhất | % | vi phạm |
|---|---|---|---|---|---|---|
| MSVC 14 | 470 | 147 | **31%** | MS-ISO | 31% | **OK** |
| MSVC≤10 | 182 | 0 | 0% | **NirSoft** | **53%** | **VI PHẠM (vendor>35%)** |
| khác | 161 | 19 | 12% | MS-ISO | 12% | OK |
| GNU/MinGW | 22 | 0 | 0% | git-for-windows | 18% | OK |
| Go | 35 | 0 | 0% | — | 0% | OK |
| Delphi | 6 | 0 | 0% | — | 0% | OK |

- **ISO ≤35%: ĐẠT mọi bin.** v4 (199 MSVC14 Scoop đa-vendor) **kéo ISO ở bin MSVC14 từ ~65% (v1) xuống 31%** → confound ISO đã giảm mạnh.
- **Vendor >35%: VI PHẠM duy nhất ở bin MSVC≤10 — NirSoft 53%** (96/182 = 46 v2 + 50 v3). Đây là confound
  **một-vendor** đã biết; **không sửa được bằng NirSoft** (pilot §10: nguồn MSVC≤10 khác gần như không có ở size-vừa).
  → **Hạn chế (đã ghi §5.1): bin MSVC≤10 KHÔNG dùng kiểm bất biến toolchain** (lệch NirSoft + <256K).
- Bin MSVC14 (ô đã thu v4) **sạch confound vendor/ISO** → **phù hợp để đánh giá bất biến**.

### 14.2 VT benign screen — HOÃN tới mai (quota)
Quota VT hôm nay dùng **489/500** (124 malware + 365 benign) → **304 benign còn lại tra NGÀY MAI** (ngưỡng ≥3
engine đã khóa). Khi xong: `vt_report.py` → ghi nghi-ngờ **theo bin và nguồn** vào §7. (Hôm nay: 17 nghi/365, §7.6.)

### 14.3 Malware TRAIN CHÍNH (không Zeus-lineage) — còn thiếu & họ lấy được
- **Train chính distinct (không Zeus-lineage):** đã khóa **708** + mới (Gozi 131 + Ramnit 30) = **869 tiềm năng**.
- **Mục tiêu ~1500 → thiếu ~631.** Zeus-lineage (398) để **nhóm riêng** (§11).
- **Họ banking KHÔNG-Zeus còn lấy được (lấp phần thiếu):**
  | họ | nguồn khả dụng | ước distinct thêm | ghi chú |
  |---|---|---|---|
  | **Qakbot** (+qbot) | BODMAS (51) / VX; **MB không trả** (§4) | ~25–40 | phải xin BODMAS-email hoặc VX thủ công |
  | **Tinba** | BODMAS (23) / VX | ~10–18 | MB không có (§8) |
  | **Carberp** | BODMAS (14) / VX | ~7–12 | MB không có |
  | Nymaim | BODMAS (8) / VX | ~4–7 | |
  | SpyEye | BODMAS (2) / VX | ~1–2 | |
  | Gozi/Ramnit | MB **đã lấy hết** (157/31) | 0 | đã cạn ở MB |
  - **Tổng thêm khả dụng (không-Zeus) ≈ +50–80 distinct** (chủ yếu qua **BODMAS-email / VX thủ công**, không qua MB).
- **Thực tế:** 869 + (~50–80 BODMAS/VX) ≈ **~920–950 distinct train chính** → **vẫn < 1500**. Vũ trụ banking-trojan
  KHÔNG-Zeus có hạn ở các nguồn tải được → **mục tiêu 1500 train-chính nhiều khả năng KHÔNG khả thi** nếu chỉ
  banking-đúng-loại không-Zeus. **Đề xuất chốt với người dùng:** (i) hạ mục tiêu train-chính xuống ~900–1000, HOẶC
  (ii) đưa Zeus-lineage vào với **đánh giá nhận-biết-toolchain** (báo riêng theo bin), HOẶC (iii) nới định nghĩa
  lớp (thêm loader đúng hệ sinh thái). **Chưa chốt, chưa khóa, không train.**

---

## 15. Cập nhật CỔNG sau khi tải đủ Tinba (2026-10-16) — HAI số

### Tinba đủ (MB tag+signature, dedup chéo)
- Tải đủ **264 raw** (218 mới + pilot), lift workers=4/14G/900s resumable, **0 Timeout** đợt full; dedup sha vs toàn bộ.
- **distinct (ppdeep≥90) = 92**; **trùng dữ liệu cũ = 2**; **MSVC14 = 0** (linker v6×107, v8×110, v10×19 → **toàn MSVC≤10**).

### (a) Malware TRAIN CHÍNH — tổng distinct (không Zeus-lineage, không Nymaim-downloader)
| nhóm | distinct |
|---|---|
| old 5 (TrickBot 189, BumbleBee 254, IcedID 114, Emotet 77, Dridex 68) | 702 |
| Gozi (dir 227)† | 139 |
| Ramnit (dir 46)† | 31 |
| **Tinba (dir 264, MỚI)** | **92** |
| **TỔNG train chính distinct** | **964** |
- **Mục tiêu 1500 → còn thiếu ~536.** (Giữ mục tiêu, không hạ.)
- † **CẢNH BÁO dir-growth:** Gozi/Ramnit/Tinba dir hiện **lớn hơn §4.6** (Gozi 157→227, Ramnit 31→46) — có thể do
  re-fetch union Gozi/ISFB/Ursnif bổ sung mẫu MB mới. **Cần người dùng xác minh** (tái lập manifest). Số ở đây là
  **trạng thái dir hiện tại**, chưa khóa.

### (b) TRONG BIN MSVC14 (bin benign SẠCH confound, §14) — distinct theo họ
| họ | MSVC14 distinct | / tổng distinct họ |
|---|---|---|
| TrickBot | 5 | 189 |
| IcedID | 5 | 114 |
| Dridex | 2 | 68 |
| Gozi | 3 | 139 |
| BumbleBee / Emotet / Ramnit / **Tinba** | 0 | 254/77/31/92 |
| **TỔNG malware MSVC14 (positives)** | **15** | — |
| **benign MSVC14 (negatives, §14)** | **470** | — |

- **AUC CI dự kiến (Hanley-McNeil, giả định AUC=0.90, m=15 pos, n=470 neg): ±0.105 → ~[0.795, 1.000]** — **RỘNG**
  (do chỉ 15 positives). Đánh giá bất-biến trong bin MSVC14 sẽ **kém chính xác** trừ khi tăng malware MSVC14.
- **GHI RÕ: các họ MỚI thêm (Zeus/Gozi/Zloader/Ramnit/Tinba) gần như TOÀN MSVC≤10** → đóng góp **~0** cho bin MSVC14.
  Tăng tổng distinct (a) KHÔNG cải thiện (b). **Mâu thuẫn cốt lõi:** bin có benign sạch (MSVC14) thiếu malware (15);
  bin có nhiều malware (MSVC≤10, ~900) thì benign lệch NirSoft 53% (§14) → **không bin nào vừa đủ malware vừa sạch benign**.
- **Hệ quả:** muốn kiểm bất-biến toolchain đáng tin trong MSVC14 cần **nguồn malware MSVC14** (trojan BIÊN DỊCH MỚI,
  vd TrickBot/IcedID/QakBot đời mới MSVC14) — các họ banking cũ (Zeus/Tinba/Gozi) KHÔNG giúp. Ghi làm hạn chế/định hướng.

**Cổng 🔴 ĐÓNG — chưa khóa v4, không train.** Tinba ở thư mục riêng (`mbtag_pilot/tinba`), chưa khóa.

---

## 16. SỬA bộ phân loại bin + §15 SAI (2026-10-16) — malware MSVC14 bị undercount nặng

### 16.1 Lỗi bộ phân loại (task 1) — bảng họ × (linker/Rich/CRT) × bin
`tc_bin` cũ **đòi Rich header HOẶC import CRT-DLL** mới gọi MSVC. Malware **bị PACK** (UPX/custom) **xóa Rich
+ xóa import CRT** nhưng **MajorLinkerVersion=14 vẫn còn** → bị ném vào **"khac"**. Bộ validate 80% trước chỉ kiểm
trên benign (không pack) nên bỏ sót. Ví dụ BumbleBee: **244 mẫu linker=14, rich=False, CRT=False → "khac"**.

**SỬA: LINKER-PRIMARY** — sau khi loại Go/Delphi/GNU (`.eh_frame`/mingw-dll), **bin theo MajorLinkerVersion**
(6–10→MSVC≤10; 11–13→MSVC11-12; 14–19→MSVC14), KHÔNG đòi Rich/CRT. Khớp binning gốc của `HOLDOUT_V4_MATCH_ESTIMATE`
(malware MSVC14=566). Đã sửa trong `harvest_v4_benign.py` + `pilot_v4_src.py`.

**MSVC14 distinct theo họ — CŨ (bug) → MỚI (sửa):**
| họ | CŨ | → MỚI | / distinct |
|---|---|---|---|
| BumbleBee | 0 | **244** | 254 |
| IcedID | 5 | **79** | 114 |
| TrickBot | 5 | **45** | 189 |
| Gozi | 3 | **32** | 139 |
| Emotet | 0 | **28** | 77 |
| Dridex | 2 | **7** | 68 |
| Ramnit | 0 | 2 | 31 |
| Tinba | 0 | 0 | 92 (đúng — toàn MSVC≤10) |

### 16.2 GATE ĐÚNG (manifest-authoritative + bin đã sửa) — THAY §15
- **(a) Malware train chính tổng distinct = 964** (old 702 + Gozi 139 + Ramnit 31 + Tinba 92). **Thiếu ~536 / 1500.** (không đổi so §15)
- **(b) Trong bin MSVC14: malware distinct = 437** (pos) · **benign MSVC14 = 565** (neg; bin mới, trước 470).
  **AUC CI dự kiến @0.90: ±0.021 → [0.879, 0.921]** — **HẸP, đủ lực.**
- **RÚT LẠI §15:** "chỉ 15 MSVC14 / CI ±0.105 rộng / mâu thuẫn bin không bin nào vừa đủ" là **ARTIFACT của bug phân loại**,
  KHÔNG đúng. Thực tế **bin MSVC14 vừa nhiều malware (437) vừa benign sạch (565) → đánh giá bất-biến toolchain đủ lực.**
- **Cần làm lại:** cap vendor/ISO §14 tính bằng bin CŨ → **phải tính lại với bin đã sửa** (benign MSVC14 565 thay 470);
  dự kiến ISO% ở MSVC14 vẫn ≤35% (v4 Scoop pha loãng) nhưng phải xác minh. Ghi TODO.

### 16.3 Dir-growth (task 2) — tái lập từ MANIFEST (hashed), KHÔNG dùng thư mục
| họ | manifest (committed, authoritative) | thư mục thực tế | DƯ không-trong-manifest |
|---|---|---|---|
| Zeus | 357 | 450 | +93 |
| Gozi | 157 | 227 | +70 |
| Zloader | 90 | 138 | +48 |
| Ramnit | 31 | 46 | +15 |
| Tinba (mbtag) | 243 | 264 | +21 |
| **Tổng** | — | — | **+247 KHÔNG trong manifest** |
- **Manifest commit đúng như §4.6** (Gozi 157, Ramnit 31). Thư mục có **~247 file KHÔNG có trong bất kỳ manifest nào**
  (Gozi: 70 file dir không-trong-manifest, 0 manifest-thiếu-dir). **§15 tính theo dir → thổi phồng; §4.6/§16.2 theo manifest là đúng.**
- **Nguồn 247 file dư: KHÔNG xác định được từ bản ghi** (nghi một lần fetch_full/pilot chạy lại tải thêm mẫu MB mới
  nhưng không ghi manifest, hoặc tồn từ phiên trước). **KHUYẾN NGHỊ: cách ly 247 file dư, KHÔNG dùng/không khóa tới khi
  điều tra**; chỉ dùng tập **manifest-authoritative** (Zeus357/Gozi157/Zloader90/Ramnit31 + Tinba243).

### 16.4 Nguồn malware MSVC14 HIỆN ĐẠI (task 4) — dù đã có 437, để tiến 1500 + tươi mới
> Lưu ý: bin MSVC14 **đã đủ lực** (437 pos). Danh sách này để **tăng tổng distinct train chính** và thêm malware
> MSVC14 **đời mới** (loader/banking 2022–2025), không bắt buộc cho tính đủ-lực MSVC14.

| nguồn/họ | loại | MSVC14? | điều kiện lấy |
|---|---|---|---|
| **QakBot** | banking/loader | thường MSVC14 | MB không trả → **BODMAS-email / VX thủ công** |
| **TrickBot/IcedID/Emotet mẫu MỚI** (first_seen 2022+) | banking | MSVC14 | **MB** theo tag + lọc `first_seen` mới (dedup vs hiện có) |
| **BumbleBee thêm** | loader | MSVC14 | MB tag `bumblebee` (ngoài 262 đã có) |
| **Latrodectus / PikaBot / DarkGate** (loader kế nhiệm 2023-24) | loader hệ sinh thái | MSVC14 | **MB** tag — cần xác minh đúng-loại (loader banking) + lineage |
| **Dridex/Gozi mẫu mới** | banking | một phần MSVC14 | MB tag + first_seen mới |
- **Việc tôi làm khi duyệt:** MB tag + lọc `first_seen≥2022`, dedup sha+ppdeep vs toàn bộ, pilot 25/họ (quy trình
  `MALWARE_SOURCING_PLAN §5`), bin bằng bộ **đã sửa**, ghi nguồn `mb-tag:<tag>`. **Hỏi trước khi tải.**

**Cổng 🔴 ĐÓNG — chưa khóa v4, không train.** §15 được thay bằng §16 (giữ lại §15 làm lịch sử lỗi).

---

## 17. Hand-check linker + probe trong bin MSVC14 + định nghĩa bin + loader hiện đại (2026-10-16)

### 17.1 (task 1) Hand-check 15 mẫu linker=14 (BumbleBee/IcedID/Emotet) — linker THẬT hay packer?
- **14/15 có Rich=True + section MSVC chuẩn** (.text/.rdata/.pdata/.gfids), entropy .text ~6.2–6.5 → **linker=14 là THẬT
  (MSVC compiler), KHÔNG do packer**. Chỉ 1/15 UPX-packed (Emotet, UPX0/UPX1 ent 8.0).
- **Sửa giải thích §16.1:** nguyên nhân gốc KHÔNG phải "packer xóa Rich", mà là **`fast_load=True` khiến pefile
  KHÔNG parse Rich** (rich luôn=False trong tc_bin) → rơi về đòi CRT-import → mẫu import-ít bị ném "khac".
  Fix linker-primary vẫn đúng; MSVC14 malware là **MSVC14 thật, phần lớn không pack**.

### 17.2 (task 2) Bảng pack + probe metadata TRONG bin MSVC14 (loại holdout BumbleBee/choco/nirsoft + v3)
| nhãn | n | Rich | CRT-import | maxEnt tb | %maxEnt>7.2 |
|---|---|---|---|---|---|
| malware | 203 | 96% | **12%** | 6.93 | 30% |
| benign | 493 | 94% | **82%** | 6.30 | 3% |
- **Rich gần bằng nhau (96/94%) → KHÔNG phải confound Rich.** Khác biệt lớn: **CRT-import 12% vs 82%** (malware
  resolve API động/loader; benign link CRT) + entropy (pack 30% vs 3%).
- **Probe metadata (OOF, GroupKFold=cluster):** FULL (8 feat gồm entropy+Rich) **AUC=0.951** [cluster-boot 0.934–0.966];
  **bỏ entropy+Rich → AUC=0.894** (dAUC −0.057).
- **Kết luận:** ngay TRONG bin MSVC14 (cùng toolchain), metadata vẫn tách malware/benign **~0.95**; bỏ entropy+Rich
  **vẫn 0.894** → **confound KHÔNG chỉ do pack/toolchain**, chủ yếu **import-style (CRT 12/82%) + size + #sections**.
  → Khi đánh giá BFBG trong bin này phải báo kèm baseline metadata + ablation bỏ entropy/Rich/import-style.

### 17.3 (task 3) ĐỊNH NGHĨA BIN theo từng kết quả — bảng nào cần tính lại
| kết quả / bảng | binning đã dùng | đúng? | cần tính lại? |
|---|---|---|---|
| `HOLDOUT_V4_MATCH_ESTIMATE §2` malware×size | **linker-based** | ✅ | không |
| §4.6 distinct/lineage (Gozi/Zeus…) | distinct=ppdeep (OK); bin-display=tc_bin cũ | distinct ✅; MSVC14-display sót | distinct OK; bin-display tính lại nếu dùng |
| §9/§12/§13 v4 benign cells (MSVC14 100/100) | harvester tc_bin (CRT-req, fast_load) | benign import CRT → **phần lớn đúng** | OK (benign không pack); đã xác nhận |
| §14 cap vendor/ISO | tc_bin cũ | ❌ | **ĐÃ tính lại** (17.4) |
| §15 gate (b) MSVC14=15 | tc_bin cũ (BUG) | ❌ | **THAY bằng §16/§17** (437) |
| §16.2 gate | linker-primary | ✅ | — |
| **v3 `tbin`** (manifest) | validate_tc (CRT-req) | benign → phần lớn OK | **GIỮ NGUYÊN** (theo lệnh; v3 đã khóa) |

### 17.4 (task 4) Cap vendor/ISO GỘP v1-v4 — bin LINKER-PRIMARY (876 benign)
| bin | n | ISO% | vendor-đơn lớn nhất | vi phạm |
|---|---|---|---|---|
| MSVC 14 | 565 | **29%** | MS-ISO 29% | **OK** |
| MSVC≤10 | 167 | 0% | **NirSoft 57%** | **VI PHẠM (>35%)** |
| MSVC khac/Go/khac/GNU/MSVC11-12/Delphi | ≤46 | ≤11% | ≤18% | OK |
- Giữ kết luận §14: **ISO ≤35% đạt mọi bin** (MSVC14 29%, v4 Scoop pha loãng); **vendor VI PHẠM chỉ ở MSVC≤10
  (NirSoft 57%)** → bin MSVC≤10 không dùng kiểm bất-biến; **bin MSVC14 sạch** (ISO 29%, vendor ≤29%).

### 17.5 (task 5) Loader HIỆN ĐẠI (MB tag, first_seen≥2022) — xác minh loại (CHƯA tải)
| họ | MB PE≤12MB (2022+) | Malpedia | đúng loại? |
|---|---|---|---|
| **Latrodectus** | 123 | backdoor/loader của **LUNAR SPIDER (creators of IcedID)**, thay IcedID | ✅ hệ sinh thái IcedID (như BumbleBee) |
| **PikaBot** | 176 | downloader+loader+backdoor, **kế nhiệm QakBot** / Black Basta | ✅ hệ sinh thái QakBot |
| **DarkGate** | 104 | **commodity loader** (HVNC/keylog/stealer), không gắn banking cụ thể | ⚠️ **construct-validity** (như SystemBC) → thận trọng/loại |
| QakBot | 0 (MB) | — | cần BODMAS/VX |
| IcedID / TrickBot (mẫu mới) | 274 / 50 (2022+) | đã có loại | thêm mẫu MSVC14 đời mới |
- **Khả dụng ngay (MB, MSVC14 đời mới):** Latrodectus 123 + PikaBot 176 ≈ **~299** loader đúng-hệ-sinh-thái →
  tăng mạnh malware MSVC14 train-chính + tiến tới 1500. **DarkGate hoãn** (commodity). **Việc tôi làm khi duyệt:**
  pilot 25/họ, dedup, bin linker-primary, ghi nguồn; **hỏi trước khi tải**.

**Cổng 🔴 ĐÓNG — không train, không khóa v4, không chạm v3/holdout.** Dừng sau bảng.

---

## 18. Lực phân tích bin MSVC14 + pilot loader hiện đại (2026-10-16)

### 18.1 (task 1) LỰC PHÂN TÍCH trong bin MSVC14 (loại holdout BumbleBee/choco/nirsoft + v3)
Tập: **203 malware / 497 benign MSVC14, 696 cluster**. AUC CI = cluster-bootstrap (2000).
| mô hình metadata | AUC | 95% CI (cluster-boot) | SE |
|---|---|---|---|
| FULL (8 feat, gồm entropy+Rich) | **0.952** | [0.937, 0.966] | 0.0075 |
| bỏ entropy+Rich | **0.892** | [0.865, 0.920] | 0.0142 |
- paired dAUC(full − bỏ) = **+0.060** [+0.041, +0.080] → **có ý nghĩa**.
- **MDD (chênh AUC nhỏ nhất phát hiện được, 80% power, α=0.05) ≈ 0.028.**
- **Hệ quả:** trong bin MSVC14, một mô hình (vd BFBG) chỉ **"hơn baseline metadata" đáng tin nếu vượt ≥~0.028 AUC**.
  Baseline để so: **0.892 (bỏ entropy+Rich)** hoặc **0.952 (full)**. Lực đủ để phát hiện chênh ~0.03 trở lên.

### 18.2 (task 2) PILOT loader hiện đại (MB tag, first_seen≥2022, 25/họ, seed 20261016)
| họ | tải | liftOK | .NET | rơi | distinct | trùng cũ | bin | Rich | CRT | maxEnt tb | %>7.2 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Latrodectus | 25 | 25 | 0 | 0 | 17 | 0 | MSVC14 14 / ≤10 9 / 11-12 1 / khac 1 | 96% | 4% | 7.23 | 60% |
| PikaBot | 25 | 24 | 0 | 1 | 18 | 0 | MSVC14 15 / ≤10 4 / khac 6 | 76% | 4% | 7.35 | 60% |
- Chéo 35 distinct/50 (0 cụm lẫn 2 họ). **Cả hai chủ yếu MSVC14** → bổ sung đúng bin cần (malware MSVC14).
- **CRT-import 4% + entropy cao (60%>7.2, pack nhiều hơn BumbleBee/IcedID)** → sẽ **củng cố confound import-style/pack**
  trong bin MSVC14 (CRT 12% vs benign 82%). Khi gộp phải báo kèm baseline metadata + ablation (§18.1/§17.2).

### 18.3 (task 3) GÁN LINEAGE (cho split — nhóm theo dòng mã nguồn, không tách qua train/test)
- **Latrodectus ↔ IcedID** (LUNAR SPIDER, kế nhiệm IcedID) → **nhóm "IcedID-lineage"**.
- **PikaBot ↔ QakBot** (kế nhiệm QakBot) → **nhóm "QakBot-lineage"** (QakBot chưa có → PikaBot mở nhóm này).
- DarkGate: **hoãn** (commodity, không hệ sinh thái banking — §17.5).

### 18.4 (task 4) CỔNG — (a)(b)
- Pilot **CHƯA khóa** → số hiện tại KHÔNG đổi: **(a) train chính 964/1500 (thiếu 536)**; **(b) MSVC14 437 malware /
  565 benign → AUC CI ±0.021; baseline metadata 0.892–0.952; MDD 0.028.**
- **Dự phóng NẾU tải đủ Latrodectus(123)+PikaBot(176):** distinct thêm ~**120–210** (pilot 68–72% distinct; full cao hơn)
  → (a) ~**1080–1170/1500**; MSVC14 malware (b) tăng thêm ~**70–170** (Latro 56% + Pika 60% MSVC14) → bin MSVC14 càng đủ lực.
- **Hỏi trước khi tải đủ.** Chưa tải, chưa khóa, không train, không chạm v3/holdout.

---

## 19. Full pull Latrodectus + PikaBot (2022+, 2026-10-16) — gate (a)(b) số thật
MB tag, first_seen≥2022, dedup sha+ppdeep≥90 vs toàn bộ cũ. **Số distinct/bin/pack = raw-based (manifest-authoritative,
KHÔNG cần lift)**; lift (workers=4/14G/900s/resumable) đang chạy nền (loader pack nặng → lift chậm, nhiều Timeout dự kiến).

| họ | n (manifest) | distinct (ppdeep) | MSVC14 distinct | trùng cũ | bin | Rich | CRT | maxEnt tb | %>7.2 |
|---|---|---|---|---|---|---|---|---|---|
| Latrodectus | 123 | **83** | **62** | 0 | MSVC14 74 / ≤10 38 / 11-12 9 / khac 2 | 96% | 4% | 7.21 | 59% |
| PikaBot | 176 | **74** | **29** | 0 | MSVC14 99 / ≤10 45 / khac 30 / 11-12 2 | 83% | 10% | 7.38 | 64% |
- **Chéo 157 distinct / 299 (0 cụm lẫn 2 họ)**, **0 trùng dữ liệu cũ**. Cả hai nhiều MSVC14; **pack cao (59-64% >7.2)**,
  **CRT 4-10%** → tiếp tục nuôi confound import-style/pack trong bin MSVC14 (báo kèm baseline metadata + ablation §17.2/§18.1).
- **Lineage (gán split):** **Latrodectus → IcedID-lineage**; **PikaBot → QakBot-lineage** (gộp cùng dòng, không tách qua train/test).
- Thư mục dư so manifest (latro 143 vs 123, pika 198 vs 176 — +42 không-trong-manifest, cùng hiện tượng §16.3) → **cách ly, dùng manifest-authoritative**.

### 19.1 CỔNG (a)(b) — số thật sau khi gộp loader (CHƯA khóa v4)
- **(a) Malware train chính tổng distinct = 964 + Latrodectus 83 + PikaBot 74 = 1.121**
  → **CÒN THIẾU CHÍNH XÁC 379 để đạt 1.500.**
- **(b) Trong bin MSVC14: malware distinct = 437 + 62 + 29 = 528** (positives) · **benign MSVC14 = 565** (negatives)
  → bin MSVC14 rất đủ lực (AUC CI ±~0.02, MDD ~0.028 §18.1).
- Zeus-lineage (398) + Nymaim (downloader) + DarkGate (commodity) vẫn **ngoài train chính**.

### 19.2 CÒN LẤP ĐƯỢC 379 — danh sách họ/nguồn (ước distinct, chưa xác minh)
| họ/nguồn | ước distinct thêm | điều kiện | lineage |
|---|---|---|---|
| **ISFB/Ursnif (MB tag)** ngoài Gozi-157 | ~60–140 | MB tag `isfb`(210)/`ursnif`(163), dedup chéo với Gozi | Gozi-lineage |
| **Qakbot** | ~25–40 | **BODMAS-email / VX** (MB không có) | QakBot-lineage (cùng PikaBot) |
| **IcedID/TrickBot mẫu mới 2022+** | ~20–60 | MB tag + first_seen, dedup vs hiện có (IcedID MB 274, TrickBot 50 mới) | sẵn có |
| **Carberp / SpyEye / Retefe** | ~10–25 | BODMAS/VX (Carberp) ; MB SpyEye 5/Retefe 4 | non-Zeus |
| **Latrodectus/PikaBot <2022 (cũ hơn)** | ~20–50 | MB tag bỏ lọc first_seen | IcedID/QakBot-lineage |
| (tuỳ chọn) DarkGate nếu nới định nghĩa loader | ~50–70 | MB tag `darkgate` 104 | commodity (construct-validity) |
- **Khả thi tới 1.500:** ISFB/Ursnif (~60–140) + Qakbot (~25–40) + IcedID/TrickBot-mới (~20–60) + Carberp/SpyEye
  (~10–25) + loader cũ (~20–50) ≈ **~135–315** → **đủ hoặc gần đủ 379**. Ưu tiên: **ISFB/Ursnif (MB, sẵn key, lớn nhất)**,
  rồi Qakbot (BODMAS/VX).

**Cổng 🔴 ĐÓNG — không khóa v4, không train, không chạm v3/holdout.** Lift loader chạy nền (báo yield native/.NET/rơi khi xong).

### 19.3 Lift yield loader (hoàn tất)
- **Latrodectus: 123/123 lift-OK** (0 .NET, 0 rơi).
- **PikaBot: 163/176 lift-OK** (0 .NET, **13 Timeout** = pack nặng, CFGFast >900s).
- Tổng loader lift-OK = **286/299**. distinct (§19, ppdeep raw) không đổi (83/74); 13 PikaBot Timeout vẫn tính
  availability nhưng **không có feature để dùng mô hình** (lift-OK usable ít hơn distinct availability).

### 7.7 VT benign screen — HOÀN TẤT 669/669 (2026-10-17, ngưỡng ≥3 engine)
| mức | n |
|---|---|
| **nghi-ngờ (malicious ≥3 engine)** | **31** (4.6%) |
| 1–2 engine | 77 |
| sạch (0) | 561 |
| không trên VT | 17 |

**Nghi-ngờ theo NGUỒN:** v3 13/165 (8%), **NirSoft 9/46 (20%)**, scoop 7/203 (3%), chocolatey 2/45 (4%).
**Nghi-ngờ theo BIN:** **MSVC≤10 21/167 (13%)**, **MSVC 14 5/365 (1%)**, Go 2/35, MSVC khac 2/39, khac 1/26.
- **Nhiễu nhãn benign tập trung ở NirSoft (20%) + bin MSVC≤10 (13%)** — dual-use recovery/password tools bị gắn
  hacktool/pua; **đúng bin đã KHÔNG dùng kiểm bất-biến** (NirSoft 57%, §14/§17.4).
- **Bin MSVC14 (bin đánh giá bất-biến): chỉ 1% nghi → negatives SẠCH** → không làm hỏng eval MSVC14.
- **KHÔNG xóa khỏi v1-v3 đã khóa** (immutable); dùng cho **ablation metric phụ**: FPR/AUC khi loại 31 mẫu nghi vs giữ,
  và riêng trong bin MSVC14 (loại 5 nghi). Danh sách sha: `data/vt/vt_summary.jsonl` (tag=benign, malicious≥3).
- VT lookup toàn bộ HOÀN TẤT: **614/614 malware + 669/669 benign** (quota 305/500 hôm nay).

---

## 20. BODMAS binaries CỤC BỘ — re-arm + lift verified; pilot Qakbot+Carberp (2026-10-17)
Người dùng đã tải **BODMAS full** về `/home/dhgia/Work/WorkingD/WORK/Research/BODMAS/`
(`BODMAS_disarmed_malware_binaries.zip` 68G = 57.293 disarmed PE; `meta_disarm.csv`; metadata). **Dùng cục bộ, không tải.**
Xử lý như **malware sống** (chỉ đọc bytes, KHÔNG execute; rút chọn lọc theo hash, không giải nén 68G).

### 20.1 Cơ chế disarm/re-arm (đã xác minh)
- Disarm = `OPTIONAL_HEADER.Subsystem=0` + `FILE_HEADER.Machine=0` (giống SOREL). Re-arm = khôi phục 2 field từ
  `meta_disarm.csv` (sha→Subsystem,Machine; Machine **332 = x86 32-bit**). **angr cần Machine hợp lệ → RE-ARM trước khi lift.**
- Script riêng `bodmas_extract_rearm.py` (chạy `-I`, isolated): unzip chọn lọc `altered/<sha>.exe` → set 2 field → ghi
  `~/bfbg_benign_work/bodmas_pilot/<fam>/<sha>`. **KHÔNG sửa `meta_disarm.csv`.**

### 20.2 Pilot Qakbot + Carberp (MB KHÔNG có 2 họ này — giá trị unique BODMAS)
| họ | re-armed | liftOK | .NET | rơi | distinct | trùng cũ | bin | machine | Rich | CRT | maxEnt | %>7.2 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **Qakbot** (qakbot+qbot) | 25 | **25** | 0 | 0 | **16** | 0 | MSVC≤10 17 / khac 8 | x86-32 | 17% | 0% | 6.34 | 17% |
| **Carberp** | 14 | **14** | 0 | 0 | **2** | 0 | MSVC 11-12 14 | x86-32 | 50% | 6.95 | — | 7% |
- **BODMAS disarmed → re-arm → angr lift HOẠT ĐỘNG** (39/39 liftOK, 0 fail, 0 .NET) → BODMAS **dùng được** cho pipeline.
- **Qakbot**: 25→**16 distinct** (MSVC≤10, x86-32 đời cũ, ít pack) — **nguồn Qakbot duy nhất** (MB trả 0). QakBot-lineage (cùng PikaBot).
- **Carberp**: 14→**chỉ 2 distinct** (near-dup chiến dịch nặng) → giá trị thấp.
- 0 trùng dữ liệu cũ. CRT 0% (loader resolve động) → giống confound import-style.

### 20.3 Đóng góp dự phóng cho 379 còn thiếu (BODMAS non-Zeus, chưa khóa)
| họ BODMAS | meta | ước distinct (pilot→full) | lineage | ghi chú |
|---|---|---|---|---|
| **Qakbot** | 51 | ~30–35 (pilot 16/25) | QakBot-lineage | **chỉ BODMAS/VX có** |
| Carberp | 14 | ~2–4 | non-Zeus | near-dup nặng |
| SpyEye | 2 | ~1–2 | non-Zeus | |
| (Gozi/Ursnif BODMAS) | 56 | chồng Gozi-157 đã có | Gozi-lineage | dedup chéo |
- **BODMAS unique non-Zeus (train chính) ≈ +35–45 distinct** (chủ yếu Qakbot). zbot/pwszbot (507) = Zeus-lineage (riêng);
  tinba/emotet/trickbot/icedid đã có; nymaim = downloader (riêng).
- **§8 trạng thái cập nhật: "chờ phản hồi" → ĐÃ CÓ BINARY CỤC BỘ, re-arm+lift verified.** Lift được, disarmed không cản.
- **CHƯA khóa v4, không train.** Đề xuất: pull đủ Qakbot (51, QakBot-lineage) từ BODMAS; Carberp/SpyEye ít giá trị.

### 20.4 Mở rộng BODMAS cục bộ — candidate report (2026-10-18; CHƯA khóa)
- BODMAS đã có sẵn cục bộ; không tải mạng, không sửa `meta_disarm.csv`, không thực thi binary.
  `bodmas_extract_full.py` đã re-arm 746 mẫu thuộc các family trong map riêng; không đưa vào `data/raw/` chuẩn.
- Trong 10 family được xét cho train chính (không gồm Zeus-lineage và Nymaim-downloader): **231 mẫu re-arm**,
  **221 có feature JSON hợp lệ**. Còn **10 chưa lift** (4 Emotet, 6 Tinba), đã có trong QA: 9 Timeout, 1 ProcessCrash.
  Một lần thử resume được dừng trước khi mẫu đầu hoàn tất; không có feature/failure record mới. Giữ các mẫu lỗi,
  không thay thế và không retry tiếp.

| family | feature-ready | cụm distinct nội bộ | net-new trước xử lý cụm chéo-family |
|---|---:|---:|---:|
| Carberp | 14 | 2 | 2 |
| Dridex | 10 | 2 | 2 |
| Emotet | 52 | 37 | 37 |
| Gozi | 13 | 12 | 12 |
| IcedID | 5 | 3 | 3 |
| Qakbot/Qbot | 51 | 32 | 32 |
| SpyEye | 2 | 2 | 2 |
| Tinba | 17 | 9 | 7 |
| TrickBot | 14 | 12 | 11 |
| Ursnif | 43 | 32 | 32 |

- Đối chiếu `ppdeep≥90` trên 221 feature-ready với **3.334 hash tham chiếu** (cache malware/benign cũ, pilot v4,
  Tinba và loader): có **142 cụm nội bộ**, **139 cụm net-new** trước rà soát lineage.
- Có **1 cụm chéo-family Dridex–Qakbot** mang hai lineage khác nhau; cách ly cụm này khỏi candidate tự động.
  Candidate còn **138 cụm net-new**, chưa tính là số đã khóa/đủ chuẩn. Tổng theo hàng family không cộng trực tiếp
  được vì cụm chéo-family được thấy ở cả hai hàng.
- Candidate manifest ngoài git: `~/bfbg_benign_work/bodmas_v4_candidate_manifest_20261018.jsonl`
  (221 dòng; SHA-256 `932e2b03bd887878f5270742ab60aabd2b4890d2f913773e8cac515a4b7922f0`).
  Trường `candidate_eligible` chỉ giữ đại diện cụm net-new sau khi loại cụm lineage xung đột; đây chưa phải manifest v4.
- **Cổng không đổi:** không cộng 138 vào số đã khóa ở §0.1 hay vào manifest v4; chưa xác minh độc lập family labels,
  chưa tạo split/manifest v4, không train, không chạy GRL, không chấm holdout. Ước lượng cũ +35–45 ở §20.3 được
  thay bằng kết quả candidate này cho tập BODMAS cục bộ, nhưng chỉ sau rà soát nhãn và lineage mới được tính vào gate.

---

## 21. Pull đủ BODMAS + ref thống nhất + bảng cổng duy nhất (2026-10-21)
BODMAS cục bộ: `/run/media/dhgia/DATA/WORK/Research/BODMAS` (zip 68G cũng còn ở path cũ — **nên xóa 1 bản để giải phóng; đĩa còn 21G**).
Đã extract+re-arm **746 banking** (0 fail, 0 trùng sha cũ), lift 736+/746.

### 21.1 (task 1) REF THỐNG NHẤT + dedup lại
- **Ref ppdeep thống nhất = 3.359**: old_mal v1 (1416) + benign v1/v2 (v12 cache) + v3 benign + 614 pilot_v4
  (Zeus/Gozi/Zloader/Ramnit) + Tinba MB (243) + Nymaim MB (25) + Latrodectus+PikaBot (299). (toàn bộ v1-v3 + mọi malware đã lift).
- **BODMAS net-new distinct (ppdeep≥90 vs ref thống nhất):**
  - **Train chính = 150** (emotet 41, ursnif 32, qakbot 32, tinba 13, gozi 12, trickbot 11, icedid 3, carberp 2, dridex 2, spyeye 2).
  - Zeus-lineage (nhóm riêng) = 346 (zbot 330 + pwszbot 16). Downloader Nymaim (riêng) = 6.
- (Con số "138" trước đó là giữa-chừng; **cuối cùng train net-new = 150**.)

### 21.2 (task 3) NGUỒN × HỌ (số khả dụng/đã thu; mb/bodmas/vx)
| họ | MalwareBazaar | BODMAS (meta) | VX-Underground | nhóm | NGUỒN DUY NHẤT? |
|---|---|---|---|---|---|
| **Qakbot** | **0** | **51** | (Families, chưa tải) | QakBot-lineage (train) | **CHỈ BODMAS** ✅ |
| **Carberp** | **0** | **14** | (chưa tải) | train | **CHỈ BODMAS** ✅ |
| Zloader | 90 (đã thu) | 0 | ? | Zeus-lineage | chỉ MB |
| Ramnit | 31 (đã thu) | 0 | ? | train | chỉ MB |
| Latrodectus | 123 (đã thu) | 0 (BODMAS 2019-20, quá cũ) | ? | IcedID-lineage(train) | chỉ MB |
| PikaBot | 176 (đã thu) | 0 | ? | QakBot-lineage(train) | chỉ MB |
| Citadel | 56 (chưa thu) | 0 | ? | Zeus-fork | chỉ MB |
| Gozi | 157 (thu) | 13 | tag | Gozi-lineage(train) | MB+BODMAS |
| Ursnif/ISFB | tag 163/210 (chưa thu) | 43 | tag | Gozi-lineage(train) | MB+BODMAS |
| Tinba | 243 (thu 92 distinct) | 23 | ? | train | MB+BODMAS |
| Zeus/Zbot | 357 (thu) | 473+34 | ATM/Families | Zeus-lineage | MB+BODMAS |
| Emotet | v1 79 | 56 | ? | train | v1+BODMAS |
| TrickBot | v1 396 | 14 | ? | train | v1+BODMAS |
| Dridex | v1 377 | 10 | ? | train | v1+BODMAS |
| IcedID | v1 260 | 5 | ? | train | v1+BODMAS |
| SpyEye | 4–5 | 2 | ? | train | MB+BODMAS |
| Nymaim | 197 | 8 | ? | downloader(riêng) | MB+BODMAS |
| Kronos/PandaBanker/Vawtrak | 0 | 0 | (chỉ VX?) | train | **chưa nguồn nào** (VX chưa kiểm) |
- **Họ CHỈ MỘT NGUỒN quan trọng:** **Qakbot & Carberp chỉ có ở BODMAS** (MB trả 0) → rủi ro **shortcut nguồn↔họ**
  (model học đặc trưng BODMAS-disarm/re-arm thay vì họ) → khi gộp phải **báo ma trận nguồn×họ + linear-probe `source`**
  (§5 MALWARE_SOURCING_PLAN). Latrodectus/PikaBot/Zloader/Ramnit/Citadel chỉ MB.

### 21.3 (task 4) BẢNG CỔNG DUY NHẤT — mỗi dòng: đã khóa / candidate / thiếu (KHÔNG trộn mẫu số)
| hạng mục | đã khóa (v1-v3) | candidate (đã thu, CHƯA khóa) | tổng khả dụng | mục tiêu | THIẾU |
|---|---|---|---|---|---|
| **Malware train chính** (distinct; không Zeus-lineage/downloader) | **702** | **569** = MB 419 (Gozi139+Ramnit31+Tinba92+Latro83+Pika74) + BODMAS 150 | **1.271** | 1.500 | **229** |
| Zeus-lineage (nhóm RIÊNG) | 0 | 744 = MB 398 (Zeus337+Zloader61) + BODMAS 346 | 744 | — (báo riêng) | — |
| Downloader Nymaim (nhóm RIÊNG) | 0 | ~31 = MB 25 + BODMAS 6 | ~31 | — (báo riêng) | — |
| **Benign** train/eval (distinct) | **669** (504 v1/v2 + 165 v3) | +207 v4 | 876 | — (reweight theo bin) | — |
| **(b) bin MSVC14 — malware train chính** | — | 528 (+BODMAS ~10-15 MSVC14) | ~540 pos / 565 benign neg | — | **đủ lực** (AUC CI ±~0.02, MDD 0.028) |
- **Mẫu số tách bạch:** dòng train chính tính vs **1.500**; Zeus-lineage/downloader/benign có mẫu số RIÊNG (không gộp
  vào 1.500); dòng (b) là **đếm trong bin MSVC14** (positives/negatives), không phải distinct-tổng.
- **Còn thiếu 229** cho train chính → lấp bằng: ISFB/Ursnif MB-tag (chưa thu, ~60–140), Citadel-nếu-non-Zeus,
  SpyEye/Carberp đã cạn, VX (Kronos/… chưa kiểm). (task 2 VT đang chạy để xác minh nhãn candidate — ghi §21.4 khi xong.)

**Cổng 🔴 ĐÓNG — không khóa v4, không train.**

### 21.5 Pilot ISFB/Ursnif + probe nguồn + gate cập nhật (2026-10-21)
**(task 2) Pilot ISFB + Ursnif (MB tag, 25/họ, seed 20261021), dedup chéo Gozi-157 (ppdeep):**
| họ | tải | distinct nội bộ | **net-new vs Gozi** | cand (sau sha-old) |
|---|---|---|---|---|
| ISFB | 25 | 24 | **23** | 146 |
| Ursnif | 25 | 24 | **23** | 47 |
- Chéo ISFB+Ursnif: 45 distinct/50. **~92% khác Gozi** dù cùng dòng (mẫu chiến dịch khác). 
- **Dự phóng full (ISFB 146 + Ursnif 47 cand):** ~**120–170 net-new** (Gozi-lineage train) → **lấp gần hết 229**.

**(task 3) Ma trận nguồn + probe shortcut nguồn:**
- **Probe LogisticRegression dự đoán NGUỒN (BODMAS vs MB/v1) từ metadata, OOF GroupKFold-theo-họ (7 họ chung,
  n=581): AUC = 0.573 ≈ ngẫu nhiên** → **metadata KHÔNG lộ nguồn/re-arm → rủi ro shortcut nguồn THẤP.**
  Gộp BODMAS+MB an toàn ở mức metadata; Qakbot/Carberp (chỉ-BODMAS) không tạo confound nguồn dễ-học.
  *(Lưu ý: đây là probe METADATA; BFBG dùng VEX/call-graph — vẫn nên probe `source` trên embedding khi train.)*
- Khác biệt nguồn (nhỏ): BODMAS x64 10% / Rich 74% / CRT 32% / maxE 7.18; MB/v1 x64 20% / Rich 86% / CRT 23% / maxE 7.04
  (BODMAS 2019-20 nghiêng x86-32 + pack hơn chút).
- Bin×năm: BODMAS first_seen 2019-2020 (đa số MSVC≤10/x86-32); MB pulls 2021-2025 (Latro/Pika 2022+ MSVC14);
  v1 2021 (TrickBot/BumbleBee MSVC14). → nguồn ~ tương quan năm/bin nhưng metadata không tách được nguồn (AUC 0.573).

### 21.6 (task 4) BẢNG CỔNG — cập nhật sau ISFB/Ursnif pilot (candidate)
| hạng mục | đã khóa | candidate (đã thu) | +dự phóng ISFB/Ursnif full | tổng khả dụng | mục tiêu | THIẾU |
|---|---|---|---|---|---|---|
| **Malware train chính** (distinct) | 702 | 569 (MB 419 + BODMAS 150) | +~120–170 | **~1.390–1.440** | 1.500 | **~60–110** |
| Zeus-lineage (riêng) | 0 | 744 | — | 744 | — | — |
| Downloader Nymaim (riêng) | 0 | ~31 | — | ~31 | — | — |
| Benign (distinct) | 669 | +207 v4 | — | 876 | — | — |
| (b) bin MSVC14 malware/benign | — | ~540 / 565 | — | — | — | đủ lực |
- Sau khi tải đủ ISFB/Ursnif (chưa làm) → train chính ~1.390–1.440, **còn thiếu ~60–110** → lấp nốt bằng Citadel(nếu
  non-Zeus)/SpyEye/VX hoặc nới định nghĩa loader. **VT candidate đang tra (§21.4 khi xong).**

**Cổng 🔴 ĐÓNG — không khóa v4, không train, không chạm v3/holdout.**

### 21.4 VT xác minh candidate BODMAS (490/502, 2026-10-21; ngưỡng khóa ≥3 engine)
Tra VT theo **sha gốc** (tên file = sha pre-disarm; VT có mẫu gốc). 12 candidate còn lại → mai (quota 500/ngày).
| họ (nhãn BODMAS) | tra | khớp-họ | None (VT ko nhãn) | nhãn-khác | nghi (<3 engine) |
|---|---|---|---|---|---|
| zbot | 318 | 20 | 283 | 15 | 0 |
| emotet | 41 | 12 | 25 | 4 | 0 |
| qakbot | 32 | 4 | 28 | 0 | 0 |
| ursnif | 32 | 2 | 24 | 6 | 0 |
| pwszbot | 16 | 0 | 15 | 1 | 0 |
| tinba | 13 | 6 | 3 | 4 | 0 |
| gozi | 12 | 0 | 10 | 2 | 0 |
| trickbot | 11 | 6 | 2 | 3 | 0 |
| nymaim/icedid/carberp/dridex/spyeye | 15 | 1 | 14 | 0 | 0 |
| **TỔNG** | **490** | **51** | **404 (82%)** | **35 (7%)** | **0** |
- **0 mẫu <3 engine → TOÀN BỘ 490 là malware** (xác nhận độc lập). **Không loại candidate nào** (ngưỡng khóa ≥3).
- **82% KHÔNG có nhãn popular VT** (`suggested_threat_label`=None) — vì mẫu **cũ 2019-2020**, VT thiếu consensus family,
  **KHÔNG phải nhãn mâu thuẫn**. Trong **86 mẫu CÓ nhãn VT → khớp họ 59%** (≈ MB 71% khi có nhãn); nhãn-khác chỉ 7%.
- **vs MB (71% khớp, mẫu mới):** nhãn family BODMAS **đồng thuận tương đương KHI VT có ý kiến**, nhưng VT **phần lớn
  bỏ trống** (mẫu cũ) → **nhãn family BODMAS chủ yếu dựa vào labeling của BODMAS, ít được VT xác nhận độc lập**.
- **HẠN CHẾ cho họ chỉ-BODMAS (Qakbot 28/32 None, Carberp 2/2 None):** nhãn family **gần như không được VT corroborate**
  → attribution dựa vào BODMAS; nêu rõ khi dùng Qakbot/Carberp làm QakBot/Carberp-lineage. 35 mẫu "nhãn-khác" → đánh dấu review.
- Gate (train net-new 150) **không đổi** (0 loại; tất cả là malware).

---

## 22. Dọn đĩa + ISFB/Ursnif full + probe nguồn trong-họ + gate đo-thật (2026-10-21)

### 22.0 (task 0) Dọn đĩa
- **HOME: 20G → 34G** (≥30G ✓). Xóa: stale imports (import_batch1/scoop/iso/choco/bodmas_survey ~2.4G), **loader_pilot raws 12G**
  (ppdeep cache 299 + features + manifest + tải lại MB được). **DATA zip BODMAS 68G** đã xóa (backup = bản giải nén
  **57.293 file** + meta_disarm còn trên DATA, 210G trống). Features/ppdeep-caches/manifests/v1-raw/meta_disarm GIỮ.
- **⚠️ `bodmas_pilot` raws bị xóa ngoài ý muốn** (nghi lệnh dọn `*_angr_rtdb` phiên trước). **Phục hồi được**:
  features_graph_bodmas (736) + bodmas_ppdeep.json (746) + bodmas_netnew_shas.json + DATA extracted (57.293) + meta_disarm
  đều còn → re-extract+re-arm khi cần raw để khóa.

### 22.1 (task 1) ISFB + Ursnif ĐỦ (MB tag, dedup chéo TOÀN BỘ) — ĐO THẬT
| họ | n (manifest) | distinct nội bộ | net-new vs Gozi | **net-new vs TOÀN BỘ ref (4105)** |
|---|---|---|---|---|
| ISFB | 145 | 125 | 123 | **123** |
| Ursnif | 29 | 28 | 27 | **27** |
| **chéo ISFB+Ursnif** | 174 | 139 | — | **137** |
- **ISFB/Ursnif đóng góp train chính (Gozi-lineage) = 137 distinct net-new** (vs toàn bộ, kể cả BODMAS gozi/ursnif + MB Gozi).
- Lift 117 mẫu mới (nền). Dir dư so manifest (+~14, hiện tượng §16.3) → dùng manifest-authoritative.

### 22.2 (task 2) Probe NGUỒN trong 6 họ có cả MB+BODMAS (Emotet/Gozi/TrickBot/Tinba/Dridex/IcedID)
- Feature metadata từ JSON (max/mean-entropy, #imports, #api, #functions, log-size, #sections). n=466 (BODMAS 110 / MB 356).
- **AUC dự đoán NGUỒN, OOF GroupKFold-theo-họ = 0.206 (< 0.5)** → **metadata KHÔNG dự đoán được nguồn ổn định**
  (hướng nguồn lệch theo từng họ, không tổng quát hoá) → **KHÔNG có shortcut nguồn↔họ đáng ngại ở mức metadata**.
  Per-họ: emotet 0.38, trickbot 0.25, dridex 0.09, icedid 0.13, gozi 0.22, tinba 0.19 (đều <0.5).
- **Qakbot & Carberp: KHÔNG KIỂM ĐƯỢC** (chỉ một nguồn = BODMAS) → không thể tách source↔family; **ghi hạn chế**:
  nếu model tách được Qakbot/Carberp, không loại trừ được việc học đặc trưng BODMAS/re-arm (cần probe `source` trên
  embedding + giữ các họ này ở nhóm đánh giá, không trộn tuỳ tiện).

### 22.3 (task 3) HẠN CHẾ — VT xác nhận họ BODMAS yếu
- **82% candidate BODMAS KHÔNG có nhãn popular VT** (`suggested_threat_label`=None; mẫu cũ 2019-20) — §21.4. Trong 86 mẫu
  có nhãn → khớp 59%. → **nhãn family BODMAS chủ yếu dựa labeling nội bộ BODMAS, ít corroborate độc lập**; đặc biệt
  **Qakbot (28/32 None) + Carberp (2/2 None)** — attribution gần như chỉ dựa BODMAS. Nêu rõ trong bài (threats to validity).
- Toàn bộ candidate BODMAS vẫn là **malware xác nhận** (0 mẫu <3 engine).

### 22.4 (task 4) BẢNG CỔNG — ĐO THẬT (không dự phóng)
| hạng mục | đã khóa (v1-v3) | candidate (đã thu, dedup, ĐO THẬT) | tổng | mục tiêu | THIẾU |
|---|---|---|---|---|---|
| **Malware train chính** (distinct) | **702** | **706** = MB 419 (Gozi139+Ramnit31+Tinba92+Latro83+Pika74) + BODMAS 150 + ISFB/Ursnif 137 | **1.408** | 1.500 | **92** |
| Zeus-lineage (riêng) | 0 | 744 (MB 398 + BODMAS 346) | 744 | — | — |
| Downloader Nymaim (riêng) | 0 | ~31 | ~31 | — | — |
| Benign (distinct) | 669 | +207 (v4) | 876 | — | — |
| (b) bin MSVC14 malware / benign | — | ~540 / 565 | — | — | đủ lực (CI ±0.02) |
- **Train chính 1.408/1.500 → còn thiếu 92** (ĐO THẬT, không dự phóng). Lấp 92 cuối: Citadel(nếu non-Zeus, MB 56),
  SpyEye/Retefe, họ VX chưa kiểm (Kronos…), hoặc ISFB/Ursnif thêm (tag chưa cạn). **Cổng 🔴 ĐÓNG — không khóa v4, không train.**
