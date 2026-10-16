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

### 0.1 Trạng thái cổng (cập nhật 2026-10-15) — **ĐÓNG** 🔴
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
