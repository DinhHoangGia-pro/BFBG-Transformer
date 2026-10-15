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

**Pilot 2026-10-15 (đo yield, §4.5):** tải thử 75 malware (Zeus/Gozi/Zloader, 25/họ, seed 20261015) vào thư mục
RIÊNG — **KHÔNG khóa vào v4**, nên con số "708" ở trên **không đổi**. Pilot xác nhận yield MB cao (native 96%,
rơi 3%, 0 trùng với dữ liệu cũ). Số malware khác biệt chỉ tăng **sau khi** tải thật + ppdeep nội bộ + khóa manifest v4.
**Còn thiếu để mở cổng:** malware khác biệt ~792; benign 6 ô (77/43/13/14/17/20); nhãn v4; holdout v4. **Không đề xuất train.**

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

---

## 5. KẾ HOẠCH v4 (mục tiêu, nguồn, thứ tự, thời gian, rủi ro, ngưỡng khóa)

### 5.1 Mục tiêu theo ô (benign) — thực dụng, KHÔNG ép khớp 1:1
Khớp 1:1 cần ~1085 benign (§2) — khó khả thi. Mục tiêu đề xuất: **mỗi ô LỚN có ≥100 benign MỖI PHÍA
đủ chia train/test qua group-aware CV**, các ô nhỏ "tồn tại được" (≥20) để bin không rỗng.

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
- **Benign:** mỗi ô LỚN (#1,#2,#3) **≥100 mẫu/ phía**, chia được train/test qua group-aware CV (cụm near-dup
  + vendor, không chia ngẫu nhiên từng mẫu); ô nhỏ (#4,#5,#6) **≥20** để bin tồn tại; **không vendor nào >35%/bin**;
  **không nguồn Microsoft/ISO >30–40% tổng**; bin GNU/Go/Rust **≤10% tổng**.
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
