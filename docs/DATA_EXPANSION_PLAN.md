# Kế hoạch mở rộng dữ liệu v4 (benign khớp-confound + malware đa dạng hơn)

> **Written for:** đồng tác giả + người dùng (tài liệu kế hoạch nội bộ). Mọi con số "trần nguồn" là
> **ước lượng trước-thu-thập** (metadata hoặc pilot cũ); **chưa tải hàng loạt**. **Hỏi người dùng trước
> khi tải.** Không chạm v1/v2/v3/holdout; v4 là tập MỚI (bất biến "không sửa tập cũ", xem `DATASET.md`).

Ngày: 2026-10-15. Động lực: run GRL biến thể 1 bị dừng sớm vì **benign chưa khớp-confound**
(xem `GRL_DESIGN.md` mục "Run thăm dò … BỊ DỪNG SỚM"). Trước khi thử lại bất-biến toolchain, cần một
holdout/benign khớp phân phối toolchain×size của malware để phép đo bất-biến không lẫn với lệch nguồn.

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

### 4.2 VX-Underground (nguồn phụ, thủ công)
- Hiện đã có **8 mẫu VX import thủ công** (`DATASET.md`). VX-Underground phát hành theo **collection/family**
  dạng file-share (không có API `get_siginfo` như MB) → **trần = ước lượng sau khi tải thủ công từng collection**,
  không khảo sát tự động được ở đây. Dùng để bổ sung family MB thiếu (Ursnif/ISFB/QakBot) **nếu** xác minh được
  nhãn family + đúng loại banking. Ghi nguồn + hash như các mẫu VX hiện có.

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
