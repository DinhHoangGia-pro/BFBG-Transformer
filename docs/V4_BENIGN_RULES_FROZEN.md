# Quy tắc loại + dedup benign v4 — ĐÓNG BĂNG TRƯỚC KHI TẢI (2026-10-15)

Commit này phải có **TRƯỚC** mọi lần tải benign v4 (tiền-đăng-ký). Kế thừa `V3_RULES_FROZEN.md`,
bổ sung dedup vs malware mới và nhắm 6 ô thiếu. **Không train, không chạm v3/holdout v2, không khóa v4,
cổng dữ liệu ĐÓNG, không push.** Song song với unit VT (`bfbg-vt`) — KHÔNG dừng, KHÔNG sửa file VT.

## Seed (tất định)
- `V4_SEED = 20261015`. Shuffle danh sách ứng viên mỗi nguồn; tie-break theo tên app rồi sha256.
- Thứ tự nguồn tất định; **dừng một nguồn khi ô của nó đã đủ** (không tải đuổi số lượng chung).

## Quy tắc loại / rơi (áp lúc harvest; mẫu RƠI bị LOẠI, KHÔNG thay thế)
1. **Không phải PE** (không MZ / `7z Type≠PE`) → loại.
2. **Installer**: tên khớp `(setup|install|uninst)` → loại (chỉ giữ payload PE bên trong; rule `benign-installer-payload-only`).
3. **Forwarder DLL** `api-ms-win-*` / `ext-ms-*` → loại.
4. **DLL bên thứ ba lặp**: DLL runtime/bên-thứ-ba dùng chung lặp qua nhiều app (vd `vcruntime*`, `msvcp*`,
   `Qt*`, `libcrypto*`, `ffmpeg*`, `icu*`…) → loại (ưu tiên exe chính của app). Giữ exe chính; bỏ DLL bundle phụ.
5. **Size** > 12 MiB → loại (`CAP = 12*1024*1024`).
6. **.NET / CLR** (`dotnet_clr` lúc lift) → loại (out-of-scope).
7. **num_functions == 0** (angr rỗng) → loại (đánh dấu `nf0`).
8. **Build lỗi/timeout** (angr) → rơi (`build_fail`; OOM=ProcessCrash exit-9 **tách** Timeout, ghi kèm sha), KHÔNG thay thế.
9. **Dedup sha256 chính xác** vs **TOÀN BỘ dữ liệu cũ**: v1+v2+v3 (mọi nhãn, mọi split) **+ 614 malware mới**
   (`data/features_graph_pilot_v4`) **+ mẫu v4 benign đã giữ** → loại.
10. **Dedup ppdeep ≥ 90** vs **cùng tập trên** (v1/v2/v3 benign **và malicious**, 614 malware mới, v4 benign đã giữ) → loại.
11. **Trùng mẫu HOLDOUT cũ** (sha256 hoặc ppdeep≥90 vs `holdout_source_chocolatey`, `holdout_source_nirsoft` v2,
    toàn bộ v3 benign) → **loại** (không để rò holdout).
12. **KHÔNG dùng Chocolatey** (đã là holdout).
13. **Cap ≤ 3 payload/app** (tránh một app thống trị).
14. **Cap vendor ≤ 35% mỗi bin** (tất định, trên số thật khi sinh manifest). **NirSoft không vượt cap đã có**
    (v2 holdout 20 + v3 50 là NirSoft; v4 chỉ thêm nếu vẫn ≤35%/bin và không trùng các mẫu NirSoft cũ).

## Ô mục tiêu (6 ô thiếu nhất — `HOLDOUT_V4_MATCH_ESTIMATE.md` / `DATA_EXPANSION_PLAN.md §2`)
1. **MSVC≤10 × 256KB–1MB** (thiếu 77) 2. **MSVC14 × 256KB–1MB** (43) 3. **MSVC14 × 1–4MB** (13)
4. **MSVC11-12 × 256KB–1MB** (14) 5. **MSVC11-12 × 1–4MB** (17) 6. **MSVC11-12 × <256KB** (20).
Bin toolchain bằng bộ đã kiểm `validate_tc.py` (80%, Rust fold MSVC14). Size bucket theo `file_size`.
**Dừng nguồn/ô khi ô đạt mục tiêu** (mục tiêu v4 §5.1: ô lớn ≥100/phía, ô nhỏ ≥20).

## Nguồn (thứ tự tất định; KHÔNG Chocolatey)
1. **Scoop Versions/Extras** (bản cũ → MSVC đời cũ cho ô #1/#4/#5/#6) + Main.
2. **PortableApps.com** (app cũ có ký → MSVC≤10 ô #1).
3. **GitHub/SourceForge release cũ** (tag 2008–2015 → MSVC≤10/11-12).
4. **Freeware cũ** (IrfanView 8, 7-Zip cũ, Notepad++ cũ…).
5. NirSoft chỉ bổ sung ô #1 nếu còn dưới cap (một vendor → siết cap).

## Cô lập (KHÔNG đụng v1-3 và VT)
- Raw → `~/bfbg_benign_work/v4_benign/` (KHÔNG vào `data/raw/benign`).
- Feature → `~/bfbg_benign_work/v4_benign_features/` (KHÔNG vào `data/features_graph`).
- State → `~/bfbg_benign_work/v4_benign_state.jsonl` (mọi mẫu giữ/loại/rơi: sha, app, nguồn, bin, size, step, reason).
- KHÔNG đọc/sửa state hay file của v1/v2/v3 và VT (`data/vt/*`, `v3_*`, `import_v3/`).
- → v4 benign không thể lọt vào train/dev/holdout cho tới khi có manifest + lệnh rõ (cổng đóng).

## Vận hành
- **Tải mạng ≤ 2 luồng**, backoff 429/502/503. **Nếu unit VT gặp 429 → giảm tải mạng việc này** (về 1 luồng / tăng nghỉ).
- **Build**: `workers=4`, cgroup `MemoryMax=14G`, `MemorySwapMax=0`, `nice 19`, `timeout 900`,
  OOM(ProcessCrash exit-9) **tách** Timeout kèm sha. **Trần phiên 7h30**, **resumable** (state bỏ qua mẫu/app đã xong).
- **Kiểm đĩa trống ≥ 30GB TRƯỚC mỗi đợt** → thấp thì DỪNG, báo.
- **sha256 mỗi mẫu GIỮ LẠI** ghi file riêng `~/bfbg_benign_work/v4_benign_kept_sha.txt` để **tra VT sau** (CHƯA tra phiên này).
- Thermal: report-only (người dùng tự lo tản nhiệt), ghi nhiệt đỉnh vào tóm tắt.

## Báo cáo cuối phiên (bắt buộc)
Bảng: mẫu theo nguồn; bin linker; khoảng kích thước; số lấp từng ô (+ còn thiếu bao nhiêu); mẫu rơi theo
nguyên nhân **và** theo bin; trùng dữ liệu cũ (sha/ppdeep); thời gian/mẫu; nhiệt đỉnh. Cập nhật
`DATA_EXPANSION_PLAN.md` (chỉ phần benign). Commit (không trailer). **Dừng sau phiên, hỏi trước phiên tiếp.**
