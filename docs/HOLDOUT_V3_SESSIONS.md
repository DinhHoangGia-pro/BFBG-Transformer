# Nhật ký phiên harvest holdout v3 (local, chưa sinh manifest)

## PHIÊN 1 — 2026-10-14 (08:16→~12:01, elapsed 3.74h)
- Cấu hình: workers=2, batch 40, nghỉ 5′, guard report-only (người dùng lo tản nhiệt), full core, seed 20261008, xen kẽ Scoop:NirSoft 3:2, dedup sha256+ppdeep≥90 vs v1/v2 + nội bộ v3.
- **stop = hết ứng viên sau khi đủ target** (scoop 77, nirsoft 50).
- apps xử lý = 116 | **kept (raw) = 129** | dedup_drop = 11 | app_fail = 4
- **build_ok = 106** | build_fail = 21 (đều "no feature json" = angr lỗi/timeout → rơi, không thay thế) | nf0_drop = 0
- NirSoft trong kept = 50/129 = **39%** (> cap 35% → sẽ cắt ở bước sinh manifest, trên số thật).
- Nhiệt: thermal_pauses = 0 (report-only), peak CPU 100°C, peak GPU 48°C.
- Raw → import_v3/ ; feature → v3_features/ (ngoài data/, chưa vào train).
- **CHƯA sinh manifest v3** (Task 4: chỉ khi mọi phiên xong + cap vendor trên số thật, commit trước mọi phép chấm).

### Phân tích build_fail PHIÊN 1 (21 mẫu)
- Nguyên nhân: **14 Timeout angr (>900s, kill)** + **7 dotnet_clr (out-of-scope .NET)**.
- Bin: khác 11, GNU/MinGW 6, MSVC14 2, MSVC≤10 1, Delphi 1. Size median 7.6MB / max 12.7MB.
- **Thiên lệch mẫu rơi:** nghiêng về file lớn/nhiều hàm (timeout) + bin khác/GNU → benign built còn lại ĐƠN GIẢN hơn (ít hàm) → ghi Threats-to-Validity.
- build_ok theo bin: MSVC≤10 64, MSVC14 23, Go 9, khác 6, GNU 4 → **MSVC14=23 (cần ≥40, PHIÊN 2 bù bằng scoop)**.

## PHIÊN 2 — 2026-10-14 (12:53→17:08, ~4h15) — Scoop-only, workers=1, no-guard
- stop = DỪNG TAY khi đủ mục tiêu (watcher auto-stop lỗi in blank dưới tải; tôi dừng thủ công khi check ENOUGH).
- **Cộng dồn 2 phiên:** kept(raw)=211 (scoop 161 / nirsoft 50), app_done=191, dedup_drop=21, app_fail=12.
- **Feature built (usable) = 166** (scoop 116 / nirsoft 50); build_fail cộng dồn=26; nf0=0.
- **MSVC14 built = 41 (≥40 ✓)**; **tổng sau cap = 166 (≥120 ✓)** — NirSoft 50/166 = **30% ≤35% → cap KHÔNG cắt** (giữ cả 166).
- Nhiệt phiên 2 (no-guard, người dùng tản nhiệt): peak CPU **100°C**, GPU 47°C, **ge95 ≈ 228 mẫu đo**. thermal_pauses=0.
- Raw import_v3/, feature v3_features/ (ngoài data/). **CHƯA sinh manifest** (Task 4).
