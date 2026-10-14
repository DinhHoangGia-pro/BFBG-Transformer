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
