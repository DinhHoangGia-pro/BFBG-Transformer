# Quy tắc loại mẫu + seed holdout v3 — ĐÓNG BĂNG TRƯỚC KHI TẢI (2026-10-14)

Commit này phải có TRƯỚC mọi lần tải/chấm v3 (quy tắc khóa, HOLDOUT_V3_PLAN §5).

## Seed (tất định)
- `V3_SEED = 20261008` (shuffle danh sách ứng viên app; tie-break theo tên app rồi sha256).

## Quy tắc loại / rơi (áp lúc harvest; mẫu RƠI bị LOẠI, KHÔNG thay thế)
1. **Không phải PE** (không MZ / 7z Type≠PE) → loại.
2. **Installer**: tên khớp `(setup|install|uninst)` → loại (chỉ giữ payload trong).
3. **Forwarder** `api-ms-win-*` / `ext-ms-*` → loại.
4. **Size** > 12 MiB → loại (CAP=12*1024*1024).
5. **Dedup sha256 chính xác** vs TOÀN BỘ v1 + v2 (mọi split) và vs mẫu v3 đã giữ → loại.
6. **Dedup ppdeep ≥ 90** vs v1 + v2 benign và vs v3 đã giữ → loại (near-dup).
7. **num_functions == 0** (angr rỗng) → loại (đánh dấu nf0).
8. **Build lỗi/timeout** (angr) → rơi (đánh dấu build_fail), không thay thế.
9. **Trùng app đã thu ở v2** (orig_name) → bỏ qua app.
10. **Cap mỗi app ≤ 3 payload** (tránh một app thống trị).
11. **Cap vendor NirSoft ≤ 35%** holdout cuối (áp khi sinh manifest, trên SỐ THẬT).

## Mẫu rơi
- Mọi mẫu loại/rơi ghi vào `v3_state.jsonl` (ngoài git) với sha256 (nếu có), app, step, reason.
- Khi sinh manifest cuối: xuất danh sách loại (sha + reason) kèm hash, commit TRƯỚC khi chấm.

## Cô lập
- Raw v3 → `~/bfbg_benign_work/import_v3/` (KHÔNG vào `data/raw/benign`).
- Feature v3 → `~/bfbg_benign_work/v3_features/` (KHÔNG vào `data/features_graph`).
- → v3 không thể lọt vào train/dev cho tới khi có manifest + lệnh rõ.

## Sửa trước khi chạy tiếp (2026-10-14) — tham số VẬN HÀNH (không phải bước lọc)
- **Thermal guard = CPU (Package id 0 qua `sensors`) VÀ GPU (nvidia-smi)**, lấy nhiệt cao nhất trong hai;
  ngưỡng giữ nguyên: >85°C kéo dài → tạm dừng 10′; >90°C hoặc 3 lần tạm dừng liên tiếp → kết thúc phiên sạch.
  (Bản trước chỉ theo GPU; máy nóng chủ yếu ở CPU khi build angr nên bổ sung CPU.)
- **Xác nhận:** TẤT CẢ bước LỌC mẫu (quy tắc 1–11 ở trên) đã nằm trong file này; harvest_v3.py không có bước lọc nào ngoài file. Thermal/session-cap/batch/rest là tham số vận hành, không loại mẫu.
