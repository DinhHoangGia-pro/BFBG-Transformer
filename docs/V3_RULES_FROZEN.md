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

## Điều chỉnh trước PHIÊN 1 chạy lại (2026-10-14) — vận hành
- **Xen kẽ nguồn Scoop:NirSoft ~3:2** (không tải hết nguồn này rồi sang nguồn kia); thứ tự app theo seed 20261008 (mỗi nguồn shuffle riêng rồi xen kẽ).
- **Dedup ppdeep≥90** áp với v1/v2 **VÀ nội bộ v3** (so với mẫu v3 đã giữ); giữ mẫu ĐẦU theo thứ tự seed, mẫu sau trùng bị loại.
- **"3 lần tạm dừng LIÊN TIẾP"** = 3 lần tạm dừng nhiệt mà **KHÔNG có đợt (batch) nào build hoàn tất sạch xen giữa**. Bộ đếm tạm dừng chỉ reset=0 sau một batch build sạch; nhiệt về bình thường KHÔNG reset.
- Tóm tắt cuối phiên ghi thêm: số lần tạm dừng nhiệt, tổng thời gian dừng, nhiệt CPU/GPU đỉnh, tỉ lệ NirSoft trong phần đã giữ (cap 35%).

## PHIÊN 1 (bản chạy lại 2026-10-14) — cấu hình nhiệt do người dùng chốt
- **workers=1**, **batch ~15**, **nghỉ 10 phút** giữa batch (giảm tải nhiệt).
- Thermal guard: **tạm dừng 10 phút khi CPU(Package id 0) ≥ 92°C kéo dài 3 phút**; **kết thúc phiên sạch khi ≥ 96°C HOẶC 3 lần tạm dừng liên tiếp** (liên tiếp = không có batch sạch xen giữa). Lấy max(CPU, GPU).
- Đo nghỉ 3 lần (30s): 68/56/48°C (đang nguội; idle thật ~48–65°C). KHÔNG dùng số "87°C" (đo lệch ngay sau tải).
- 15 phút đầu phiên: ghi nhiệt CPU/GPU mỗi 30s → `~/bfbg_benign_work/v3_temps.jsonl` để xác nhận workers=1 giữ CPU<92°C; nếu KHÔNG giữ được thì BÁO (không tự nâng ngưỡng).
- Tóm tắt cuối phiên: số lần tạm dừng + nhiệt đỉnh (đã có).

## Giảm nhiệt bằng taskset (2026-10-14) — workers=1 vẫn chạm 100°C
- workers=1/batch15 vẫn ghim CPU ~100°C (guard clean-finish sau ~2 app). → Ghim TOÀN phiên vào **4 core: `taskset -c 0-3`** (cả ppdeep ref + angr build + mọi tiến trình con) để giảm nhiệt tại gốc.
- Giữ nguyên guard 92/96, workers=1, batch 15, nghỉ 10′, logger nhiệt 15′ đầu.
- Thử 15′: nếu CPU<92°C → chạy tiếp (đo ~60′/lần); nếu KHÔNG → BÁO (không nâng ngưỡng).
- State giữ nguyên để resume (2 mẫu phiên trước đã clean-finish vẫn tính).

## Chạy hết mức (2026-10-14) — người dùng tự lo tản nhiệt
- Người dùng chịu trách nhiệm tản nhiệt; guard chuyển **REPORT-ONLY** (`THERMAL_ACTION=False`): chỉ GHI/BÁO nhiệt, **KHÔNG tạm dừng, KHÔNG kết thúc theo nhiệt**.
- Khôi phục **workers=2, batch 40, nghỉ 5′, BỎ ghim core** (chạy hết mức). Logger nhiệt 15′ đầu + nhiệt đỉnh trong tóm tắt vẫn giữ (chỉ để báo).
- Trần phiên 7h30 + dedup + cap vendor + các bước lọc 1–11 GIỮ NGUYÊN.

## PHIÊN 2 (2026-10-14) — quyết định người dùng
- **Nguồn: chỉ Scoop (Main+Extras), BỎ NirSoft** (đã đủ 50 ở phiên 1).
- **KHÔNG guard nhiệt** (người dùng tự lo tản nhiệt): chỉ GHI nhiệt CPU(Package id 0)+GPU **mỗi ~60 phút** vào log; cuối phiên báo **nhiệt đỉnh + số mẫu ≥95°C**. Không tạm dừng/kết thúc theo nhiệt.
- workers=1, nice 19, cgroup 8G, trần phiên 7h30; không tắt máy.
- **Mục tiêu: ≥40 MSVC14 VÀ tổng ≥120 sau cap**; dừng khi đủ (theo dõi thủ công vì cap tính ở manifest).
- **Cap vendor** (NirSoft ≤35%) áp ở bước sinh manifest, tất định (seed 20261008, thứ tự sha), ghi danh sách mẫu bị bỏ do cap.

## Metric trên v3 (khóa 2026-10-14) — v3 CHỈ benign
- v3 = **benign-only (166)** → chỉ đo **FPR** tại ngưỡng cố định chọn từ **train/dev** (KHÔNG từ v3), kèm Wilson CI.
- **AUC cần mẫu dương ghép, CHỌN TRƯỚC:** dùng **BumbleBee holdout (holdout_family_bumblebee, 262 malicious)** làm positives — **nguồn ghi rõ, KHÔNG lấy từ train**. AUC(BumbleBee vs v3-benign) + cluster-bootstrap CI.
- Chạm v3 MỘT lần với cấu hình đã commit (FINAL_CONFIG_PROPOSAL); báo cả tốt lẫn xấu; không chạm lại.
