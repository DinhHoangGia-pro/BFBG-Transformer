# BFBG-Transformer (code repo)

Mã nguồn cho bài (hướng B): **"A Shortcut-Aware Evaluation Protocol and Benchmark for Static Banking-Trojan Detection"**.
BFBG (Binary Function Block Graph + Transformer) ở đây là **mô hình được ĐÁNH GIÁ**, không phải đóng góp kiến trúc của bài; đóng góp là **giao thức đánh giá nhận-biết-shortcut + benchmark** (manifest/hash đóng băng, split theo cụm near-duplicate, holdout chéo nguồn, baseline probe). Tên repo/thư mục code giữ nguyên. Kiến trúc kế thừa từ T-CFBG; xem `docs/LESSONS_FROM_EVM_CODEBASE.md`.

## Cài đặt sau khi clone

```bash
python3 -m venv ~/bfbg_venv
source ~/bfbg_venv/bin/activate
pip install -r requirements.txt
pip install -e .            # để `import src.*` chạy được từ mọi thư mục

# BẮT BUỘC: hook chặn commit nhầm file PE (malware) vào repo
cp scripts/hooks/pre-commit.sample .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Hook đọc 2 byte đầu của mọi file đang stage và chặn commit nếu là `MZ` (header PE), kể cả file đã `git add -f` qua `.gitignore` hoặc không có đuôi. `.gitignore` đã bỏ qua toàn bộ `data/` (trừ `data/README.md`) cùng mọi file `.exe/.dll/.sys/.zip/...`; hook là lớp chặn thứ hai cho trường hợp lọt qua.

Bố cục dữ liệu cục bộ: `data/README.md`.
