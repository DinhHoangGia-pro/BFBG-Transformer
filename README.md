# BFBG-Transformer

Phát hiện malware PE bằng Binary Function Block Graph + Transformer. Kiến trúc kế thừa từ T-CFBG (EVM smart contract); xem `docs/LESSONS_FROM_EVM_CODEBASE.md`.

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
