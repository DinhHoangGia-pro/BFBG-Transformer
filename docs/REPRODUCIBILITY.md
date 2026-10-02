# Reproducibility

Ghi chú về tính tái lập và cách đọc đúng kết quả pipeline.

## build_graphs.py

- Log console của `build_graphs.py` có thể chèn dòng khi chạy nhiều worker (print không atomic) - đây chỉ là hiển thị, không ảnh hưởng dữ liệu. Số liệu chính xác nằm ở `lift_failures.jsonl`, `out_of_scope_samples.jsonl`, và tổng kết cuối cùng.
