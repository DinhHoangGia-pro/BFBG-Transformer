# ĐÓNG BĂNG thiết kế & split v2 (2026-10)

Mốc đóng băng TRƯỚC khi chạy BFBG. Mọi thay đổi ĐÁNH GIÁ sau mốc này **phải gắn nhãn "post-hoc"** trong tài liệu/commit.

## Hash tài liệu & artifact (tại thời điểm đóng băng)
| artifact | SHA256 |
|---|---|
| docs/dataset_v1_manifest.jsonl (v1 BẤT BIẾN) | `2c2aa06467b69187b42ec8cf394aa9668d449e2f59302813d3d250b67d1e27c6` |
| docs/dataset_v2_split_plan.jsonl (dry-run, 304 benign mới) | `38378f6e2c836252047fb9b4c3fa69052b4dff17d5abd52620429d19b4d635d3` |
| docs/TRAINING_DESIGN.md | `ce0a5d8eecb6ed272e3acde973c4bfa570d54ddb6d5d8f2fd9bba3e4a10fc582` |
| docs/DATASET.md | `ffeb5090556b415ef51a60040d4ed93b2e26a6f5ce42d1e90aa62b8a24d4f2d9` |
| data/insn_vocab_v2.json (vocab train, gitignore) | `af69e190e0c9eed0e39b8b30fc88238b6389fe5033222d4aa00c45c83f9d1bc8` |

## Trạng thái
- **v1**: bất biến (1.637 mẫu, split đã khóa).
- **v2 split plan**: 304 benign mới (scoop 258 / nirsoft 46) sau dedup+dọn 3rd-party DLL; **train-eligible non-ISO=237, test_indist +46, holdout_source_nirsoft=21, dual-use=0**. ISO cap ≤35% áp Ở LOADER nhưng sau batch1 ISO=141/≈413=34% → không binding.
- **CHƯA build đợt 1, CHƯA train BFBG.** v2 manifest THẬT (kèm num_functions/cluster) sẽ sinh sau khi build 304 benign mới; plan này là hợp đồng gán split, build phải khớp.
- **Tiêu chí thắng (đã khóa):** AUC threshold-free vs holdout chéo-nguồn (choco + nirsoft), claim superiority ở fold khó (Emotet/IcedID) + thiết lập bỏ đặc trưng đường tắt; FPR@ngưỡng là phụ.
