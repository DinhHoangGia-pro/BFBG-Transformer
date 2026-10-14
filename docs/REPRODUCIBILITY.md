# Reproducibility

All numbers in the paper are generated from committed artifacts. The held-out set (v3) is
evaluated exactly once; its result file is hashed and the evaluation is guarded by a run-once lock.

## Environment
- OS: Linux (x86_64). GPU: NVIDIA RTX 2080 Super Max-Q (CUDA). CPU builds dominate feature construction.
- Python 3.14.4 (virtualenv `~/bfbg_venv`).
- Key libraries: angr 10.0.1, torch 2.14.1+cu130, torch_geometric 2.8.0, pefile 2024.8.26,
  ppdeep 20260221, scikit-learn 1.9.1, numpy 2.5.3.
- Heavy jobs run under a systemd user cgroup (`MemoryMax`, `nice 19`) to bound memory.

## Frozen artifacts and hashes
- `docs/dataset_v1_manifest.jsonl`, `docs/dataset_v2_manifest.jsonl` (SHA256 `e2e2c67a...`),
  `docs/dataset_v3_manifest.jsonl` (165 benign, SHA256 `9f6e54f2...`).
- v3 evaluation config `docs/v3_eval_config.json` (CONFIG_HASH `55ace0a9...`);
  drop list `docs/V3_DROP_LIST.jsonl` (`57e7315b...`); freeze record `docs/FREEZE_v3.md`.
- v3 result (per-sample scores + metrics) `docs/v3_eval_result.json` (SHA256 `1dca53a2...`).
- Table provenance: `paper_tables/TABLES_MANIFEST.md`.

## Run order
1. Build features (angr) for all samples into `data/features_graph/` (malware/benign) and, for the
   held-out benign, `~/bfbg_benign_work/v3_features/` (not required to reproduce tables if caches exist).
2. Dev / within-bin / LOFO tables (cache-only, no training, no holdout):
   `python experiments/dataset/pilots/reproduce_tables.py`
3. Export all paper tables (CSV + LaTeX + provenance), reading v3 from the locked result (not recomputed):
   `python experiments/dataset/pilots/export_paper_tables.py`  -> writes `paper_tables/`.
4. Held-out v3 evaluation is ALREADY DONE and locked. To re-derive its numbers, read
   `docs/v3_eval_result.json`; do not re-run (the run-once lock refuses a second touch).
   The scoring entry point is `experiments/dataset/pilots/eval_v3.py` (`--selftest`, `--subtest`, `--run`).

## Caches (machine-local, not in git)
- `~/bfbg_benign_work/feat_cache.jsonl` (PE metadata + graph scalars per sample),
  `~/bfbg_benign_work/bin_parse.pkl` (model-view token/API counters, seed-edge stats),
  `~/bfbg_benign_work/foldrun_v2es*/v2api*.json` (BFBG per-seed scores),
  `~/bfbg_benign_work/v3_features/` (v3 feature JSONs), `~/bfbg_benign_work/eval_v3.lock`.

## What is NOT distributed
- **Malware samples and benign binaries are not redistributed.** We release only **SHA256 hashes**
  (in the manifests) plus derived features/scores. Malware (TrickBot, Dridex, BumbleBee, IcedID,
  Emotet) can be obtained by hash from the original source under its terms; benign programs can be
  re-fetched from their named repositories (Windows ISO, Chocolatey, Scoop, NirSoft).
- Full feature JSONs for very large programs are large (v3 total ~7.7 GB); released as hashes + the
  scripts to regenerate, not as blobs.
