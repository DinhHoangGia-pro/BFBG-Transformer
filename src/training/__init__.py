"""Training/eval harness cho BFBG-Transformer (thiet ke: docs/TRAINING_DESIGN.md).
Hien co: splits (group-aware theo cum), metrics (balanced acc, PR-AUC, FPR@TPR,
cluster-bootstrap), probe_baselines (metadata + graph, cung split/CV).
Loader BFBG (torch_geometric) se them khi train that - CHUA train BFBG."""
