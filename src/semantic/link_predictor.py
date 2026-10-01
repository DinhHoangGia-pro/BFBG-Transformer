"""
link_predictor.py
=================
Learned Semantic Dependency Predictor (Paper1 Section 4.3), tách từ
scripts/train_tcfbg_defi.py.

MLP nhận cặp embedding (h_i, h_j) trong cùng một đồ thị nội hàm, dự đoán
P(e_sem = 1). Huấn luyện weak-supervision: các cặp seed (do bộ luật seed
sinh ra) làm nhãn dương, cặp ngẫu nhiên loại trừ seed làm nhãn âm,
loss = BCE.

Nguồn seed là tham số tổng quát `seed_pairs` (danh sách [i, j] chỉ số node
cục bộ) — không còn gắn với 5 luật SWC của bản EVM; bảng luật ATT&CK cho
miền PE sẽ được nạp qua src/semantic/seed_rules_attck.py.
"""

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

SEM_EDGE_THRESHOLD = 0.5
NEG_SAMPLE_RATIO = 3


class LearnedSemanticDependencyPredictor(nn.Module):
    def __init__(self, in_dim):
        super().__init__()
        self.mlp = nn.Sequential(
            nn.Linear(in_dim * 2, in_dim), nn.ReLU(),
            nn.Linear(in_dim, in_dim // 2), nn.ReLU(),
            nn.Linear(in_dim // 2, 1),
        )

    def forward(self, h, pairs_idx):
        hi, hj = h[pairs_idx[:, 0]], h[pairs_idx[:, 1]]
        logits = self.mlp(torch.cat([hi, hj], dim=-1)).squeeze(-1)
        return logits

    def predict_edges(self, h, threshold=SEM_EDGE_THRESHOLD, max_candidates=200):
        n = h.size(0)
        if n < 2:
            return torch.empty((2, 0), dtype=torch.long, device=h.device)
        k = min(max_candidates, n * (n - 1))
        idx_i = torch.randint(0, n, (k,), device=h.device)
        idx_j = torch.randint(0, n, (k,), device=h.device)
        mask = idx_i != idx_j
        idx_i, idx_j = idx_i[mask], idx_j[mask]
        with torch.no_grad():
            logits = self.mlp(torch.cat([h[idx_i], h[idx_j]], dim=-1)).squeeze(-1)
            probs = torch.sigmoid(logits)
        keep = probs > threshold
        return torch.stack([idx_i[keep], idx_j[keep]], dim=0)


def sample_weak_labels(num_nodes, seed_pairs, neg_ratio=NEG_SAMPLE_RATIO):
    """seed_pairs: các cặp [i, j] (chỉ số node cục bộ) từ bất kỳ nguồn luật
    seed nào, dùng làm nhãn dương. Trả về (pairs_idx, labels) hoặc
    (None, None) nếu đồ thị quá nhỏ."""
    if num_nodes < 2:
        return None, None
    pos = [tuple(p) for p in seed_pairs if p[0] < num_nodes and p[1] < num_nodes]
    n_neg = max(1, len(pos) * neg_ratio) if pos else min(4, num_nodes)
    pos_set = set(pos)
    neg = []
    attempts = 0
    while len(neg) < n_neg and attempts < n_neg * 10:
        i, j = np.random.randint(0, num_nodes), np.random.randint(0, num_nodes)
        attempts += 1
        if i != j and (i, j) not in pos_set:
            neg.append((i, j))
    all_pairs = pos + neg
    if not all_pairs:
        return None, None
    labels = [1.0] * len(pos) + [0.0] * len(neg)
    return torch.tensor(all_pairs, dtype=torch.long), torch.tensor(labels, dtype=torch.float)


def semantic_link_loss(predictor, h_local, seed_pairs, neg_ratio=NEG_SAMPLE_RATIO):
    """BCE weak-supervision loss cho một đồ thị; None nếu không lấy được cặp nào."""
    pairs_idx, labels = sample_weak_labels(h_local.size(0), seed_pairs, neg_ratio)
    if pairs_idx is None:
        return None
    logits = predictor(h_local, pairs_idx.to(h_local.device))
    return F.binary_cross_entropy_with_logits(logits, labels.to(h_local.device))
