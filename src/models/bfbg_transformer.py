"""
bfbg_transformer.py
===================
Kiến trúc 3 tầng tách từ scripts/train_tcfbg_defi.py (T_CFBG_Model):

  Stage 1 (Section 4.2): Token-Sequence Transformer trên chuỗi token của
          từng đồ thị nội hàm.
  Stage sem (Section 4.3): Learned Semantic Dependency Predictor bổ sung
          cạnh E_sem — xem src/semantic/link_predictor.py.
  Intra:  GATv2Conv trên E_struct (E_seq + E_data) ∪ E_sem, global_max_pool
          thành embedding hàm.
  Stage 2 (Section 4.4): TransformerConv trên đồ thị liên hàm G_inter,
          global_mean_pool thành embedding chương trình.

Lớp embedding đầu vào không còn gắn với vocab EVM_OPS: truyền `vocab_size`
của bất kỳ vocab nào (x86/VEX), hoặc `pretrained_embedding` (tensor
[vocab_size, embed_dim]) để nạp sẵn trọng số. Chỉ số 0 được dùng làm token
padding/<UNK> như bản gốc.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.nn import Linear
from torch_geometric.nn import GATv2Conv, TransformerConv, global_max_pool, global_mean_pool

from src.semantic.link_predictor import (
    NEG_SAMPLE_RATIO,
    SEM_EDGE_THRESHOLD,
    LearnedSemanticDependencyPredictor,
    semantic_link_loss,
)


# === STAGE 1: TOKEN-SEQUENCE TRANSFORMER (Section 4.2) ===
class TokenSequenceTransformer(nn.Module):
    def __init__(self, vocab_size, embed_dim=64, n_heads=4, n_layers=2, max_len=512,
                 pretrained_embedding=None, freeze_embedding=False):
        super().__init__()
        if pretrained_embedding is not None:
            if pretrained_embedding.shape != (vocab_size, embed_dim):
                raise ValueError(f"pretrained_embedding có shape {tuple(pretrained_embedding.shape)}, "
                                 f"cần ({vocab_size}, {embed_dim})")
            self.embedding = nn.Embedding.from_pretrained(pretrained_embedding, freeze=freeze_embedding)
        else:
            self.embedding = nn.Embedding(vocab_size, embed_dim)
        self.pos_embedding = nn.Embedding(max_len, embed_dim)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim, nhead=n_heads, dim_feedforward=embed_dim * 2,
            batch_first=True, dropout=0.1,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=n_layers)
        self.max_len = max_len

    def forward(self, x_tokens, graph_ptr):
        """Gộp toàn bộ đồ thị trong batch thành 1 tensor có padding, chạy
        self.encoder() đúng 1 lần cho cả batch (tránh overhead gọi kernel
        nhỏ lẻ cho từng hàm)."""
        ptr_list = graph_ptr.tolist()
        n_graphs = len(ptr_list) - 1
        lengths = [min(ptr_list[i + 1] - ptr_list[i], self.max_len) for i in range(n_graphs)]
        max_L = max(lengths) if lengths else 1

        padded_tokens = torch.zeros((n_graphs, max_L), dtype=torch.long, device=x_tokens.device)
        pad_mask = torch.ones((n_graphs, max_L), dtype=torch.bool, device=x_tokens.device)  # True = vi tri pad
        for i in range(n_graphs):
            s = ptr_list[i]
            L = lengths[i]
            padded_tokens[i, :L] = x_tokens[s:s + L]
            pad_mask[i, :L] = False

        pos_ids = torch.arange(max_L, device=x_tokens.device).unsqueeze(0).expand(n_graphs, -1)
        h = self.embedding(padded_tokens) + self.pos_embedding(pos_ids)
        h = self.encoder(h, src_key_padding_mask=pad_mask)

        out_chunks = []
        for i in range(n_graphs):
            s, e = ptr_list[i], ptr_list[i + 1]
            L = lengths[i]
            chunk = h[i, :L]
            if L < (e - s):
                pad = torch.zeros(e - s - L, chunk.size(-1), device=chunk.device)
                chunk = torch.cat([chunk, pad], dim=0)
            out_chunks.append(chunk)
        return torch.cat(out_chunks, dim=0)


# === KIẾN TRÚC ĐẦY ĐỦ (Stage1 + Stage sem + GATv2 + Stage2) ===
class BFBGTransformer(nn.Module):
    def __init__(self, vocab_size, embed_dim=64, hidden_dim=128, num_global_features=4, num_classes=2,
                 pretrained_embedding=None, freeze_embedding=False,
                 sem_edge_threshold=SEM_EDGE_THRESHOLD, neg_sample_ratio=NEG_SAMPLE_RATIO):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.sem_edge_threshold = sem_edge_threshold
        self.neg_sample_ratio = neg_sample_ratio

        self.token_transformer = TokenSequenceTransformer(
            vocab_size, embed_dim=embed_dim,
            pretrained_embedding=pretrained_embedding, freeze_embedding=freeze_embedding,
        )
        self.sem_predictor = LearnedSemanticDependencyPredictor(embed_dim)

        self.gat1 = GATv2Conv(embed_dim, hidden_dim, heads=2, concat=True)
        self.gat2 = GATv2Conv(hidden_dim * 2, hidden_dim, heads=1, concat=False)

        self.macro1 = TransformerConv(hidden_dim, hidden_dim, heads=2, concat=True, dropout=0.1)
        self.macro2 = TransformerConv(hidden_dim * 2, hidden_dim, heads=1, concat=False, dropout=0.1)

        self.fc1 = Linear(hidden_dim + num_global_features, 64)
        self.fc2 = Linear(64, num_classes)
        self.dropout = nn.Dropout(p=0.3)

    @classmethod
    def from_config(cls, vocab_size, cfg=None, **overrides):
        """Tao model tu configs/model.yaml (muc model + semantic); overrides
        ghi de tung tham so, vd pretrained_embedding=..."""
        if cfg is None:
            from src.utils.path_resolver import load_config
            cfg = load_config('model')
        m, sem = cfg['model'], cfg['semantic']
        kwargs = dict(
            embed_dim=m['embed_dim'], hidden_dim=m['hidden_dim'],
            num_global_features=m['num_global_features'], num_classes=m['num_classes'],
            sem_edge_threshold=sem['sem_edge_threshold'], neg_sample_ratio=sem['neg_sample_ratio'],
        )
        kwargs.update(overrides)
        return cls(vocab_size, **kwargs)

    def forward(self, batch_dict, train_sem_predictor=True):
        """batch_dict gồm: intra_batch (PyG Batch các đồ thị nội hàm),
        seed_pairs_per_graph (cặp seed cho từng đồ thị nội hàm, từ nguồn luật
        seed bất kỳ), inter_edges, num_functions, global_features.
        Trả về (logits, sem_loss)."""
        device = self.fc1.weight.device
        intra_batch = batch_dict['intra_batch'].to(device)
        seed_pairs_per_graph = batch_dict['seed_pairs_per_graph']
        inter_edges = batch_dict['inter_edges']
        num_functions = batch_dict['num_functions']
        global_feats_all = batch_dict['global_features'].to(device)

        h_token = self.token_transformer(intra_batch.x, intra_batch.ptr.to(device))

        sem_loss_terms = []
        extra_sem_edges = []
        ptr = intra_batch.ptr.tolist()
        for gi in range(len(ptr) - 1):
            s, e = ptr[gi], ptr[gi + 1]
            h_local = h_token[s:e]

            if train_sem_predictor:
                loss_g = semantic_link_loss(self.sem_predictor, h_local, seed_pairs_per_graph[gi],
                                            neg_ratio=self.neg_sample_ratio)
                if loss_g is not None:
                    sem_loss_terms.append(loss_g)

            pred_edges_local = self.sem_predictor.predict_edges(h_local, threshold=self.sem_edge_threshold)
            if pred_edges_local.numel() > 0:
                extra_sem_edges.append(pred_edges_local + s)

        sem_loss = torch.stack(sem_loss_terms).mean() if sem_loss_terms else torch.tensor(0.0, device=device)

        struct_edges = intra_batch.edge_index
        if extra_sem_edges:
            sem_edges_cat = torch.cat(extra_sem_edges, dim=1)
            full_edge_index = torch.cat([struct_edges, sem_edges_cat], dim=1)
        else:
            full_edge_index = struct_edges

        if full_edge_index.numel() > 0:
            h = F.relu(self.gat1(h_token, full_edge_index))
            h = self.dropout(h)
            h = self.gat2(h, full_edge_index)
        else:
            h = torch.zeros((h_token.size(0), self.hidden_dim), device=device)

        func_embeddings = global_max_pool(h, intra_batch.batch)

        inter_x_list, inter_edge_list, inter_batch_idx = [], [], []
        node_offset = 0
        for idx, num_funcs in enumerate(num_functions):
            program_node_features = func_embeddings[node_offset: node_offset + num_funcs]
            inter_x_list.append(program_node_features)

            edge_idx = inter_edges[idx].to(device)
            if edge_idx.numel() > 0:
                inter_edge_list.append(edge_idx + node_offset)

            inter_batch_idx.append(torch.full((num_funcs,), idx, dtype=torch.long, device=device))
            node_offset += num_funcs

        big_inter_x = torch.cat(inter_x_list, dim=0)
        big_inter_batch = torch.cat(inter_batch_idx, dim=0)

        if len(inter_edge_list) > 0:
            big_inter_edge_index = torch.cat(inter_edge_list, dim=1)
            h_prog = F.relu(self.macro1(big_inter_x, big_inter_edge_index))
            h_prog = self.dropout(h_prog)
            h_prog = self.macro2(h_prog, big_inter_edge_index)
        else:
            h_prog = big_inter_x

        pooled_program = global_mean_pool(h_prog, big_inter_batch)
        combined_vector = torch.cat([pooled_program, global_feats_all], dim=1)

        out = F.relu(self.fc1(combined_vector))
        out = self.dropout(out)
        out = self.fc2(out)
        return out, sem_loss
