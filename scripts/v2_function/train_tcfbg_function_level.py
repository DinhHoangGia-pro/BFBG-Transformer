"""
train_tcfbg_function_level.py
====================
PHUONG AN A: don vi mau la 1 HAM (khong phai 1 hop dong). Bo han Stage 2
(macro inter-function Graph Transformer) vi khong con y nghia khi don vi
phan loai da la ham - dung dung kien truc ma DR-GCN/TMP/CGE (2 bai da
trich dan trong Related Work) su dung de dat >90%.

Nguon nhan: function_level_train_index.jsonl (2165 vuln + 2165 safe = 4330
ham, tu SmartBugs-Curated + DAppSCAN, NGUOI AUDIT THAT - khong phai
Slither tu dong).

YEU CAU: pip install torch torch_geometric scikit-learn tqdm numpy
"""

import os
import json
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.nn import Linear
from torch_geometric.nn import GATv2Conv, global_max_pool
from torch_geometric.data import Data, Batch
from torch.utils.data import DataLoader, Dataset
from tqdm import tqdm
import numpy as np
import gc

from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"

# === 1. CAU HINH ===
HIN_DIR_DEFI = os.environ.get('HIN_DIR_DEFI', '.')
TRAIN_INDEX_PATH = os.path.join(HIN_DIR_DEFI, 'function_level_train_index.jsonl')

BATCH_SIZE = 32          # co the lon hon nhieu so ban contract-level, vi
                          # moi mau gio chi la 1 ham (nho hon nhieu 1 hop dong)
EPOCHS = 30
NUM_WORKERS = 4
SEM_EDGE_THRESHOLD = 0.5
NEG_SAMPLE_RATIO = 3
LAMBDA_SEM = 0.3

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

EVM_OPS = (
    [f"PUSH{i}" for i in range(1, 33)] +
    [f"DUP{i}" for i in range(1, 17)] +
    [f"SWAP{i}" for i in range(1, 17)] +
    [f"LOG{i}" for i in range(0, 5)] +
    [
        'STOP', 'ADD', 'MUL', 'SUB', 'DIV', 'SDIV', 'MOD', 'SMOD',
        'ADDMOD', 'MULMOD', 'EXP', 'SIGNEXTEND',
        'LT', 'GT', 'SLT', 'SGT', 'EQ', 'ISZERO', 'AND', 'OR', 'XOR', 'NOT', 'BYTE',
        'SHL', 'SHR', 'SAR', 'SHA3',
        'ADDRESS', 'BALANCE', 'ORIGIN', 'CALLER', 'CALLVALUE', 'CALLDATALOAD',
        'CALLDATASIZE', 'CALLDATACOPY', 'CODESIZE', 'CODECOPY', 'GASPRICE',
        'EXTCODESIZE', 'EXTCODECOPY', 'RETURNDATASIZE', 'RETURNDATACOPY',
        'EXTCODEHASH', 'BLOCKHASH', 'COINBASE', 'TIMESTAMP', 'NUMBER',
        'DIFFICULTY', 'GASLIMIT', 'CHAINID', 'SELFBALANCE', 'BASEFEE',
        'POP', 'MLOAD', 'MSTORE', 'MSTORE8', 'SLOAD', 'SSTORE',
        'JUMP', 'JUMPI', 'PC', 'MSIZE', 'GAS', 'JUMPDEST',
        'CREATE', 'CREATE2', 'CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL',
        'RETURN', 'REVERT', 'INVALID', 'SELFDESTRUCT',
    ]
)
VOCAB = {op: idx + 1 for idx, op in enumerate(EVM_OPS)}
VOCAB['<UNK>'] = 0
VOCAB_SIZE = len(VOCAB)


# === 2. DATASET CAP HAM ===
class FunctionLevelDataset(Dataset):
    """Moi mau = 1 HAM (1 func_key ben trong 1 file JSON hop dong).
    Doc thang tu function_level_train_index.jsonl da chuan bi san."""
    def __init__(self, index_entries):
        self.entries = index_entries
        self._file_cache = {}  # tranh doc lai cung 1 file JSON nhieu lan

    def __len__(self):
        return len(self.entries)

    def _load_file(self, fp):
        if fp not in self._file_cache:
            with open(fp) as f:
                self._file_cache[fp] = json.load(f)
        return self._file_cache[fp]

    def __getitem__(self, idx):
        entry = self.entries[idx]
        fp, func_key = entry['file'], entry['func_key']
        try:
            data = self._load_file(fp)
            g = data['intra_procedural_graphs'][func_key]

            node_list = g.get('nodes', [])
            x_indices = [VOCAB.get(n, 0) for n in node_list]
            if len(x_indices) == 0:
                return None

            edges_seq = g.get('edges_seq', []) or []
            edges_data = g.get('edges_data', []) or []
            struct_edges = edges_seq + edges_data
            edge_index_raw = (np.array(struct_edges, dtype=np.int64).T.tolist()
                               if struct_edges else [[], []])

            seed_raw = g.get('seed_sem_edges', []) or []
            seed_pairs = [[e[0], e[1]] for e in seed_raw]

            label = g.get('function_level_label')
            if label is None:
                return None  # phong ngu, khong nen xay ra vi index da loc san

            global_features_raw = [
                data.get('mean_entropy', 0.0),
                data.get('max_entropy', 0.0),
                data.get('min_entropy', 0.0),
                float(data.get('has_any_external_call', 0)),
            ]

            return {
                'x': x_indices,
                'edge_index': edge_index_raw,
                'seed_sem_pairs': seed_pairs,
                'num_nodes': len(x_indices),
                'global_features_raw': global_features_raw,
                'label_raw': int(label),
            }
        except Exception:
            return None


def custom_collate_fn(batch_samples):
    batch_samples = [s for s in batch_samples if s is not None]
    if not batch_samples:
        return None

    data_list = []
    seed_pairs_per_graph = []
    global_features_list, labels_list = [], []

    for sample in batch_samples:
        x_tensor = torch.tensor(sample['x'], dtype=torch.long)
        edge_index_tensor = torch.tensor(sample['edge_index'], dtype=torch.long)
        data_list.append(Data(x=x_tensor, edge_index=edge_index_tensor))
        seed_pairs_per_graph.append(sample['seed_sem_pairs'])
        global_features_list.append(torch.tensor(sample['global_features_raw'], dtype=torch.float))
        labels_list.append(torch.tensor(sample['label_raw'], dtype=torch.long))

    batch = Batch.from_data_list(data_list)

    return {
        'batch': batch,
        'seed_pairs_per_graph': seed_pairs_per_graph,
        'global_features': torch.stack(global_features_list, dim=0),
        'labels': torch.stack(labels_list, dim=0),
    }


from sklearn.model_selection import GroupShuffleSplit

def load_train_test_split(index_path, split_ratio=0.8, random_state=42):
    entries = []
    with open(index_path) as f:
        for line in f:
            entries.append(json.loads(line))
    print(f"[BUOC 1] Doc {len(entries)} mau tu {index_path}")

    groups = [e['file'] for e in entries]   # nhom theo HOP DONG GOC
    gss = GroupShuffleSplit(n_splits=1, test_size=(1 - split_ratio), random_state=random_state)
    train_idx, test_idx = next(gss.split(entries, groups=groups))

    train_entries = [entries[i] for i in train_idx]
    test_entries = [entries[i] for i in test_idx]

    n_train_files = len(set(e['file'] for e in train_entries))
    n_test_files = len(set(e['file'] for e in test_entries))
    print(f"Train = {len(train_entries)} ham tu {n_train_files} hop dong | "
          f"Test = {len(test_entries)} ham tu {n_test_files} hop dong")
    return train_entries, test_entries


# === 3. TOKEN-SEQUENCE TRANSFORMER (giong kien truc cu, tai su dung nguyen) ===
class TokenSequenceTransformer(nn.Module):
    def __init__(self, vocab_size, embed_dim=64, n_heads=4, n_layers=2, max_len=512):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim)
        self.pos_embedding = nn.Embedding(max_len, embed_dim)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim, nhead=n_heads, dim_feedforward=embed_dim * 2,
            batch_first=True, dropout=0.1,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=n_layers)
        self.max_len = max_len

    def forward(self, x_tokens, graph_ptr):
        ptr_list = graph_ptr.tolist()
        n_graphs = len(ptr_list) - 1
        lengths = [min(ptr_list[i + 1] - ptr_list[i], self.max_len) for i in range(n_graphs)]
        max_L = max(lengths) if lengths else 1

        padded_tokens = torch.zeros((n_graphs, max_L), dtype=torch.long, device=x_tokens.device)
        pad_mask = torch.ones((n_graphs, max_L), dtype=torch.bool, device=x_tokens.device)
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


# === 4. LEARNED SEMANTIC DEPENDENCY PREDICTOR (giu nguyen tu ban cu) ===
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


# === 5. MO HINH FUNCTION-LEVEL (rut gon - BO Stage 2) ===
class T_CFBG_FunctionLevel(nn.Module):
    def __init__(self, vocab_size, embed_dim=64, hidden_dim=128):
        super().__init__()
        self.token_transformer = TokenSequenceTransformer(vocab_size, embed_dim=embed_dim)
        self.sem_predictor = LearnedSemanticDependencyPredictor(embed_dim)

        self.gat1 = GATv2Conv(embed_dim, hidden_dim, heads=2, concat=True)
        self.gat2 = GATv2Conv(hidden_dim * 2, hidden_dim, heads=1, concat=False)

        # KHONG CON Stage 2 (macro TransformerConv) - da bo hoan toan.
        self.fc1 = Linear(hidden_dim + 4, 64)
        self.fc2 = Linear(64, 2)
        self.dropout = nn.Dropout(p=0.3)

    def forward(self, batch_dict, train_sem_predictor=True):
        batch = batch_dict['batch'].to(device)
        seed_pairs_per_graph = batch_dict['seed_pairs_per_graph']
        global_feats = batch_dict['global_features'].to(device)

        h_token = self.token_transformer(batch.x, batch.ptr.to(device))

        sem_loss_terms = []
        extra_sem_edges = []
        ptr = batch.ptr.tolist()
        for gi in range(len(ptr) - 1):
            s, e = ptr[gi], ptr[gi + 1]
            n_local = e - s
            h_local = h_token[s:e]

            if train_sem_predictor:
                pairs_idx, labels = sample_weak_labels(n_local, seed_pairs_per_graph[gi])
                if pairs_idx is not None:
                    logits = self.sem_predictor(h_local, pairs_idx.to(device))
                    sem_loss_terms.append(F.binary_cross_entropy_with_logits(logits, labels.to(device)))

            pred_edges_local = self.sem_predictor.predict_edges(h_local)
            if pred_edges_local.numel() > 0:
                extra_sem_edges.append(pred_edges_local + s)

        sem_loss = torch.stack(sem_loss_terms).mean() if sem_loss_terms else torch.tensor(0.0, device=device)

        struct_edges = batch.edge_index
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
            h = torch.zeros((h_token.size(0), 128), device=device)

        h_func = global_max_pool(h, batch.batch)   # 1 vector / ham (khong con pool len chuong trinh)
        combined = torch.cat([h_func, global_feats], dim=1)

        out = F.relu(self.fc1(combined))
        out = self.dropout(out)
        out = self.fc2(out)
        return out, sem_loss


# === 6. TRAINING LOOP ===
def main():
    print("KHOI DONG TRAINING T-CFBG FUNCTION-LEVEL (Phuong an A)...")
    print(f"VOCAB_SIZE = {VOCAB_SIZE}")

    train_entries, test_entries = load_train_test_split(TRAIN_INDEX_PATH)

    train_dataset = FunctionLevelDataset(train_entries)
    test_dataset = FunctionLevelDataset(test_entries)

    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True,
                               collate_fn=custom_collate_fn, num_workers=NUM_WORKERS, drop_last=True)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False,
                              collate_fn=custom_collate_fn, num_workers=NUM_WORKERS)

    model = T_CFBG_FunctionLevel(vocab_size=VOCAB_SIZE).to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.0003, weight_decay=1e-4)

    best_f1 = 0.0
    print(f"\n>>> BAT DAU TRAINING ({EPOCHS} EPOCHS) — loss = CE + {LAMBDA_SEM}*BCE(E_sem)...")
    for epoch in range(1, EPOCHS + 1):
        model.train()
        total_loss, correct, total_samples = 0.0, 0, 0

        pbar_train = tqdm(train_loader, desc=f"Epoch {epoch:02d}/{EPOCHS:02d} [TRAIN]")
        for batch_dict in pbar_train:
            if batch_dict is None:
                continue
            optimizer.zero_grad()
            try:
                outputs, sem_loss = model(batch_dict, train_sem_predictor=True)
                targets = batch_dict['labels'].to(device)
                loss = criterion(outputs, targets) + LAMBDA_SEM * sem_loss
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                optimizer.step()

                bs = targets.size(0)
                total_loss += loss.item() * bs
                preds = outputs.argmax(dim=1)
                correct += int((preds == targets).sum())
                total_samples += bs
                pbar_train.set_postfix({'Loss': f"{loss.item():.4f}", 'Acc': f"{correct/total_samples:.4f}"})
            except torch.cuda.OutOfMemoryError:
                torch.cuda.empty_cache()
                continue

        avg_train_loss = total_loss / total_samples if total_samples > 0 else 0
        train_acc = correct / total_samples if total_samples > 0 else 0

        model.eval()
        y_true, y_pred = [], []
        with torch.no_grad():
            for batch_dict in tqdm(test_loader, desc=f"Epoch {epoch:02d}/{EPOCHS:02d} [EVAL ]"):
                if batch_dict is None:
                    continue
                outputs, _ = model(batch_dict, train_sem_predictor=False)
                targets = batch_dict['labels'].to(device)
                preds = outputs.argmax(dim=1)
                y_true.extend(targets.cpu().numpy())
                y_pred.extend(preds.cpu().numpy())

        if len(y_true) > 0:
            test_acc = accuracy_score(y_true, y_pred)
            precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary', zero_division=0)
        else:
            test_acc, precision, recall, f1 = 0.0, 0.0, 0.0, 0.0

        print(f"Epoch {epoch:02d}: Train Loss={avg_train_loss:.4f} Acc={train_acc:.4f} | "
              f"Test Acc={test_acc:.4f} P={precision:.4f} R={recall:.4f} F1={f1:.4f}")

        if f1 > best_f1 and f1 < 1.0:
            best_f1 = f1
            torch.save(model.state_dict(), 'best_tcfbg_function_level.pth')
            print(f"[SAVE] Mo hinh tot nhat, F1={best_f1:.4f}")

        print("-" * 80)
        gc.collect()
        if torch.cuda.is_available():
            torch.cuda.empty_cache()

    print("\nHOAN TAT TRAINING FUNCTION-LEVEL.")


if __name__ == '__main__':
    main()
