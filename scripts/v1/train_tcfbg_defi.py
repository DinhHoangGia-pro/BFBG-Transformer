"""
train_tcfbg_defi.py
====================
Bản CẢI BIÊN của train_gnn.py (H_GNN_Model cho IoT malware) sang kiến trúc
T-CFBG mô tả trong Paper1.docx (Section 4.2 - 4.4):

  Stage 0 (giữ nguyên bản IoT): đọc JSON *_static.json do
           extract_evm_features.py sinh ra, lazy-load + collate theo batch.

  Stage 1 (Section 4.2 - MỚI so với IoT): Token-Sequence Transformer thay
           cho "nn.Embedding tĩnh -> GATv2" đơn thuần của bản IoT — token
           embedding đi qua TransformerEncoder (positional encoding theo
           thứ tự opcode trong block) TRƯỚC KHI đưa vào GATv2Conv trên
           E_seq/E_data (giữ cấu trúc cạnh y hệt bản IoT, không đổi).

  Stage sem (Section 4.3 - MỚI, cốt lõi nhất): Learned Semantic Dependency
           Predictor — MLP nhận cặp embedding (h_i, h_j) trong cùng đồ thị,
           dự đoán xác suất tồn tại cạnh ngữ nghĩa E_sem. Huấn luyện bằng
           weak-supervision: seed_sem_edges (do 5 luật SWC sinh ra ở bước
           extract) làm nhãn dương, cặp ngẫu nhiên loại trừ seed làm nhãn
           âm, loss = BCE (RQ2: sanity-check khôi phục đúng 5 luật gốc).

  Stage 2 (Section 4.4 - MỚI so với IoT): Macro-level Inter-function Graph
           Transformer — thay SAGEConv (bản IoT) bằng TransformerConv (PyG)
           trên đồ thị liên hàm G_inter, giữ nguyên global_max_pool nội hàm
           + global_mean_pool liên hàm như triết lý pooling gốc.

CẬP NHẬT (sau khi đối chiếu với dữ liệu thật, 10.513 file JSON từ
extract_evm_features.py - phát hiện 2 vấn đề trong bản gốc):

  1. [SỬA LỖI NGHIÊM TRỌNG] `sorted_func_keys = sorted(intra_graphs.keys())`
     dùng string-sort (alphabet) thay vì numeric-sort. Vì
     inter_procedural_call_graph.edges trong JSON được extract_evm_features.py
     xuất ra dựa trên vị trí trong func_pc_list ĐÃ SORT THEO SỐ (theo PC),
     string-sort làm chỉ số hàm bị LỆCH (vd "func_1200" đứng trước "func_70"
     theo string-sort, dù 70 < 1200 theo số) - khiến cạnh liên hàm trỏ nhầm
     hàm một cách ÂM THẦM (không crash, chỉ học sai cấu trúc đồ thị macro).
     Đã sửa: sort theo phần số trích từ key.

  2. [MỞ RỘNG VOCAB] EVM_OPS bản gốc thiếu EXP (chính Bảng 1 của bài dùng
     EXP làm 1 trong 3 opcode nguồn cho luật Integer Overflow!), thiếu SHA3
     (rất phổ biến), và nhiều biến thể PUSH/DUP/SWAP - mở rộng đầy đủ hơn
     để giảm tỷ lệ rơi vào <UNK>.

YÊU CẦU: pip install torch torch_geometric scikit-learn tqdm numpy
"""

import os
import json
import glob
import math
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.nn import Linear
from torch_geometric.nn import GATv2Conv, TransformerConv, global_max_pool, global_mean_pool
from torch_geometric.data import Data, Batch
from torch.utils.data import DataLoader, Dataset
from tqdm import tqdm
import numpy as np
import gc

from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"

# === 1. CẤU HÌNH HỆ THỐNG ===
HIN_DIR_DEFI = os.environ.get('HIN_DIR_DEFI', './hin_defi_static')
DATA_ROOT = os.path.join(HIN_DIR_DEFI, 'data', 'features_graph')

BATCH_SIZE = 4
MAX_FUNCS_PER_PROG = 150
EPOCHS = 20
NUM_WORKERS = 4
SEM_EDGE_THRESHOLD = 0.5
NEG_SAMPLE_RATIO = 3
LAMBDA_SEM = 0.3

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

# ĐÃ MỞ RỘNG: thêm EXP (dùng trong Bảng 1 - Integer Overflow), SHA3, thêm
# đầy đủ PUSH1-32/DUP1-16/SWAP1-16, GAS/CREATE/CODECOPY và các opcode phổ
# biến khác trong bytecode EVM thực tế, giảm tỷ lệ rơi vào <UNK>.
EVM_OPS = (
    [f"PUSH{i}" for i in range(1, 33)] +
    [f"DUP{i}" for i in range(1, 17)] +
    [f"SWAP{i}" for i in range(1, 17)] +
    [f"LOG{i}" for i in range(0, 5)] +
    [
        'STOP', 'ADD', 'MUL', 'SUB', 'DIV', 'SDIV', 'MOD', 'SMOD',
        'ADDMOD', 'MULMOD', 'EXP', 'SIGNEXTEND',
        'LT', 'GT', 'SLT', 'SGT', 'EQ', 'ISZERO', 'AND', 'OR', 'XOR', 'NOT', 'BYTE',
        'SHL', 'SHR', 'SAR',
        'SHA3',
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

RULE_NAMES = [
    "reentrancy_call_before_sstore", "unchecked_external_call_return",
    "integer_overflow_arith_to_storage", "tx_origin_authorization",
    "timestamp_dependence",
]
RULE_TO_IDX = {r: i for i, r in enumerate(RULE_NAMES)}


def _func_key_sort_key(fkey: str) -> int:
    """SUA LOI: trich phan so tu key kieu 'func_1234' -> 1234 (int), dung
    de sort DUNG THEO SO (khop voi thu tu func_pc_list.index(...) da sort
    theo PC ma extract_evm_features.py dung khi sinh inter_procedural_call
    _graph.edges). Sort chuoi (sorted(keys())) se cho ra thu tu SAI."""
    try:
        return int(fkey.split('_')[-1])
    except (ValueError, IndexError):
        return 0


# === 2. DATASET THỜI GIAN THỰC ===
class TCFBGLazyDataset(Dataset):
    def __init__(self, file_paths):
        self.file_paths = file_paths

    def __len__(self):
        return len(self.file_paths)

    def __getitem__(self, idx):
        fpath = self.file_paths[idx]
        try:
            with open(fpath, 'r') as f:
                data = json.load(f)

            label = data.get('label', 0)
            intra_graphs = data.get('intra_procedural_graphs', {})
            if not intra_graphs:
                return None

            # SUA LOI QUAN TRONG: sort THEO SO (khop voi thu tu PC ma
            # extract_evm_features.py da dung), KHONG sort theo chuoi.
            sorted_func_keys = sorted(intra_graphs.keys(), key=_func_key_sort_key)
            if len(sorted_func_keys) > MAX_FUNCS_PER_PROG:
                keys_with_evidence = [k for k in sorted_func_keys
                                       if len(intra_graphs[k].get("seed_sem_edges", [])) > 0]
                keys_without_evidence = [k for k in sorted_func_keys if k not in set(keys_with_evidence)]
                if len(keys_with_evidence) >= MAX_FUNCS_PER_PROG:
                    sorted_func_keys = keys_with_evidence[:MAX_FUNCS_PER_PROG]
                else:
                    remaining_slots = MAX_FUNCS_PER_PROG - len(keys_with_evidence)
                    sorted_func_keys = keys_with_evidence + keys_without_evidence[:remaining_slots]
                    sorted_func_keys = sorted(sorted_func_keys, key=_func_key_sort_key)

            intra_graphs_raw = []
            for fkey in sorted_func_keys:
                f_data = intra_graphs[fkey]
                node_list = f_data.get('nodes', [])
                x_indices = [VOCAB.get(n, 0) for n in node_list]
                if len(x_indices) == 0:
                    x_indices = [0]

                edges_seq = f_data.get('edges_seq', []) or []
                edges_data = f_data.get('edges_data', []) or []
                struct_edges = edges_seq + edges_data
                edge_index_raw = (np.array(struct_edges, dtype=np.int64).T.tolist()
                                   if struct_edges else [[], []])

                seed_raw = f_data.get('seed_sem_edges', []) or []
                seed_pairs = [[e[0], e[1]] for e in seed_raw]

                intra_graphs_raw.append({
                    'x': x_indices,
                    'edge_index': edge_index_raw,
                    'seed_sem_pairs': seed_pairs,
                    'num_nodes': len(x_indices),
                })

            if len(intra_graphs_raw) == 0:
                return None

            inter_cg = data.get('inter_procedural_call_graph', {}) or {}
            raw_inter_edges = inter_cg.get('edges', []) or []
            # Bay gio sorted_func_keys DA DUNG THU TU (khop func_pc_list ben
            # extract_evm_features.py), nen index u,v trong inter_edges tuong
            # ung dung voi vi tri trong sorted_func_keys.
            valid_inter_edges = [[u, v] for u, v in raw_inter_edges
                                  if u < len(sorted_func_keys) and v < len(sorted_func_keys)]
            inter_edge_index_raw = (np.array(valid_inter_edges, dtype=np.int64).T.tolist()
                                     if valid_inter_edges else [[], []])

            global_features_raw = [
                data.get('mean_entropy', 0.0),
                data.get('max_entropy', 0.0),
                data.get('min_entropy', 0.0),
                float(data.get('has_any_external_call', 0)),
            ]

            return {
                'intra_graphs_raw': intra_graphs_raw,
                'inter_edge_index_raw': inter_edge_index_raw,
                'num_functions': len(sorted_func_keys),
                'global_features_raw': global_features_raw,
                'label_raw': int(label),
            }
        except Exception:
            return None


def custom_collate_fn(batch_samples):
    batch_samples = [s for s in batch_samples if s is not None]
    if not batch_samples:
        return None

    flat_intra_graphs = []
    seed_pairs_per_graph = []
    inter_edges_list, num_functions_list = [], []
    global_features_list, labels_list = [], []

    for sample in batch_samples:
        for g_raw in sample['intra_graphs_raw']:
            x_tensor = torch.tensor(g_raw['x'], dtype=torch.long)
            edge_index_tensor = torch.tensor(g_raw['edge_index'], dtype=torch.long)
            flat_intra_graphs.append(Data(x=x_tensor, edge_index=edge_index_tensor))
            seed_pairs_per_graph.append(g_raw['seed_sem_pairs'])

        inter_edges_list.append(torch.tensor(sample['inter_edge_index_raw'], dtype=torch.long))
        num_functions_list.append(sample['num_functions'])
        global_features_list.append(torch.tensor(sample['global_features_raw'], dtype=torch.float))
        labels_list.append(torch.tensor(sample['label_raw'], dtype=torch.long))

    compiled_intra_batch = Batch.from_data_list(flat_intra_graphs)

    return {
        'intra_batch': compiled_intra_batch,
        'seed_pairs_per_graph': seed_pairs_per_graph,
        'inter_edges': inter_edges_list,
        'num_functions': num_functions_list,
        'global_features': torch.stack(global_features_list, dim=0),
        'labels': torch.stack(labels_list, dim=0),
    }


# === 3. THU THẬP & CÂN BẰNG FILE ===
def get_balanced_file_paths(root_dir, split_ratio=0.8, random_state=42):
    raw_files = glob.glob(os.path.join(root_dir, '*.json'))
    print(f"[BƯỚC 1] Quét {len(raw_files)} tệp đặc trưng JSON trong {root_dir}")
    if len(raw_files) == 0:
        raise RuntimeError(f"Không tìm thấy file .json nào trong {root_dir} - "
                            f"kiểm tra lại biến môi trường HIN_DIR_DEFI va da chay "
                            f"run_extract_evm_xargs.sh chua.")

    benign_files, vuln_files = [], []
    for fpath in tqdm(raw_files, desc="Phân loại nhãn"):
        try:
            with open(fpath, 'r') as f:
                for line in f:
                    if '"label"' in line:
                        label = int(''.join(c for c in line if c.isdigit()))
                        (benign_files if label == 0 else vuln_files).append(fpath)
                        break
        except Exception:
            continue

    print(f"Benign = {len(benign_files)} | Vulnerable = {len(vuln_files)}")
    max_balanced = min(len(benign_files), len(vuln_files))
    if max_balanced == 0:
        raise RuntimeError("Không đủ dữ liệu cho cả 2 lớp — kiểm tra lại DATA_ROOT.")

    np.random.seed(random_state)
    chosen_benign = np.random.choice(benign_files, size=max_balanced, replace=False).tolist()
    chosen_vuln = np.random.choice(vuln_files, size=max_balanced, replace=False).tolist()
    final_files = chosen_benign + chosen_vuln
    np.random.shuffle(final_files)

    train_files, test_files = train_test_split(final_files, test_size=(1 - split_ratio), random_state=random_state)
    print(f"Train = {len(train_files)} | Test = {len(test_files)}")
    return train_files, test_files


# === 4. STAGE 1: TOKEN-SEQUENCE TRANSFORMER (Section 4.2) ===
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
        """DA TOI UU: thay vi lap Python goi self.encoder() RIENG LE cho
        tung ham (co the toi 200 lan/forward voi batch_size=4 x
        MAX_FUNCS_PER_PROG=50 - nguyen nhan chinh gay cham tren GPU do
        overhead khoi dong kernel giua cac lenh goi nho le), gop TOAN BO
        cac ham trong batch thanh 1 tensor co PADDING, chay dung 1 lan goi
        self.encoder() duy nhat cho ca batch."""
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
        h = self.encoder(h, src_key_padding_mask=pad_mask)   # <-- CHI 1 LAN GOI DUY NHAT

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


# === 5. STAGE SEM: LEARNED SEMANTIC DEPENDENCY PREDICTOR (Section 4.3) ===
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


# === 6. KIẾN TRÚC T-CFBG ĐẦY ĐỦ (Stage1 + Stage sem + Stage2) ===
class T_CFBG_Model(nn.Module):
    def __init__(self, vocab_size, embed_dim=64, hidden_dim=128):
        super().__init__()
        self.token_transformer = TokenSequenceTransformer(vocab_size, embed_dim=embed_dim)
        self.sem_predictor = LearnedSemanticDependencyPredictor(embed_dim)

        self.gat1 = GATv2Conv(embed_dim, hidden_dim, heads=2, concat=True)
        self.gat2 = GATv2Conv(hidden_dim * 2, hidden_dim, heads=1, concat=False)

        self.macro1 = TransformerConv(hidden_dim, hidden_dim, heads=2, concat=True, dropout=0.1)
        self.macro2 = TransformerConv(hidden_dim * 2, hidden_dim, heads=1, concat=False, dropout=0.1)

        self.fc1 = Linear(hidden_dim + 4, 64)
        self.fc2 = Linear(64, 2)
        self.dropout = nn.Dropout(p=0.3)

    def forward(self, batch_dict, train_sem_predictor=True):
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
            h = torch.zeros((h_token.size(0), 128), device=device)

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


# === 7. PIPELINE HUẤN LUYỆN ===
def main():
    print("KHỞI ĐỘNG HUẤN LUYỆN T-CFBG TRÊN TOÀN BỘ DATA_ROOT...")
    print(f"DATA_ROOT = {DATA_ROOT}")
    print(f"VOCAB_SIZE = {VOCAB_SIZE} (đã mở rộng, bao gồm EXP/SHA3/PUSH1-32/DUP1-16/SWAP1-16)")

    train_files, test_files = get_balanced_file_paths(DATA_ROOT, split_ratio=0.8)

    train_dataset = TCFBGLazyDataset(train_files)
    test_dataset = TCFBGLazyDataset(test_files)

    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True,
                               collate_fn=custom_collate_fn, num_workers=NUM_WORKERS, drop_last=True)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False,
                              collate_fn=custom_collate_fn, num_workers=NUM_WORKERS)

    model = T_CFBG_Model(vocab_size=VOCAB_SIZE).to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.0002, weight_decay=1e-4)

    best_f1 = 0.0
    print(f"\n>>> BẮT ĐẦU TRAINING ({EPOCHS} EPOCHS) — loss = CE + {LAMBDA_SEM}*BCE(E_sem weak-sup)...")
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

                pbar_train.set_postfix({'Loss': f"{loss.item():.4f}",
                                         'SemLoss': f"{sem_loss.item():.4f}",
                                         'Acc': f"{correct/total_samples:.4f}"})
            except torch.cuda.OutOfMemoryError:
                torch.cuda.empty_cache()
                continue

        avg_train_loss = total_loss / total_samples if total_samples > 0 else 0
        train_acc = correct / total_samples if total_samples > 0 else 0

        model.eval()
        y_true, y_pred = [], []
        pbar_test = tqdm(test_loader, desc=f"Epoch {epoch:02d}/{EPOCHS:02d} [EVAL ]")
        with torch.no_grad():
            for batch_dict in pbar_test:
                if batch_dict is None:
                    continue
                try:
                    outputs, _ = model(batch_dict, train_sem_predictor=False)
                    targets = batch_dict['labels'].to(device)
                    preds = outputs.argmax(dim=1)
                    y_true.extend(targets.cpu().numpy())
                    y_pred.extend(preds.cpu().numpy())
                except torch.cuda.OutOfMemoryError:
                    torch.cuda.empty_cache()
                    continue

        if len(y_true) > 0:
            test_acc = accuracy_score(y_true, y_pred)
            precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary', zero_division=0)
        else:
            test_acc, precision, recall, f1 = 0.0, 0.0, 0.0, 0.0

        print(f"Epoch {epoch:02d}: Train Loss={avg_train_loss:.4f} Acc={train_acc:.4f} | "
              f"Test Acc={test_acc:.4f} P={precision:.4f} R={recall:.4f} F1={f1:.4f}")

        if f1 > best_f1 and f1 < 1.0:
            best_f1 = f1
            torch.save(model.state_dict(), 'best_tcfbg_defi.pth')
            print(f"[SAVE] Mô hình tốt nhất, F1={best_f1:.4f}")

        print("-" * 80)
        gc.collect()
        if torch.cuda.is_available():
            torch.cuda.empty_cache()

    print("\nHOÀN TẤT HUẤN LUYỆN T-CFBG.")


if __name__ == '__main__':
    main()
