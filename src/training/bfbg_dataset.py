"""Dataset + collate BFBG doc STREAMING tu data/features_graph (global_features=0).
Moi program -> list function graph (1 token/node), intra edges (cfg+seq), seed_pairs
(local idx); inter call-graph (chi so function local). Khop I/O model BFBGTransformer."""
import json, os, torch
from torch_geometric.data import Data, Batch
from src.utils.path_resolver import get_path

def load_vocab_stoi():
    itos = json.load(open(get_path('vex_vocab')))
    return {t: i for i, t in enumerate(itos)}, len(itos)

class BFBGDataset(torch.utils.data.Dataset):
    def __init__(self, records, stoi, max_funcs=150, feat_dir=None, select='first'):
        self.records = records; self.stoi = stoi; self.max_funcs = max_funcs
        self.select = select   # 'first' (mac dinh, giu nguyen) | 'apidensity' (top-K ham nhieu call/API)
        self.feat_dir = feat_dir or os.path.join(os.path.dirname(get_path('vex_vocab')), 'features_graph')
    def __len__(self): return len(self.records)
    def __getitem__(self, i):
        r = self.records[i]
        d = json.load(open(os.path.join(self.feat_dir, f"{r['sha256']}_static.json")))
        ipg = d['intra_procedural_graphs']
        items = list(ipg.values())
        if self.select == 'apidensity' and len(items) > self.max_funcs:
            dens = [sum(1 for n in (g.get('nodes') or []) if n.get('api') or n.get('mnemonic') == 'call') for g in items]
            top = sorted(range(len(items)), key=lambda k: (-dens[k], k))[:self.max_funcs]
            sel_idx = sorted(top)                                   # giu thu tu dia chi trong so da chon
        else:
            sel_idx = list(range(min(len(items), self.max_funcs)))  # 'first': y het ban cu
        funcs = [items[k] for k in sel_idx]
        remap = {old: new for new, old in enumerate(sel_idx)}       # old func idx -> new local idx
        nf = len(funcs)
        func_data = []; seed_list = []
        for g in funcs:
            nodes = g['nodes']
            x = torch.tensor([self.stoi.get(n.get('token'), 0) for n in nodes], dtype=torch.long)
            ed = (g.get('edges_cfg') or []) + (g.get('edges_seq') or [])
            ed = [(a, b) for a, b in ed if a < len(nodes) and b < len(nodes)]
            ei = torch.tensor(ed, dtype=torch.long).t().contiguous() if ed else torch.zeros((2, 0), dtype=torch.long)
            func_data.append(Data(x=x, edge_index=ei, num_nodes=len(nodes)))
            sp = [[e['src_idx'], e['dst_idx']] for e in (g.get('seed_edges') or [])
                  if e.get('src_idx') is not None and e['src_idx'] < len(nodes) and e['dst_idx'] < len(nodes)]
            seed_list.append(sp)   # list cac cap [i,j] (semantic_link_loss duyet tung cap)
        inter = (d.get('inter_procedural_call_graph') or {}).get('edges') or []
        inter = [(remap[a], remap[b]) for a, b in inter if a in remap and b in remap]
        inter_ei = torch.tensor(inter, dtype=torch.long).t().contiguous() if inter else torch.zeros((2, 0), dtype=torch.long)
        return dict(func_data=func_data, seed=seed_list, inter=inter_ei, num_functions=nf,
                    label=int(r['label']), meta=r)

def collate(samples):
    all_funcs = []; seed_pairs = []; inter_edges = []; num_functions = []; labels = []; metas = []
    for s in samples:
        if s['num_functions'] == 0:   # bo program rong
            continue
        all_funcs.extend(s['func_data']); seed_pairs.extend(s['seed'])
        inter_edges.append(s['inter']); num_functions.append(s['num_functions'])
        labels.append(s['label']); metas.append(s['meta'])
    if not all_funcs:
        return None
    intra_batch = Batch.from_data_list(all_funcs)
    return dict(intra_batch=intra_batch, seed_pairs_per_graph=seed_pairs, inter_edges=inter_edges,
                num_functions=num_functions, global_features=torch.zeros(len(num_functions), 0),
                labels=torch.tensor(labels, dtype=torch.long), metas=metas)
