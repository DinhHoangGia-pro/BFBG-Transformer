"""
bfbg_builder.py
===============
Dung BFBG (Binary Function Block Graph) cho 1 file PE va ghi ra JSON:

  1. Lift: angr.Project + CFGFast -> lenh may + VEX IR
     (src/disassembly/pe_lifter.py - cung bo cong cu ban IoT/ELF goc).
  2. Resolve API call: voi moi call site cua tung ham, lay ham dich tu IAT
     (SimProcedure hoac thunk `jmp [IAT]`), CHUAN HOA TEN bang cach bo tien
     to DLL ("kernel32.dll!OpenProcess" -> "OpenProcess") roi moi dung
     ResolvedCall. Day la lop DUY NHAT chiu trach nhiem chuan hoa ten -
     src/semantic/seed_rules_attck.py gia dinh ten da chuan hoa.
  3. Moi ham: goi generate_seed_edges() VA generate_node_indicators(),
     window_size doc tu configs/model.yaml -> semantic.window_size.
  4. Ghi JSON <sha256>_static.json (khong indent) vao paths.features_dir
     (configs/config.yaml). Token VEX luu dang id tham chieu MOT bang vocab
     dung chung (paths.vex_vocab) - vocab chi THEM token moi, id cu khong
     doi, nen JSON ghi truoc van tra dung. An toan khi chay song song nhieu
     tien trinh tren cung 1 may (update_shared_vocab khoa file).
  5. Moi ham: func["boundary_flags"] (SPREAD/FAR_UNLINK/OVERLAP, rong neu
     binh thuong) tu src/bfbg/boundary_flags.py - ham angr co the gop nham.

Node = 1 lenh may (khop TokenSequenceTransformer: 1 token / node).
node_id = dia chi lenh dang hex ("0x401000") - duy nhat trong ca binary.
ResolvedCall.position = thu tu cua loi goi API trong ham (0, 1, 2, ...
theo dia chi call site), KHONG phai chi so lenh - window_size dem theo so
loi goi API, dung nhu thiet ke cua seed_rules_attck.py.

Schema JSON (cac khoa cap ham giu khung cu de experiments/qa/ doc duoc):
  sha256, path, file_size, arch, entry, label, vex_vocab_size,
  mean_entropy/max_entropy/min_entropy, section_entropies, num_imports,
  num_api_calls, num_functions, structural_indicators{...},
  intra_procedural_graphs: { "func_<addr>": {
      addr, name,
      nodes:   [{node_id, idx, addr, block, token, mnemonic, api}],
      edges_seq: [[i, i+1]]  (lenh lien tiep trong cung block),
      edges_cfg: [[i, j]]    (lenh cuoi block -> lenh dau block ke tiep),
      blocks:  [{addr, size, first_idx, num_insns, jumpkind, vex_ids}],
      api_calls:       [{node_id, idx, api, position}],
      boundary_flags:  ["OVERLAP", ...]  (rong = khong bi gan co),
      seed_edges:      [{src_node_id, dst_node_id, src_idx, dst_idx, technique_id, rule_name, confidence}],
      node_indicators: [{node_id, idx, technique_id, rule_name}] } },
  inter_procedural_call_graph: {edges, num_edges},
  cross_function_seed_edges: [{src_func, src_node_id, src_idx, dst_func, dst_node_id, dst_idx,
                               technique_id, rule_name, confidence="cross_function_1hop"}]
      (khop chain LIEN HAM 1-hop qua call graph - TACH RIENG, KHONG gop vao
       seed_edges cua tung ham; xem docs/LESSONS_LEARNED.md muc 2)

Chay:  python -m src.bfbg.bfbg_builder <file.exe> [...] [--label 0|1] [--out-dir DIR] [--vex-vocab FILE]
"""

import argparse
import json
import logging
import os

import pefile

from src.disassembly.callgraph_extractor import extract_callgraph, resolve_apis
from src.disassembly.pe_lifter import lift_pe
from src.bfbg.boundary_flags import analyze_sample
from src.bfbg.boundary_flags import default_params as default_boundary_params
from src.disassembly.vex_tokenizer import instruction_token, update_shared_vocab
from src.semantic.seed_rules_attck import (
    ResolvedCall,
    compute_structural_indicators,
    generate_cross_function_seed_edges,
    generate_node_indicators,
    generate_seed_edges,
)
from src.utils.path_resolver import get_path, load_config

# So ham import toi thieu cua mot PE "binh thuong" - it hon coi la bat
# thuong bang import (dau hieu pack). CHUA kiem chung tren du lieu that,
# giong nguong entropy 7.2 trong seed_rules_attck.py.
MIN_NORMAL_IMPORTS = 10


def normalize_api_name(raw):
    """'kernel32.dll!OpenProcess' -> 'OpenProcess'."""
    return raw.rsplit('!', 1)[-1].strip()


def section_stats(path):
    """(entropy tung section, so ham import) doc bang pefile."""
    pe = pefile.PE(path, fast_load=True)
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        entropies = [s.get_entropy() for s in pe.sections]
        num_imports = sum(len(e.imports) for e in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []))
    finally:
        pe.close()
    return entropies, num_imports


def resolve_call_sites(lifted, lfunc):
    """{dia chi lenh call: [ten API da chuan hoa]} cho 1 ham."""
    functions = lifted.cfg.kb.functions
    callgraph = lifted.cfg.kb.callgraph
    func = functions[lfunc.addr]
    last_insn_of_block = {b.addr: b.instructions[-1].addr for b in lfunc.blocks if b.instructions}

    resolved = {}
    for site in func.get_call_sites():
        target = func.get_call_target(site)
        if target is None or target not in functions or site not in last_insn_of_block:
            continue
        apis = [normalize_api_name(a) for a in resolve_apis(functions[target], functions, callgraph)]
        if apis:
            resolved[last_insn_of_block[site]] = apis
    return resolved


def build_function_graph(lifted, lfunc, window_size):
    nodes, edges_seq, blocks_out = [], [], []
    first_idx_of_block, last_idx_of_block = {}, {}
    for block in lfunc.blocks:
        first_idx_of_block[block.addr] = len(nodes)
        for k, insn in enumerate(block.instructions):
            idx = len(nodes)
            if k > 0:
                edges_seq.append([idx - 1, idx])
            nodes.append({
                'node_id': f"{insn.addr:#x}", 'idx': idx, 'addr': insn.addr, 'block': block.addr,
                'token': instruction_token(insn.mnemonic, insn.operand_types),
                'mnemonic': insn.mnemonic, 'api': None,
            })
        last_idx_of_block[block.addr] = len(nodes) - 1
        blocks_out.append({'addr': block.addr, 'size': block.size, 'first_idx': first_idx_of_block[block.addr],
                           'num_insns': len(block.instructions), 'jumpkind': block.jumpkind,
                           'vex_tokens': list(block.vex_tokens)})   # doi sang vex_ids trong build_bfbg

    edges_cfg = []
    for u, v in lfunc.edges:
        src_b, dst_b = lfunc.blocks[u], lfunc.blocks[v]
        if src_b.instructions and dst_b.instructions:
            edges_cfg.append([last_idx_of_block[src_b.addr], first_idx_of_block[dst_b.addr]])

    idx_of_node_id = {n['node_id']: n['idx'] for n in nodes}
    calls = []
    for addr, apis in sorted(resolve_call_sites(lifted, lfunc).items()):
        node = nodes[idx_of_node_id[f"{addr:#x}"]]
        node['api'] = apis[0] if len(apis) == 1 else apis
        for api in apis:
            calls.append(ResolvedCall(node_id=node['node_id'], api_name=api, position=len(calls)))

    seed_edges = generate_seed_edges(calls, window_size=window_size)
    node_indicators = generate_node_indicators(calls, window_size=window_size)

    return {
        'addr': lfunc.addr,
        'name': lfunc.name,
        'nodes': nodes,
        'edges_seq': edges_seq,
        'edges_cfg': edges_cfg,
        'blocks': blocks_out,
        'api_calls': [{'node_id': c.node_id, 'idx': idx_of_node_id[c.node_id], 'api': c.api_name,
                       'position': c.position} for c in calls],
        'seed_edges': [{'src_node_id': e.src_node_id, 'dst_node_id': e.dst_node_id,
                        'src_idx': idx_of_node_id[e.src_node_id], 'dst_idx': idx_of_node_id[e.dst_node_id],
                        'technique_id': e.technique_id, 'rule_name': e.rule_name,
                        'confidence': e.confidence} for e in seed_edges],
        'node_indicators': [{'node_id': i.node_id, 'idx': idx_of_node_id[i.node_id],
                             'technique_id': i.technique_id, 'rule_name': i.rule_name}
                            for i in node_indicators],
    }


def encode_vex_tokens(intra, vocab_path):
    """Doi blocks[].vex_tokens -> vex_ids theo vocab dung chung (cap id duoi
    khoa); tra ve kich thuoc vocab tai thoi diem cap id."""
    tokens = {t for g in intra.values() for b in g['blocks'] for t in b['vex_tokens']}
    vocab = update_shared_vocab(vocab_path, sorted(tokens))
    for g in intra.values():
        for b in g['blocks']:
            b['vex_ids'] = vocab.encode(b.pop('vex_tokens'))
    return len(vocab)


def build_cross_function_edges(intra, callgraph, window_size):
    """Goi generate_cross_function_seed_edges() SAU generate_seed_edges() (da chay
    trong build_function_graph), tren API-call da chuan hoa cua tung ham va
    canh goi truc tiep cua call graph."""
    keys = list(intra)
    assert [intra[k]['addr'] for k in keys] == callgraph.func_addrs, "thu tu ham lech call graph"
    calls_by_function = {k: [ResolvedCall(node_id=c['node_id'], api_name=c['api'], position=c['position'])
                             for c in intra[k]['api_calls']] for k in keys}
    edges = [(keys[u], keys[v]) for u, v in callgraph.edges]
    owner = {n['node_id']: (k, n['idx']) for k in keys for n in intra[k]['nodes']}
    out = []
    for e in generate_cross_function_seed_edges(calls_by_function, edges, window_size=window_size):
        (src_func, src_idx), (dst_func, dst_idx) = owner[e.src_node_id], owner[e.dst_node_id]
        out.append({'src_func': src_func, 'src_node_id': e.src_node_id, 'src_idx': src_idx,
                    'dst_func': dst_func, 'dst_node_id': e.dst_node_id, 'dst_idx': dst_idx,
                    'technique_id': e.technique_id, 'rule_name': e.rule_name, 'confidence': e.confidence})
    return out


def build_bfbg(path, vex_vocab_path, label=None, window_size=None, boundary_params=None):
    """Dung toan bo BFBG cho 1 file PE, tra ve dict san sang ghi JSON."""
    if window_size is None:
        window_size = load_config('model')['semantic']['window_size']

    lifted = lift_pe(path, lift_vex=True)
    callgraph = extract_callgraph(lifted)
    entropies, num_imports = section_stats(path)
    structural = compute_structural_indicators(entropies, import_table_anomaly=num_imports < MIN_NORMAL_IMPORTS)

    intra = {f"func_{f.addr}": build_function_graph(lifted, f, window_size) for f in lifted.functions}
    cross_edges = build_cross_function_edges(intra, callgraph, window_size)
    boundary_params = boundary_params or default_boundary_params()
    for key, result in analyze_sample(intra, boundary_params).items():
        intra[key]['boundary_flags'] = result['flags'] if result else []
    vex_vocab_size = encode_vex_tokens(intra, vex_vocab_path)

    return {
        'sha256': lifted.sha256,
        'path': lifted.path,
        'file_size': lifted.file_size,
        'arch': lifted.arch,
        'entry': lifted.entry,
        'label': label,
        'mean_entropy': sum(entropies) / len(entropies) if entropies else 0.0,
        'max_entropy': max(entropies, default=0.0),
        'min_entropy': min(entropies, default=0.0),
        'section_entropies': entropies,
        'num_imports': num_imports,
        # Dem theo CALL SITE (moi lenh call toi API tinh 1 lan) - khop api_calls/node.api tung ham. KHAC
        # CallGraph.num_api_calls (callgraph_extractor.py, dem theo canh call-graph) - khac muc dich, khong phai bug.
        'num_api_calls': sum(len(g['api_calls']) for g in intra.values()),
        'num_functions': len(intra),
        'structural_indicators': {
            'max_section_entropy': structural.max_section_entropy,
            'has_import_table_anomaly': structural.has_import_table_anomaly,
            'is_likely_packed': structural.is_likely_packed,
        },
        'window_size': window_size,
        'vex_vocab_size': vex_vocab_size,
        'boundary_params': boundary_params,
        'intra_procedural_graphs': intra,
        'inter_procedural_call_graph': {
            'edges': [list(e) for e in callgraph.edges],
            'num_edges': len(callgraph.edges),
        },
        'cross_function_seed_edges': cross_edges,
    }


def write_bfbg(bfbg, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{bfbg['sha256']}_static.json")
    with open(out_path, 'w') as f:
        json.dump(bfbg, f, separators=(',', ':'))
    return out_path


def main():
    parser = argparse.ArgumentParser(description="Dung BFBG JSON cho file PE")
    parser.add_argument('paths', nargs='+')
    parser.add_argument('--label', type=int, choices=[0, 1], default=None,
                        help="Nhan gan vao JSON (mac dinh null - nhan VT gan o buoc sau)")
    parser.add_argument('--out-dir', default=None, help="Mac dinh: paths.features_dir trong configs/config.yaml")
    parser.add_argument('--vex-vocab', default=None, help="Mac dinh: paths.vex_vocab trong configs/config.yaml")
    args = parser.parse_args()
    for name in ('angr', 'cle', 'pyvex'):
        logging.getLogger(name).setLevel(logging.ERROR)

    out_dir = args.out_dir or get_path('features_dir')
    vocab_path = args.vex_vocab or get_path('vex_vocab')
    for path in args.paths:
        bfbg = build_bfbg(path, vocab_path, label=args.label)
        out_path = write_bfbg(bfbg, out_dir)
        n_edges = sum(len(g['seed_edges']) for g in bfbg['intra_procedural_graphs'].values())
        n_ind = sum(len(g['node_indicators']) for g in bfbg['intra_procedural_graphs'].values())
        print(f"{os.path.basename(path)} -> {out_path}  (ham={bfbg['num_functions']}, "
              f"API-call={bfbg['num_api_calls']}, seed_edges={n_edges}, node_indicators={n_ind})")


if __name__ == '__main__':
    main()
