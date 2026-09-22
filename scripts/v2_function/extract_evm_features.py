"""
extract_evm_features.py  (PHIEN BAN FUNCTION-LEVEL)
========================
CAP NHAT LON: tich hop Giai doan 1+2 da xay dung va kiem chung rieng
(srcmap-runtime parsing, manifest nhan cap ham tu SmartBugs-Curated +
DAppSCAN) vao thang pipeline trich xuat chinh.

Thay doi cot loi so voi ban contract-level truoc do:
  - Compile bang --combined-json bin-runtime,srcmap-runtime (thay vi chi
    --bin-runtime) de co du lieu khop source<->bytecode.
  - Cat bo metadata CBOR truoc khi disassemble (da xac nhan bang thuc
    nghiem: pyevmasm bien metadata thanh opcode gia neu khong cat).
  - Moi node (opcode) trong CFBG duoc gan them PC that (truoc day chi co
    ten opcode, khong co PC) - can thiet de doi chieu voi pc_to_line.
  - Moi "ham" CFBG (func_<PC>, heuristic cu dua tren JUMPDEST) duoc gan
    THEM nhan cap ham tong hop tu cac opcode ben trong no, dua theo
    manifest nguoi audit that (SmartBugs-Curated + DAppSCAN) - KHONG con
    dung nhan Slither tu dong nua cho huong nay.
  - Nhan cap hop dong (top-level "label") gio la GIA TRI SUY RA
    (contract co it nhat 1 ham vulnerable hay khong), chi de tham khao -
    tin hieu train chinh nam o "function_level_label" cua tung node/ham.

YEU CAU CAI DAT: pip install pyevmasm solc-select
"""

import sys
import os
import re
import json
import math
import hashlib
import functools
import subprocess
import traceback
from collections import Counter

try:
    from pyevmasm import disassemble_all, Instruction
except ImportError as e:
    sys.stderr.write(f"[ERROR] Missing pyevmasm: {e}. pip install pyevmasm\n")
    sys.exit(1)

print = functools.partial(print, flush=True)

PRAGMA_RE = re.compile(r'pragma\s+solidity\s*[^;]*?([0-9]+\.[0-9]+\.[0-9]+)')


def log_error(msg):
    sys.stderr.write(f"[ERROR] {msg}\n")
    sys.stderr.flush()


def log_info(msg):
    sys.stderr.write(f"[INFO] {msg}\n")
    sys.stderr.flush()


# =============================================================================
# HELPER: HASH, ENTROPY
# =============================================================================
def get_bytecode_hash(bytecode_hex: str) -> str:
    return hashlib.sha256(bytecode_hex.encode()).hexdigest()


def get_entropy_manual(raw_bytes: bytes):
    if not raw_bytes:
        return 0.0, 0.0, 0.0, []
    total_len = len(raw_bytes)
    counter = Counter(raw_bytes)
    entropy = 0.0
    for count in counter.values():
        p = count / total_len
        entropy -= p * math.log2(p)

    chunk_size = 64
    seq = []
    for i in range(0, total_len, chunk_size):
        chunk = raw_bytes[i:i + chunk_size]
        c = Counter(chunk)
        e = 0.0
        for cnt in c.values():
            p = cnt / len(chunk)
            e -= p * math.log2(p)
        seq.append(round(e, 4))

    if seq:
        return round(entropy, 4), max(seq), min(seq), seq
    return round(entropy, 4), round(entropy, 4), round(entropy, 4), []


# =============================================================================
# METADATA STRIPPING (SUA LOI: pyevmasm bien metadata CBOR cuoi bytecode
# thanh opcode gia neu khong cat truoc)
# =============================================================================
def strip_metadata(bytecode_hex: str) -> str:
    """Cat bo metadata CBOR o cuoi runtime bytecode - Solidity ghi 2 BYTE
    CUOI CUNG la do dai (big-endian) cua doan metadata CBOR ngay truoc do."""
    if bytecode_hex.startswith("0x"):
        bytecode_hex = bytecode_hex[2:]
    raw = bytes.fromhex(bytecode_hex)
    if len(raw) < 2:
        return bytecode_hex
    metadata_len = int.from_bytes(raw[-2:], byteorder='big')
    if metadata_len == 0 or metadata_len >= len(raw):
        return bytecode_hex
    return raw[:-(metadata_len + 2)].hex()


# =============================================================================
# SRCMAP PARSING (Giai doan 2 - da kiem chung bang thuc nghiem)
# =============================================================================
def parse_srcmap(srcmap_str):
    """Tra ve list (start, length, file_idx, jump_type) - 1 phan tu/opcode,
    xu ly dung quy tac KE THUA TUNG TRUONG cua dinh dang srcmap."""
    entries = srcmap_str.split(';')
    parsed = []
    prev_s, prev_l, prev_f, prev_j = None, None, None, None
    for entry in entries:
        parts = entry.split(':') if entry else []
        s = int(parts[0]) if len(parts) > 0 and parts[0] != '' else prev_s
        l = int(parts[1]) if len(parts) > 1 and parts[1] != '' else prev_l
        f = int(parts[2]) if len(parts) > 2 and parts[2] != '' else prev_f
        j = parts[3] if len(parts) > 3 and parts[3] != '' else prev_j
        parsed.append((s, l, f, j))
        prev_s, prev_l, prev_f, prev_j = s, l, f, j
    return parsed


def offset_to_line(offset, source_text):
    if offset is None:
        return None
    return source_text[:offset].count('\n') + 1


def build_pc_to_line_map(bytecode_hex_stripped, srcmap_str, source_text, instructions):
    """Khop instructions (tu pyevmasm, DA STRIP metadata) voi srcmap_entries
    (tu solc) THEO THU TU. Chap nhan lech <=1 (hanh vi da biet cua dinh
    dang srcmap), canh bao neu lech lon hon."""
    srcmap_entries = parse_srcmap(srcmap_str)
    diff = abs(len(instructions) - len(srcmap_entries))
    if diff > 1:
        log_info(f"[CANH BAO] Lech opcode bat thuong: pyevmasm={len(instructions)}, "
                 f"srcmap={len(srcmap_entries)}, chenh={diff}")

    pc_to_line = {}
    limit = min(len(instructions), len(srcmap_entries))
    for i in range(limit):
        s, l, fidx, j = srcmap_entries[i]
        pc_to_line[instructions[i].pc] = offset_to_line(s, source_text)
    return pc_to_line


def map_pc_to_function(pc_to_line, functions_manifest):
    """Noi pc_to_line voi manifest cap ham (loc san cho DUNG 1 hop dong).
    Tra ve dict PC -> {"function_name","label","vuln_type"}."""
    pc_to_func_label = {}
    for pc, line in pc_to_line.items():
        if line is None:
            continue
        for func in functions_manifest:
            if func["start_line"] <= line <= func["end_line"]:
                pc_to_func_label[pc] = {
                    "function_name": func["function_name"],
                    "label": func["label"],
                    "vuln_type": func.get("vuln_type"),
                }
                break
    return pc_to_func_label


# =============================================================================
# MANIFEST LOADING (Giai doan 1)
# =============================================================================
def load_matching_manifest(sol_path, manifest_paths):
    """Doc TOAN BO cac file manifest, chi giu lai entry co contract_file la
    HAU TO (suffix) cua sol_path da chuan hoa - hoat dong dung cho ca
    SmartBugs-Curated (contract_file = basename) lan DAppSCAN (contract_file
    = duong dan tuong doi day du, tranh nham lan basename trung nhau)."""
    sol_norm = sol_path.replace("\\", "/")
    matches = []
    for mpath in manifest_paths:
        if not os.path.exists(mpath):
            continue
        with open(mpath) as f:
            for line in f:
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                cf = row["contract_file"].replace("\\", "/")
                if sol_norm.endswith(cf):
                    matches.append(row)
    return matches


# =============================================================================
# BUOC 1: DISASSEMBLE
# =============================================================================
TERMINATOR_OPS = {"STOP", "RETURN", "REVERT", "SELFDESTRUCT", "INVALID"}
BRANCH_OPS = {"JUMP", "JUMPI"}
EXTERNAL_CALL_OPS = {"CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"}

SEMANTIC_RULES = {
    "reentrancy_call_before_sstore":            (EXTERNAL_CALL_OPS, {"SSTORE"}),
    "unchecked_external_call_return":           (EXTERNAL_CALL_OPS, {"POP"}),
    "integer_overflow_arith_to_storage":        ({"ADD", "MUL", "SUB"}, {"SSTORE"}),
    "tx_origin_authorization":                  ({"ORIGIN"}, {"EQ"}),
    "timestamp_dependence":                     ({"TIMESTAMP"}, {"LT", "GT", "EQ", "SLT", "SGT"}),
}
SEMANTIC_WINDOW = 8


def find_seed_edges_in_block(block_instrs, pc_to_node, func_key):
    edges = []
    n = len(block_instrs)
    for i, ins_a in enumerate(block_instrs):
        for rule_name, (set_a, set_b) in SEMANTIC_RULES.items():
            if ins_a.name not in set_a:
                continue
            window_end = min(i + 1 + SEMANTIC_WINDOW, n)
            for j in range(i + 1, window_end):
                if block_instrs[j].name in set_b:
                    na = pc_to_node[(func_key, ins_a.pc)]
                    nb = pc_to_node[(func_key, block_instrs[j].pc)]
                    edges.append([na, nb, rule_name])
                    break
    return edges


def disassemble_bytecode(bytecode_hex: str):
    """SUA: cat metadata TRUOC khi disassemble."""
    bytecode_hex = strip_metadata(bytecode_hex)
    if bytecode_hex.startswith("0x"):
        bytecode_hex = bytecode_hex[2:]
    raw_bytes = bytes.fromhex(bytecode_hex)
    instructions = list(disassemble_all(raw_bytes))
    return instructions, raw_bytes


def split_basic_blocks(instructions):
    blocks = {}
    current_start = instructions[0].pc if instructions else 0
    current_instrs = []
    for i, ins in enumerate(instructions):
        if ins.name == "JUMPDEST" and current_instrs:
            blocks[current_start] = {"instrs": current_instrs, "fallthrough": ins.pc}
            current_start = ins.pc
            current_instrs = [ins]
            continue
        current_instrs.append(ins)
        if ins.name in TERMINATOR_OPS or ins.name in BRANCH_OPS:
            next_pc = instructions[i + 1].pc if i + 1 < len(instructions) else None
            fallthrough = next_pc if ins.name != "JUMP" and ins.name not in TERMINATOR_OPS else None
            blocks[current_start] = {"instrs": current_instrs, "fallthrough": fallthrough}
            current_start = next_pc
            current_instrs = []
    if current_instrs:
        blocks[current_start] = {"instrs": current_instrs, "fallthrough": None}
    return blocks


def resolve_static_jump_targets(instructions):
    targets = {}
    for i, ins in enumerate(instructions):
        if ins.name in BRANCH_OPS and i > 0:
            prev = instructions[i - 1]
            if prev.name.startswith("PUSH") and prev.operand is not None:
                targets[ins.pc] = prev.operand
    return targets


# =============================================================================
# BUOC 2: XAY CFBG (THEM: luu ca PC cua tung node, khong chi ten opcode)
# =============================================================================
def build_intra_and_inter_graphs(instructions):
    blocks = split_basic_blocks(instructions)
    static_jump_targets = resolve_static_jump_targets(instructions)

    jumpdest_pcs = sorted(pc for pc, ins in ((b_pc, b["instrs"][0]) for b_pc, b in blocks.items())
                           if ins.name == "JUMPDEST")
    call_targets = set(static_jump_targets.values())
    func_entry_pcs = sorted(set(jumpdest_pcs) & call_targets) or jumpdest_pcs[:1]

    def owning_func(block_pc):
        owner = func_entry_pcs[0] if func_entry_pcs else 0
        for fpc in func_entry_pcs:
            if fpc <= block_pc:
                owner = fpc
            else:
                break
        return owner

    intra_proc_graphs = {}
    node_id_counter = {}
    pc_to_node = {}

    for entry_pc in func_entry_pcs:
        func_key = f"func_{entry_pc}"
        intra_proc_graphs[func_key] = {
            "nodes": [], "node_pcs": [], "edges_seq": [], "edges_data": [],
            "seed_sem_edges": [],
        }
        node_id_counter[func_key] = 0

    block_first_node = {}
    block_last_node = {}

    for block_pc, block in sorted(blocks.items()):
        func_key = f"func_{owning_func(block_pc)}"
        if func_key not in intra_proc_graphs:
            continue
        g = intra_proc_graphs[func_key]

        prev_node_id = None
        for ins in block["instrs"]:
            nid = node_id_counter[func_key]
            g["nodes"].append(ins.name)
            g["node_pcs"].append(ins.pc)   # MOI: luu PC that cua node
            pc_to_node[(func_key, ins.pc)] = nid
            if block_pc not in block_first_node:
                block_first_node[block_pc] = nid
            block_last_node[block_pc] = nid
            if prev_node_id is not None:
                g["edges_seq"].append([prev_node_id, nid])
            prev_node_id = nid
            node_id_counter[func_key] += 1

        g["seed_sem_edges"].extend(
            find_seed_edges_in_block(block["instrs"], pc_to_node, func_key)
        )

    for block_pc, block in blocks.items():
        func_key = f"func_{owning_func(block_pc)}"
        if func_key not in intra_proc_graphs or block_pc not in block_last_node:
            continue
        g = intra_proc_graphs[func_key]
        last_nid = block_last_node[block_pc]
        last_ins = block["instrs"][-1]
        succ_pcs = []
        if block["fallthrough"] is not None:
            succ_pcs.append(block["fallthrough"])
        if last_ins.name in BRANCH_OPS and last_ins.pc in static_jump_targets:
            succ_pcs.append(static_jump_targets[last_ins.pc])
        for spc in succ_pcs:
            if spc in block_first_node and owning_func(spc) == owning_func(block_pc):
                g["edges_data"].append([last_nid, block_first_node[spc]])

    for func_key, g in intra_proc_graphs.items():
        g["num_nodes"] = len(g["nodes"])
        g["num_edges_seq"] = len(g["edges_seq"])
        g["num_edges_data"] = len(g["edges_data"])
        g["num_seed_sem_edges"] = len(g["seed_sem_edges"])

    inter_edges = []
    external_call_flags = {fk: False for fk in intra_proc_graphs}
    func_pc_list = sorted(func_entry_pcs)

    for block_pc, block in blocks.items():
        caller_func = owning_func(block_pc)
        caller_key = f"func_{caller_func}"
        for ins in block["instrs"]:
            if ins.pc in static_jump_targets:
                tgt = static_jump_targets[ins.pc]
                if tgt in func_entry_pcs and tgt != caller_func:
                    u = func_pc_list.index(caller_func)
                    v = func_pc_list.index(tgt)
                    inter_edges.append([u, v])
            if ins.name in EXTERNAL_CALL_OPS and caller_key in external_call_flags:
                external_call_flags[caller_key] = True

    return intra_proc_graphs, inter_edges, func_pc_list, external_call_flags


# =============================================================================
# BUOC 2.5: GAN NHAN CAP HAM VAO CFBG (MOI - Giai doan 3)
# =============================================================================
def attach_function_level_labels(intra_proc_graphs, pc_to_func_label):
    """Voi moi func_key trong CFBG, tong hop nhan tu cac node (opcode) ben
    trong no dua theo pc_to_func_label (tu manifest nguoi audit that)."""
    any_vulnerable = False
    for func_key, g in intra_proc_graphs.items():
        covered = [pc_to_func_label[pc] for pc in g["node_pcs"] if pc in pc_to_func_label]
        if covered:
            label = 1 if any(c["label"] == 1 for c in covered) else 0
            names = sorted({c["function_name"] for c in covered})
            vuln_types = sorted({
                (vt if isinstance(vt, str) else ",".join(vt))
                for c in covered if c["label"] == 1 and c["vuln_type"]
                for vt in ([c["vuln_type"]] if isinstance(c["vuln_type"], str) else c["vuln_type"])
            })
            g["function_level_label"] = label
            g["function_level_names"] = names
            g["function_level_vuln_types"] = vuln_types
            if label == 1:
                any_vulnerable = True
        else:
            g["function_level_label"] = None   # khong co annotation nao khop
            g["function_level_names"] = []
            g["function_level_vuln_types"] = []
    return any_vulnerable


# =============================================================================
# BUOC 3: COMPILE (--combined-json, can srcmap-runtime)
# =============================================================================
def detect_solc_version(sol_path: str) -> str:
    try:
        text = open(sol_path, errors="ignore").read()
        m = PRAGMA_RE.search(text)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "0.8.21"

# Ban va cuoi cung cua tung nhanh minor - dung lam fallback khi pragma
# ghi phien ban thap nhat (vd ^0.6.0) nhung code that su dung cu phap
# chi co tu ban vas sau (vd {value: ...} can >=0.6.2).
LATEST_PATCH_FOR_MINOR = {
    "0.4": "0.4.26", "0.5": "0.5.17", "0.6": "0.6.12",
    "0.7": "0.7.6", "0.8": "0.8.26",
}


def get_version_candidates(detected_version):
    """Tra ve danh sach [detected_version, ban_vas_cuoi_cung_cung_minor]
    (loai trung neu giong nhau) - de thu them ban moi nhat cung nhanh
    minor khi ban thap nhat bi loi cu phap."""
    candidates = [detected_version]
    parts = detected_version.split(".")
    if len(parts) >= 2:
        minor_key = f"{parts[0]}.{parts[1]}"
        latest = LATEST_PATCH_FOR_MINOR.get(minor_key)
        if latest and latest != detected_version:
            candidates.append(latest)
    return candidates
    
FALLBACK_VERSIONS_NO_PRAGMA = ["0.4.18", "0.4.11", "0.4.24", "0.4.8", "0.4.0", "0.3.6", "0.3.5"]


def find_project_root(sol_path):
    """Do nguoc len tu vi tri file .sol de tim goc project - uu tien thu
    muc co node_modules (chua @openzeppelin/... that su), fallback ve
    thu muc cap 2 duoi DAppSCAN-source/contracts/ neu khong tim duoc."""
    current = os.path.dirname(os.path.abspath(sol_path))
    root_marker = "DAppSCAN-source" + os.sep + "contracts" + os.sep
    fallback_root = None
    depth = 0
    while current and depth < 15:
        if os.path.isdir(os.path.join(current, "node_modules")):
            return current
        if root_marker in current and fallback_root is None:
            idx = current.find(root_marker) + len(root_marker)
            rest = current[idx:].split(os.sep)
            if rest and rest[0]:
                fallback_root = os.path.join(current[:idx], rest[0])
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
        depth += 1
    return fallback_root or os.path.dirname(os.path.abspath(sol_path))


def try_compile_with_flags(sol_path, env, project_root):
    """Thu compile voi cac cap do co dan tu day du -> toi gian, vi cac
    phien ban solc cu KHONG HO TRO --include-path (can >=0.8.8) va thap
    hon nua thi ca --base-path cung khong co (can >=0.6.9). Thu lan luot,
    dung lai ngay khi thanh cong hoac khi loi KHONG PHAI do co sai."""
    flag_variants = [
        ["--base-path", project_root, "--include-path", os.path.join(project_root, "node_modules")],
        ["--base-path", project_root],
        [],
    ]
    last_proc = None
    for flags in flag_variants:
        cmd = ["solc", "--combined-json", "bin-runtime,srcmap-runtime"] + flags + [sol_path]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90, env=env)
        except subprocess.TimeoutExpired:
            return None
        if proc.returncode == 0:
            return proc
        last_proc = proc
        if "unrecognised option" not in proc.stderr:
            break
    return last_proc


def compile_with_solc_select_full(sol_path: str, solc_version: str):
    """Tra ve (bytecode_hex, srcmap_str, version_thuc_su_dung)."""
    versions_to_try = FALLBACK_VERSIONS_NO_PRAGMA if solc_version == "0.8.21" else get_version_candidates(solc_version)
    last_error = None
    for v in versions_to_try:
        try:
            subprocess.run(["solc-select", "install", v], capture_output=True, timeout=120)
            env = os.environ.copy()
            env["SOLC_VERSION"] = v
            project_root = find_project_root(sol_path)
            proc = try_compile_with_flags(sol_path, env, project_root)
            if proc is None:
                last_error = "timeout"
                continue
            if proc.returncode != 0:
                last_error = proc.stderr[:300]
                continue
            data = json.loads(proc.stdout)
            contracts = data.get("contracts", {})
            candidates = [(k, c) for k, c in contracts.items() if c.get("bin-runtime")]
            if not candidates:
                last_error = "khong co contract nao co bin-runtime non-empty"
                continue
            key, best = max(candidates, key=lambda kv: len(kv[1]["bin-runtime"]))
            return best["bin-runtime"], best.get("srcmap-runtime", ""), v
        except json.JSONDecodeError as e:
            last_error = f"loi doc combined-json: {e}"
            continue
        except Exception as e:
            last_error = str(e)
            continue
    raise RuntimeError(f"Khong compile duoc voi bat ky version nao trong {versions_to_try}: {last_error}")


# =============================================================================
# BUOC 4: MAIN
# =============================================================================
def process_single_contract(sol_path, contract_id, bytecode_hex, srcmap_str,
                             manifest_entries, output_dir, extra_meta=None):
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, f"{contract_id}_static.json")

    with open(sol_path, errors="ignore") as f:
        source_text = f.read()

    instructions, raw_bytes = disassemble_bytecode(bytecode_hex)
    if not instructions:
        log_error(f"Empty disassembly for {contract_id}")
        return

    pc_to_line = build_pc_to_line_map(bytecode_hex, srcmap_str, source_text, instructions)
    pc_to_func_label = map_pc_to_function(pc_to_line, manifest_entries)

    m_ent, mx_ent, mn_ent, seq = get_entropy_manual(raw_bytes)
    intra_graphs, inter_edges, func_pc_list, ext_call_flags = build_intra_and_inter_graphs(instructions)

    any_vulnerable = attach_function_level_labels(intra_graphs, pc_to_func_label)
    n_labeled_funcs = sum(1 for g in intra_graphs.values() if g["function_level_label"] is not None)

    feat = {
        "contract_id": contract_id,
        "source_sol_path": sol_path,
        "bytecode_hash": get_bytecode_hash(bytecode_hex),
        "label": int(any_vulnerable),   # fallback cap hop dong, CHI DE THAM KHAO
        "bytecode_length": len(raw_bytes),
        "num_functions_detected": len(func_pc_list),
        "num_functions_with_manifest_label": n_labeled_funcs,
        "has_any_external_call": int(any(ext_call_flags.values())),
        "mean_entropy": m_ent,
        "max_entropy": mx_ent,
        "min_entropy": mn_ent,
        "entropy_sequence": seq,
        "inter_procedural_call_graph": {
            "edges": inter_edges,
            "num_edges": len(inter_edges),
        },
        "intra_procedural_graphs": intra_graphs,
    }
    if extra_meta:
        feat.update(extra_meta)

    with open(out_path, "w") as f:
        json.dump(feat, f, indent=2)
    log_info(f"OK: {contract_id} -> {os.path.basename(out_path)} "
              f"(funcs={len(func_pc_list)}, labeled={n_labeled_funcs}, "
              f"seed_sem={sum(g['num_seed_sem_edges'] for g in intra_graphs.values())})")


def main():
    """
    Cach dung:
        python extract_evm_features.py <contract.sol> <contract_id> <manifest1.jsonl>[,<manifest2.jsonl>,...] [out_dir]
    """
    if len(sys.argv) < 4:
        log_error("Usage: python extract_evm_features.py <contract.sol> <contract_id> <manifest.jsonl>[,...] [out_dir]")
        sys.exit(1)

    sol_path = sys.argv[1]
    contract_id = sys.argv[2]
    manifest_paths = sys.argv[3].split(",")
    out_dir = sys.argv[4] if len(sys.argv) >= 5 else os.environ.get(
        "HIN_DIR_DEFI", "./hin_defi_static") + "/data/features_graph"

    solc_version = None
    try:
        manifest_entries = load_matching_manifest(sol_path, manifest_paths)
        if not manifest_entries:
            log_error(f"Khong tim thay annotation nao trong manifest cho: {sol_path}")
            sys.exit(1)

        detected_version = detect_solc_version(sol_path)
        bytecode_hex, srcmap_str, solc_version = compile_with_solc_select_full(sol_path, detected_version)

        process_single_contract(sol_path, contract_id, bytecode_hex, srcmap_str,
                                 manifest_entries, out_dir,
                                 extra_meta={"solc_version_used": solc_version})

    except Exception as e:
        log_error(f"Critical crash on {contract_id}: {e}")
        traceback.print_exc(file=sys.stderr)


if __name__ == "__main__":
    main()
