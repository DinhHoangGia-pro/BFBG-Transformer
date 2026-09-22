"""
extract_evm_features.py
========================
Ban CAI BIEN cua extract_features_single.py (IoT/ELF + angr/pyvex) sang mien
DeFi Smart Contract (EVM bytecode), phuc vu kien truc T-CFBG.

CAP NHAT (lan 3 - QUAN TRONG NHAT): sua loi seed_sem_edges gan nhu KHONG
BAT DUOC gi ca doi voi 2/5 luat quan trong nhat. Da xac nhan bang so lieu
tren toan bo 10.513 file da trich xuat: reentrancy_call_before_sstore chi
khop 4/5797 hop dong (0.07%), tx_origin_authorization khop DUNG 0 hop dong,
trong khi Slither bao cao hang nghin hop dong that su dinh 2 loai nay.

Nguyen nhan: luat cu yeu cau 2 opcode NAM NGAY CANH NHAU
(block["instrs"][j] va block["instrs"][j+1]) - nhung bytecode Solidity that
GAN NHU KHONG BAO GIO sinh ra kieu lien ke tuyet doi nay. Vi du:
  tx.origin == owner   bien dich thanh:  ORIGIN, PUSH20 <addr>, EQ
                                          (co PUSH20 CHEN GIUA, khong lien ke)
  CALL truoc SSTORE    bien dich thanh:  CALL, ISZERO, PUSH<dest>, JUMPI, ...
                                          (nhieu lenh xen giua, khong lien ke)

Da sua: quet trong CUA SO SEMANTIC_WINDOW=8 lenh thay vi doi hoi lien ke
tuyet doi, van gioi han trong PHAM VI 1 BASIC BLOCK (khong bang qua ranh
gioi block) de tranh sinh qua nhieu canh gia (false-positive weak-label).

GIOI HAN CON LAI (ghi nhan de dua vao Discussion): mau reentrancy kinh dien
(CALL o 1 block, SSTORE cap nhat trang thai o 1 block KHAC sau nhanh JUMPI)
van co the khong duoc bat neu 2 opcode nam o 2 block khac nhau - day la gioi
han co chu dich cua ban sua nay (uu tien giam false-positive hon la toi da
recall), can cau nhac mo rong sang lien-block trong phien ban sau neu
reentrancy van it mau sau khi ap dung fix nay.

CAP NHAT (lan 2): thay the hoan toan thu vien `solcx` bang goi truc tiep
`solc-select` + `solc` qua subprocess - vi `solcx` TU CHOI cai cac phien
ban solc < 0.4.11 (UnsupportedVersionError), trong khi dataset SmartBugs
Wild co toi 13/41 phien ban nam duoi nguong nay (0.3.5 -> 0.4.10).
`solc-select` (da dung thanh cong cho ca 47.398 file o buoc chay Slither
truoc do) HO TRO day du cac phien ban nay, khong co gioi han nay.

CAP NHAT (lan 1, da gop vao lan 2): tu dong do dung phien ban solc tu dong
pragma cua tung file, thay vi hardcode "0.8.21" nhu ban goc (gay loi
compile gan nhu toan bo voi dataset cu 2017-2019).

  - IoT: angr.Project + CFGFast (lift ELF -> VEX IR) de lay CFG cap ham.
  - DeFi: pyevmasm (disassembler EVM) tren bytecode da compile, tu dung CFG
    cap basic-block bang cach cat theo JUMPDEST/JUMP/JUMPI/STOP/RETURN/REVERT.
  - "Ham" trong EVM (Solidity) = JUMPDEST duoc tro toi boi dispatcher.
  - E_sem (5 luat SWC trong Bang 1 cua bai) duoc xuat ra duoi dang
    "seed_sem_edges" (weak positive label) de Learned Semantic Dependency
    Predictor dung lam nhan khoi tao khi huan luyen.

YEU CAU CAI DAT (venv rieng):
    pip install pyevmasm solc-select
    (KHONG con can py-solc-x nua)
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

# Bat duoc ca cu phap pragma dang khoang (>=X.Y.Z <A.B.C)
PRAGMA_RE = re.compile(r'pragma\s+solidity\s*[^;]*?([0-9]+\.[0-9]+\.[0-9]+)')


def log_error(msg):
    sys.stderr.write(f"[ERROR] {msg}\n")
    sys.stderr.flush()


def log_info(msg):
    sys.stderr.write(f"[INFO] {msg}\n")
    sys.stderr.flush()


# =============================================================================
# CAC HAM HELPER (hash, entropy) - GIU NGUYEN TU BAN GOC
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
# BUOC 1: DISASSEMBLE BYTECODE -> DANH SACH INSTRUCTION
# =============================================================================
TERMINATOR_OPS = {"STOP", "RETURN", "REVERT", "SELFDESTRUCT", "INVALID"}
BRANCH_OPS = {"JUMP", "JUMPI"}
EXTERNAL_CALL_OPS = {"CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"}

# 5 luat SWC cua Bang 1 trong bai - dung lam weak seed label cho Learned
# Semantic Dependency Predictor (Section 4.3).
SEMANTIC_RULES = {
    "reentrancy_call_before_sstore":            (EXTERNAL_CALL_OPS, {"SSTORE"}),
    "unchecked_external_call_return":           (EXTERNAL_CALL_OPS, {"POP"}),
    "integer_overflow_arith_to_storage":        ({"ADD", "MUL", "SUB"}, {"SSTORE"}),
    "tx_origin_authorization":                  ({"ORIGIN"}, {"EQ"}),
    "timestamp_dependence":                     ({"TIMESTAMP"}, {"LT", "GT", "EQ", "SLT", "SGT"}),
}

# SUA LOI CHINH: so opcode toi da duoc phep xen giua source va target khi
# tim seed_sem_edges. Truoc day yeu cau lien ke tuyet doi (window=1), gan
# nhu khong bao gio khop voi bytecode Solidity that (da xac nhan bang so
# lieu: reentrancy 4/5797, tx_origin 0/~2613). Gioi han van trong PHAM VI
# 1 BASIC BLOCK (xem ham find_seed_edges_in_block).
SEMANTIC_WINDOW = 8


def find_seed_edges_in_block(block_instrs, pc_to_node, func_key):
    """SUA LOI QUAN TRONG: quet CUA SO SEMANTIC_WINDOW lenh thay vi chi bat
    2 opcode lien ke tuyet doi - vi bytecode Solidity that gan nhu luon co
    lenh trung gian (vd ORIGIN, PUSH20 <addr>, EQ cho tx.origin==owner).
    Van gioi han trong 1 block (khong quet qua ranh gioi block) de tranh
    sinh qua nhieu canh gia. Voi moi opcode nguon khop set_a, chi lay KHOP
    GAN NHAT phia sau no trong cua so, tranh trung lap qua muc."""
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
                    break  # chi lay khop gan nhat cho moi (opcode nguon, luat)
    return edges


def disassemble_bytecode(bytecode_hex: str):
    """Tra ve list cac Instruction (pc, name, operand) tu pyevmasm."""
    if bytecode_hex.startswith("0x"):
        bytecode_hex = bytecode_hex[2:]
    raw_bytes = bytes.fromhex(bytecode_hex)
    instructions = list(disassemble_all(raw_bytes))
    return instructions, raw_bytes


def split_basic_blocks(instructions):
    """
    Cat basic block theo quy tac EVM chuan:
      - Mot block moi bat dau tai moi JUMPDEST.
      - Mot block ket thuc ngay sau JUMP/JUMPI/STOP/RETURN/REVERT/
        SELFDESTRUCT/INVALID, hoac ngay truoc JUMPDEST tiep theo.
    Tra ve dict: block_start_pc -> {"instrs": [...], "fallthrough": pc|None}
    """
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
    """
    Suy ra target tinh cua JUMP/JUMPI khi lenh ngay truoc la PUSHx <const>.
    Tra ve dict: pc_of_jump -> target_pc.
    """
    targets = {}
    for i, ins in enumerate(instructions):
        if ins.name in BRANCH_OPS and i > 0:
            prev = instructions[i - 1]
            if prev.name.startswith("PUSH") and prev.operand is not None:
                targets[ins.pc] = prev.operand
    return targets


# =============================================================================
# BUOC 2: PHAN TACH "HAM" (JUMPDEST) + XAY CFBG NOI-HAM
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
            "nodes": [], "edges_seq": [], "edges_data": [],
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
            op_token = ins.name
            nid = node_id_counter[func_key]
            g["nodes"].append(op_token)
            pc_to_node[(func_key, ins.pc)] = nid
            if block_pc not in block_first_node:
                block_first_node[block_pc] = nid
            block_last_node[block_pc] = nid

            if prev_node_id is not None:
                g["edges_seq"].append([prev_node_id, nid])
            prev_node_id = nid
            node_id_counter[func_key] += 1

        # SUA LOI CHINH: thay vi chi so sanh 2 opcode lien ke (j, j+1),
        # goi ham quet theo cua so SEMANTIC_WINDOW cho toan bo block.
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

    # =========================================================================
    # BUOC 3: DO THI LIEN HAM (inter_procedural_call_graph)
    # =========================================================================
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
# BUOC 3.5: COMPILE - GOI TRUC TIEP solc-select + solc (KHONG DUNG solcx NUA)
# =============================================================================
def detect_solc_version(sol_path: str) -> str:
    """Tu dong doc dong 'pragma solidity' cua file, thay vi hardcode."""
    try:
        text = open(sol_path, errors="ignore").read()
        m = PRAGMA_RE.search(text)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "0.8.21"  # fallback neu khong tim thay pragma nao (hiem gap)


# Cac phien ban pho bien nhat cua giai doan TRUOC KHI pragma tro thanh
# bat buoc (~cuoi 2016 tro ve truoc) - thu tuan tu, dung ban dau tien
# compile thanh cong.
FALLBACK_VERSIONS_NO_PRAGMA = ["0.4.18", "0.4.11", "0.4.24", "0.4.8", "0.4.0", "0.3.6", "0.3.5"]


def compile_with_solc_select(sol_path: str, solc_version: str):
    """Tra ve (bytecode_hex, version_thuc_su_dung).
    Neu solc_version la "0.8.21" (fallback mac dinh khi khong tim thay
    pragma), THU TUAN TU cac phien ban pho bien nhat cua giai doan chua
    bat buoc pragma, thay vi ep bang 0.8.21 (chac chan loi voi code cu)."""
    versions_to_try = FALLBACK_VERSIONS_NO_PRAGMA if solc_version == "0.8.21" else [solc_version]

    last_error = None
    for v in versions_to_try:
        try:
            subprocess.run(["solc-select", "install", v], capture_output=True, timeout=120)
            env = os.environ.copy()
            env["SOLC_VERSION"] = v

            proc = subprocess.run(
                ["solc", "--bin-runtime", sol_path],
                capture_output=True, text=True, timeout=60, env=env,
            )
            if proc.returncode != 0:
                last_error = proc.stderr[:300]
                continue

            blocks = re.split(r'=======\s*(.*?)\s*=======', proc.stdout)
            candidates = []
            for i in range(1, len(blocks), 2):
                body = blocks[i + 1] if i + 1 < len(blocks) else ""
                m = re.search(r'Binary of the runtime part:\s*\n([0-9a-fA-F]+)', body)
                if m and m.group(1):
                    candidates.append(m.group(1))

            if candidates:
                best_bytecode = max(candidates, key=len)
                return best_bytecode, v

        except subprocess.TimeoutExpired:
            last_error = "timeout"
            continue
        except Exception as e:
            last_error = str(e)
            continue

    raise RuntimeError(f"Khong compile duoc voi bat ky version nao trong {versions_to_try}: {last_error}")


# =============================================================================
# BUOC 4: MAIN
# =============================================================================
def process_single_contract(bytecode_hex: str, contract_id: str, label: int,
                             output_dir: str, extra_meta: dict = None):
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, f"{contract_id}_static.json")

    instructions, raw_bytes = disassemble_bytecode(bytecode_hex)
    if not instructions:
        log_error(f"Empty disassembly for {contract_id}")
        return

    m_ent, mx_ent, mn_ent, seq = get_entropy_manual(raw_bytes)
    intra_graphs, inter_edges, func_pc_list, ext_call_flags = build_intra_and_inter_graphs(instructions)

    feat = {
        "contract_id": contract_id,
        "bytecode_hash": get_bytecode_hash(bytecode_hex),
        "label": int(label),
        "bytecode_length": len(raw_bytes),
        "num_functions_detected": len(func_pc_list),
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
              f"(funcs={len(func_pc_list)}, seed_sem={sum(g['num_seed_sem_edges'] for g in intra_graphs.values())})")


def main():
    """
    Cach dung:
        python extract_evm_features.py <contract.sol|--bytecode hex> <id> <label> [out_dir]
    """
    if len(sys.argv) < 4:
        log_error("Usage: python extract_evm_features.py <contract.sol|--bytecode hex> <id> <label> [out_dir]")
        sys.exit(1)

    src_arg = sys.argv[1]
    contract_id = sys.argv[2]
    label = int(sys.argv[3])
    out_dir = sys.argv[4] if len(sys.argv) >= 5 else os.environ.get(
        "HIN_DIR_DEFI", "./hin_defi_static") + "/data/features_graph"

    solc_version = None
    try:
        if src_arg == "--bytecode":
            hex_arg = sys.argv[2]
            contract_id = sys.argv[3]
            label = int(sys.argv[4])
            out_dir = sys.argv[5] if len(sys.argv) >= 6 else out_dir
            bytecode_hex = open(hex_arg).read().strip() if os.path.exists(hex_arg) else hex_arg
        else:
            detected_version = detect_solc_version(src_arg)
            bytecode_hex, solc_version = compile_with_solc_select(src_arg, detected_version)

        process_single_contract(bytecode_hex, contract_id, label, out_dir,
                                 extra_meta={"solc_version_used": solc_version})

    except Exception as e:
        log_error(f"Critical crash on {contract_id}: {e}")
        traceback.print_exc(file=sys.stderr)


if __name__ == "__main__":
    main()
