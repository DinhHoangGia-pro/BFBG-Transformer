"""
pe_lifter.py
============
Nap file PE (.exe/.dll) bang angr, dung CFG bang CFGFast va lift tung basic
block -> lenh may (capstone) + VEX IR (pyvex). Cung bo cong cu ma ban
IoT/ELF goc (H-GNN) da dung - binary PE gan voi ELF hon nhieu so voi
bytecode EVM, nen KHONG port code tu pipeline EVM.

Ket qua la LiftedBinary: danh sach ham (sap theo dia chi), moi ham gom cac
block (sap theo dia chi) va canh chuyen dieu khien noi ham. Do thi lien ham
lay bang src/disassembly/callgraph_extractor.py.

Ham bi loai khoi danh sach: SimProcedure (ham import tu DLL, nam trong
cle##externs), thunk import (is_plt, vd `jmp [IAT]`), padding can le
(is_alignment), syscall, va ham nam ngoai main object. Loi goi toi ham
import van duoc giu o callgraph_extractor duoi dang API-call.

Chay thu:  python -m src.disassembly.pe_lifter <file.exe>
YEU CAU:   pip install angr
"""

import hashlib
import os
from dataclasses import dataclass, field

import angr
import pefile

from src.disassembly.vex_tokenizer import operand_type_name, vex_stmt_token

# Data directory 14 = IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (CLR header).
_COM_DESCRIPTOR_INDEX = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']


@dataclass
class Instruction:
    addr: int
    mnemonic: str
    op_str: str
    operand_types: tuple   # vd ('reg', 'mem')


@dataclass
class LiftedBlock:
    addr: int
    size: int
    instructions: list
    vex_tokens: list = None   # None neu lift voi lift_vex=False
    jumpkind: str = None      # vd Ijk_Boring, Ijk_Call, Ijk_Ret


@dataclass
class LiftedFunction:
    addr: int
    name: str
    blocks: list                                 # LiftedBlock, sap theo dia chi
    edges: list = field(default_factory=list)    # (src_idx, dst_idx) theo vi tri trong blocks

    @property
    def num_instructions(self):
        return sum(len(b.instructions) for b in self.blocks)


@dataclass
class LiftedBinary:
    path: str
    sha256: str
    file_size: int
    arch: str
    entry: int
    functions: list                  # LiftedFunction, sap theo dia chi
    project: object = field(default=None, repr=False)
    cfg: object = field(default=None, repr=False)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def is_dotnet_assembly(path):
    """True neu PE la .NET/CLR assembly (co CLR header - data directory
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR kich thuoc > 0). Than .NET la CIL
    bytecode, khong phai ma may x86 -> angr CFGFast khong lift duoc co y
    nghia (chi thay stub _CorExeMain). Doc bang pefile, khong nap angr."""
    pe = pefile.PE(path, fast_load=True)
    try:
        dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if _COM_DESCRIPTOR_INDEX >= len(dirs):
            return False
        clr = dirs[_COM_DESCRIPTOR_INDEX]
        return clr.VirtualAddress != 0 and clr.Size > 0
    finally:
        pe.close()


def load_project(path):
    """Chi nap main object - khong nap DLL phu thuoc (auto_load_libs=False);
    ham import tro thanh SimProcedure trong cle##externs."""
    return angr.Project(path, auto_load_libs=False)


def build_cfg(project):
    return project.analyses.CFGFast(normalize=True, resolve_indirect_jumps=True)


def is_lifted_function(func, main_object):
    """Ham thuoc code cua chinh binary (khong phai import/thunk/padding)."""
    if func.is_simprocedure or func.is_plt or func.is_alignment or func.is_syscall:
        return False
    return main_object.contains_addr(func.addr)


def _operand_types(cs_insn):
    try:
        return tuple(operand_type_name(op.type) for op in cs_insn.insn.operands)
    except Exception:   # capstone khong co detail cho lenh nay
        return ()


def lift_block(project, addr, size, lift_vex=True):
    block = project.factory.block(addr, size=size)
    instructions = [
        Instruction(addr=i.address, mnemonic=i.mnemonic, op_str=i.op_str, operand_types=_operand_types(i))
        for i in block.capstone.insns
    ]
    vex_tokens, jumpkind = None, None
    if lift_vex:
        irsb = block.vex
        vex_tokens = [t for t in (vex_stmt_token(s) for s in irsb.statements) if t is not None]
        jumpkind = irsb.jumpkind
    return LiftedBlock(addr=addr, size=size, instructions=instructions, vex_tokens=vex_tokens, jumpkind=jumpkind)


def lift_function(project, func, lift_vex=True):
    block_nodes = sorted((n for n in func.graph.nodes() if n.size and n.addr in func.block_addrs_set),
                         key=lambda n: n.addr)
    blocks = [lift_block(project, n.addr, n.size, lift_vex=lift_vex) for n in block_nodes]
    index = {n.addr: i for i, n in enumerate(block_nodes)}
    edges = sorted({(index[u.addr], index[v.addr]) for u, v in func.graph.edges()
                    if u.addr in index and v.addr in index})
    return LiftedFunction(addr=func.addr, name=func.name, blocks=blocks, edges=edges)


def lift_pe(path, lift_vex=True, keep_project=True):
    """Nap + dung CFG + lift toan bo ham cua 1 file PE.

    keep_project=True giu lai angr Project/CFG trong ket qua (can cho
    callgraph_extractor); dat False de giai phong bo nho khi chi can token."""
    project = load_project(path)
    cfg = build_cfg(project)
    main_object = project.loader.main_object

    functions = [
        lift_function(project, f, lift_vex=lift_vex)
        for f in sorted(cfg.kb.functions.values(), key=lambda f: f.addr)
        if is_lifted_function(f, main_object)
    ]
    functions = [f for f in functions if f.blocks]

    return LiftedBinary(
        path=os.path.abspath(path),
        sha256=sha256_file(path),
        file_size=os.path.getsize(path),
        arch=project.arch.name,
        entry=project.entry,
        functions=functions,
        project=project if keep_project else None,
        cfg=cfg if keep_project else None,
    )


def main():
    import argparse
    import logging
    from collections import Counter

    from src.disassembly.callgraph_extractor import extract_callgraph
    from src.disassembly.vex_tokenizer import tokenize_function

    parser = argparse.ArgumentParser(description="Lift 1 file PE va in tom tat")
    parser.add_argument('path')
    parser.add_argument('--show', type=int, default=12, help="So token dau tien in ra cho ham entry")
    args = parser.parse_args()
    for name in ('angr', 'cle', 'pyvex'):
        logging.getLogger(name).setLevel(logging.ERROR)

    lb = lift_pe(args.path)
    cg = extract_callgraph(lb)
    n_blocks = sum(len(f.blocks) for f in lb.functions)
    n_insns = sum(f.num_instructions for f in lb.functions)
    print(f"{os.path.basename(lb.path)}  sha256={lb.sha256[:16]}...  size={lb.file_size}  arch={lb.arch}  "
          f"entry={lb.entry:#x}")
    print(f"ham={len(lb.functions)}  block={n_blocks}  lenh={n_insns}  "
          f"canh goi noi bo={len(cg.edges)}  API-call={cg.num_api_calls} ({len(cg.unique_apis)} API khac nhau)")

    entry = next((f for f in lb.functions if f.addr == lb.entry), lb.functions[0] if lb.functions else None)
    if entry is not None:
        print(f"\nHam {entry.name} @ {entry.addr:#x}: {len(entry.blocks)} block, {len(entry.edges)} canh noi ham")
        print("  insn:", tokenize_function(entry, 'insn')[:args.show])
        print("  vex: ", tokenize_function(entry, 'vex')[:args.show])
        print("  API: ", cg.api_calls.get(entry.addr, [])[:args.show])

    top = Counter(tok for f in lb.functions for tok in tokenize_function(f, 'insn')).most_common(10)
    print(f"\nToken insn pho bien nhat: {top}")


if __name__ == '__main__':
    main()
