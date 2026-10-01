"""
vex_tokenizer.py
================
Tokenize lenh may / cau lenh VEX IR thanh token roi rac cho lop embedding
cua TokenSequenceTransformer (src/models/bfbg_transformer.py).

Hai che do token:
  - 'insn' (mac dinh): mnemonic + kieu toan hang, vd `mov rax, [rbp-8]`
    -> "mov_reg_mem", `call 0x401000` -> "call_imm", `ret` -> "ret".
    Bo gia tri cu the (thanh ghi, hang so, dia chi) de vocab nho va khong
    phu thuoc dia chi nap.
  - 'vex': tag cau lenh VEX + tag bieu thuc + phep toan, vd
    "WrTmp:Binop:Iop_Add32", "Store:RdTmp", "Exit:Ijk_Boring". Doc lap voi
    kien truc (x86/x64/ARM deu lift ve cung IR).

Module nay KHONG phu thuoc angr - chi lam viec tren du lieu da lift boi
src/disassembly/pe_lifter.py (LiftedBlock) va object pyvex.
"""

import json
from collections import Counter

UNK_TOKEN = '<UNK>'
UNK_ID = 0   # trung voi chi so padding/<UNK> ma TokenSequenceTransformer dung

# Gia tri chung cua capstone (CS_OP_REG/IMM/MEM/FP); x86 va ARM64 dung cung ma.
_OPERAND_TYPE_NAMES = {1: 'reg', 2: 'imm', 3: 'mem', 4: 'fp'}

# Cau lenh VEX khong mang ngu nghia tinh toan - bo qua khi tokenize.
_SKIP_VEX_TAGS = {'Ist_IMark', 'Ist_NoOp', 'Ist_AbiHint'}


def operand_type_name(cs_op_type):
    return _OPERAND_TYPE_NAMES.get(cs_op_type, f'op{cs_op_type}')


def instruction_token(mnemonic, operand_types):
    """'mov', ('reg', 'mem') -> 'mov_reg_mem'. Tien to (rep/lock) noi bang '.'."""
    head = mnemonic.strip().lower().replace(' ', '.')
    return '_'.join([head, *operand_types])


def _strip(tag, prefix):
    return tag[len(prefix):] if tag.startswith(prefix) else tag


def vex_stmt_token(stmt):
    """Token cho 1 cau lenh pyvex, hoac None neu cau lenh bi bo qua."""
    if stmt.tag in _SKIP_VEX_TAGS:
        return None
    parts = [_strip(stmt.tag, 'Ist_')]
    if stmt.tag == 'Ist_Exit':
        parts.append(stmt.jumpkind)
    data = getattr(stmt, 'data', None)
    if data is not None:
        parts.append(_strip(data.tag, 'Iex_'))
        op = getattr(data, 'op', None)
        if op is not None:
            parts.append(op)
    return ':'.join(parts)


def tokenize_block(block, mode='insn'):
    if mode == 'insn':
        return [instruction_token(i.mnemonic, i.operand_types) for i in block.instructions]
    if mode == 'vex':
        if block.vex_tokens is None:
            raise ValueError("Block chua co vex_tokens - lift voi lift_vex=True")
        return list(block.vex_tokens)
    raise ValueError(f"mode khong hop le: {mode!r} (chi 'insn' hoac 'vex')")


def tokenize_function(func, mode='insn'):
    """Token cua ca ham theo thu tu block (sap theo dia chi)."""
    return [tok for block in func.blocks for tok in tokenize_block(block, mode)]


class Vocab:
    """Anh xa token <-> id, id 0 = <UNK>. len(vocab) la vocab_size truyen
    vao BFBGTransformer."""

    def __init__(self, tokens=()):
        self.itos = [UNK_TOKEN]
        self.stoi = {UNK_TOKEN: UNK_ID}
        for tok in tokens:
            self.add(tok)

    def add(self, token):
        if token not in self.stoi:
            self.stoi[token] = len(self.itos)
            self.itos.append(token)
        return self.stoi[token]

    @classmethod
    def build(cls, token_iterables, min_freq=1, max_size=None):
        """Dung vocab tu nhieu chuoi token (vd tap train), token pho bien truoc."""
        counter = Counter()
        for tokens in token_iterables:
            counter.update(tokens)
        ranked = sorted((t for t, c in counter.items() if c >= min_freq), key=lambda t: (-counter[t], t))
        if max_size is not None:
            ranked = ranked[:max_size - 1]   # chua cho <UNK>
        return cls(ranked)

    def encode(self, tokens):
        return [self.stoi.get(t, UNK_ID) for t in tokens]

    def decode(self, ids):
        return [self.itos[i] if 0 <= i < len(self.itos) else UNK_TOKEN for i in ids]

    def __len__(self):
        return len(self.itos)

    def __contains__(self, token):
        return token in self.stoi

    def save(self, path):
        with open(path, 'w') as f:
            json.dump(self.itos, f, indent=0)

    @classmethod
    def load(cls, path):
        with open(path) as f:
            itos = json.load(f)
        if not itos or itos[0] != UNK_TOKEN:
            raise ValueError(f"{path}: phan tu dau tien phai la {UNK_TOKEN}")
        return cls(itos[1:])
