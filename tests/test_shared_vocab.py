"""
Test ghi vocab VEX dung chung tu nhieu tien trinh dong thoi
(src/disassembly/vex_tokenizer.update_shared_vocab).

Moi tien trinh lap nhieu vong: them mot tap token ngau nhien (chong lan
voi tien trinh khac) vao CUNG 1 file vocab, ghi lai cap (token, id) da
nhan duoc - dung nhu bfbg_builder dung id do de ghi JSON. Sau cung kiem
tra:
  1. file vocab hop le, <UNK> o id 0, khong token trung lap;
  2. MOI cap (token, id) ma bat ky tien trinh nao da dung deu khop vocab
     cuoi cung (neu khong: JSON da ghi tro toi sai token = corrupt).
Doan giua doc va ghi duoc lam cham co chu dich de race de xay ra.

Chay:  python tests/test_shared_vocab.py   (hoac pytest tests/)
"""

import json
import multiprocessing as mp
import os
import random
import sys
import tempfile
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.disassembly import vex_tokenizer  # noqa: E402
from src.disassembly.vex_tokenizer import UNK_TOKEN, Vocab, update_shared_vocab  # noqa: E402

N_PROCS = 6
N_ROUNDS = 25
TOKEN_POOL = [f"WrTmp:Binop:Iop_Op{i}" for i in range(300)]


def _slow_add(orig_add):
    def add(self, token):
        if token not in self.stoi:
            time.sleep(0.0005)    # mo rong khe doc -> ghi
        return orig_add(self, token)
    return add


def naive_update(path, tokens):
    """Cach cu (khong khoa): doc, them, ghi."""
    vocab = Vocab.load(path) if os.path.exists(path) else Vocab()
    for t in tokens:
        vocab.add(t)
    with open(path, 'w') as f:
        json.dump(vocab.itos, f)
    return vocab


def worker(args):
    path, seed, use_lock = args
    Vocab.add = _slow_add(Vocab.add)
    rng = random.Random(seed)
    used = []
    for _ in range(N_ROUNDS):
        tokens = rng.sample(TOKEN_POOL, rng.randint(1, 15))
        try:
            vocab = update_shared_vocab(path, tokens) if use_lock else naive_update(path, tokens)
        except (json.JSONDecodeError, ValueError) as e:     # doc trung luc file dang ghi do
            used.append(('__READ_ERROR__', repr(e)))
            continue
        used.extend((t, vocab.stoi[t]) for t in tokens)
    return used


def run(use_lock):
    """Tra ve (so cap (token,id) sai, so loi doc, file vocab cuoi hop le?)."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'vex_vocab.json')
        with mp.get_context('fork').Pool(N_PROCS) as pool:
            results = pool.map(worker, [(path, seed, use_lock) for seed in range(N_PROCS)])
        try:
            itos = json.load(open(path))
            valid = itos[0] == UNK_TOKEN and len(set(itos)) == len(itos)
        except Exception:
            return None, None, False
    used = [pair for r in results for pair in r]
    read_errors = sum(1 for t, _ in used if t == '__READ_ERROR__')
    wrong = sum(1 for t, i in used if t != '__READ_ERROR__' and (i >= len(itos) or itos[i] != t))
    return wrong, read_errors, valid


def test_update_shared_vocab_concurrent():
    wrong, read_errors, valid = run(use_lock=True)
    assert valid, "file vocab cuoi khong hop le"
    assert read_errors == 0, f"{read_errors} lan doc trung file dang ghi do"
    assert wrong == 0, f"{wrong} cap (token, id) da dung khong con khop vocab cuoi"


def test_atomic_save_never_partial():
    """Doc lien tuc trong luc tien trinh khac ghi: khong bao gio thay file do."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'v.json')
        Vocab(TOKEN_POOL[:5]).save(path)
        ctx = mp.get_context('fork')
        writer = ctx.Process(target=lambda: [Vocab(TOKEN_POOL[:k]).save(path) for k in range(5, 300)])
        writer.start()
        bad = 0
        while writer.is_alive():
            try:
                Vocab.load(path)
            except Exception:
                bad += 1
        writer.join()
        assert bad == 0, f"{bad} lan doc thay file ghi do"


if __name__ == '__main__':
    for name, lock in (("KHONG khoa (cach cu)", False), ("update_shared_vocab (co khoa)", True)):
        wrong, read_errors, valid = run(use_lock=lock)
        print(f"{name:32s}: {N_PROCS} tien trinh x {N_ROUNDS} vong -> cap (token,id) sai={wrong}, "
              f"loi doc file do={read_errors}, file cuoi hop le={valid}")
    test_update_shared_vocab_concurrent()
    test_atomic_save_never_partial()
    print("PASS: test_update_shared_vocab_concurrent, test_atomic_save_never_partial")
