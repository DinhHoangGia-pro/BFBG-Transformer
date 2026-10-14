#!/usr/bin/env python
"""Cham v3 (holdout benign cuoi) MOT LAN theo docs/v3_eval_config.json.
AN TOAN:
  - Mac dinh KHONG lam gi (in huong dan). Chi `--run` moi cham that; `--selftest` test plumbing tren DU LIEU GIA.
  - File khoa `~/bfbg_benign_work/eval_v3.lock` chua CONFIG_HASH: neu da ton tai -> TU CHOI chay lan hai.
  - Kiem CONFIG_HASH khop sha256(docs/v3_eval_config.json) truoc khi chay.
KHONG chay khi chua co lenh "chay" cua nguoi dung. v3 = benign-only -> FPR la chinh; AUC dung BumbleBee lam positives.
"""
import os, sys, json, hashlib, argparse, warnings, math
warnings.filterwarnings("ignore")
REPO = "/home/dhgia/Work/Defi/BFBG-Transformer"
CONFIG = os.path.join(REPO, "docs", "v3_eval_config.json")
CONFIG_HASH = "a7945f94dc33c78428faa94c582ec48477dcf3dfb1c89679efdf58172e386b1c"
LOCK = os.path.expanduser("~/bfbg_benign_work/eval_v3.lock")
RESULT = os.path.expanduser("~/bfbg_benign_work/eval_v3_result.json")
BINS = ["MSVC<=10", "MSVC 11-12", "MSVC 14", "GNU/MinGW", "Go", "Delphi", "khac"]

# ---------- metric helpers (duoc selftest kiem) ----------
def wilson_ci(k, n, z=1.96):
    if n == 0: return (float("nan"), float("nan"))
    p = k / n; d = 1 + z*z/n
    c = (p + z*z/(2*n)) / d; half = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n)) / d
    return (max(0, c-half), min(1, c+half))

def tpr95_threshold(pos_scores):
    """Nguong sao cho ~95% positive >= nguong = percentile thu 5 cua positive scores."""
    import numpy as np
    return float(np.percentile(np.asarray(pos_scores, float), 5))

def fpr_at(neg_scores, thr):
    import numpy as np
    neg = np.asarray(neg_scores, float)
    return float((neg >= thr).mean()) if len(neg) else float("nan")

def fpr_by_bin(neg_scores, neg_bins, thr):
    import numpy as np
    out = {}
    neg = np.asarray(neg_scores, float); nb = np.asarray(neg_bins, object)
    for b in BINS:
        m = nb == b; n = int(m.sum())
        if n == 0: continue
        k = int((neg[m] >= thr).sum()); lo, hi = wilson_ci(k, n)
        out[b] = {"n": n, "fpr": k/n, "wilson": [lo, hi]}
    return out

def auc_score(y, s):
    from sklearn.metrics import roc_auc_score
    return float(roc_auc_score(y, s)) if len(set(y)) > 1 else float("nan")

def cluster_bootstrap_auc(y, s, cl, n=2000, seed=20261008):
    import numpy as np
    y = np.asarray(y); s = np.asarray(s, float); cl = np.asarray(cl, object)
    uc = np.unique(cl); rng = np.random.RandomState(seed); idx = {c: np.where(cl == c)[0] for c in uc}; v = []
    for _ in range(n):
        ii = np.concatenate([idx[c] for c in rng.choice(uc, len(uc), replace=True)])
        if len(set(y[ii])) > 1:
            from sklearn.metrics import roc_auc_score
            v.append(roc_auc_score(y[ii], s[ii]))
    v = np.array(v)
    return (float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))) if len(v) else (float("nan"), float("nan"))

def verify_config():
    h = hashlib.sha256(open(CONFIG, "rb").read()).hexdigest()
    if h != CONFIG_HASH:
        raise SystemExit(f"CONFIG_HASH khong khop! file={h} expect={CONFIG_HASH} -> TU CHOI")
    return json.load(open(CONFIG))

def check_lock():
    if os.path.exists(LOCK):
        prev = open(LOCK).read().strip()
        raise SystemExit(f"DA CHAM v3 roi (lock ton tai): {LOCK}\n  {prev}\n-> TU CHOI chay lan hai. v3 chi cham MOT lan.")

def write_lock(result_hash):
    import datetime
    with open(LOCK, "w") as f:
        f.write(json.dumps({"config_hash": CONFIG_HASH, "result_hash": result_hash,
                            "at": datetime.datetime.now().isoformat()}) + "\n")

# ---------- selftest tren DU LIEU GIA (khong cham v3) ----------
def selftest():
    import numpy as np, tempfile
    print("[selftest] kiem metric + lock tren du lieu gia (KHONG cham v3)...")
    rng = np.random.RandomState(0)
    pos = rng.normal(0.8, 0.1, 200).clip(0, 1)      # train positives (de tinh nguong OOF gia)
    thr = tpr95_threshold(pos)
    neg = rng.normal(0.3, 0.2, 166).clip(0, 1)      # v3 benign gia
    negbins = rng.choice(BINS, 166)
    fpr = fpr_at(neg, thr); bb = fpr_by_bin(neg, negbins, thr)
    assert 0 <= fpr <= 1 and all(0 <= v["fpr"] <= 1 for v in bb.values())
    # AUC gia: positives(1) vs v3(0)
    y = np.r_[np.ones(262), np.zeros(166)]; s = np.r_[rng.normal(0.7,0.2,262), rng.normal(0.4,0.2,166)].clip(0,1)
    cl = np.r_[np.arange(262), np.arange(166)+1000]
    a = auc_score(y, s); lo, hi = cluster_bootstrap_auc(y, s, cl, n=200)
    assert 0 <= a <= 1 and lo <= hi
    lk, nn = 3, 20; wlo, whi = wilson_ci(lk, nn); assert 0 <= wlo <= whi <= 1
    # lock plumbing tren file tam
    global LOCK; real = LOCK; LOCK = os.path.join(tempfile.mkdtemp(), "eval_v3.lock")
    try:
        check_lock()  # chua co -> ok
        write_lock("dummyhash")
        try: check_lock(); raise AssertionError("lock le ra phai chan lan hai")
        except SystemExit: pass  # dung: bi chan
        print(f"[selftest] thr={thr:.3f} fpr={fpr:.3f} bins={len(bb)} auc={a:.3f} ci[{lo:.3f},{hi:.3f}] wilson[{wlo:.2f},{whi:.2f}] lock=OK")
    finally: LOCK = real
    print("[selftest] PASS (plumbing OK, chua cham v3).")

# ---------- cham THAT (chi khi --run; khong chay trong prompt nay) ----------
def run_real():
    cfg = verify_config(); check_lock()
    import numpy as np, torch, pefile
    sys.path.insert(0, REPO); os.chdir(REPO)
    from src.training.splits import by_split, group_key
    from src.training.bfbg_dataset import BFBGDataset, collate
    from src.models.bfbg_transformer import BFBGTransformer
    from torch.utils.data import DataLoader
    from sklearn.ensemble import RandomForestClassifier
    # ... (duong cham that: train 5 model tren v2 train_pool, nguong OOF, cham v3+BumbleBee,
    #      FPR-by-bin + AUC). Code day du o ban cuoi; CHUA CHAY trong prompt nay nen de placeholder an toan.)
    raise SystemExit("run_real(): duong cham that da dinh nghia khung; chi hoan thien+chay khi nguoi dung noi 'chay'. "
                     "Hien tai chan de khong vo tinh cham v3.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--run", action="store_true", help="CHAM THAT v3 (chi khi nguoi dung noi 'chay')")
    A = ap.parse_args()
    if A.selftest: selftest(); return
    if A.run: run_real(); return
    print("eval_v3.py: KHONG lam gi mac dinh. `--selftest` de test gia; `--run` de cham that (chi khi duoc lenh 'chay').")
    print(f"  CONFIG_HASH={CONFIG_HASH}  lock={LOCK} (ton tai={os.path.exists(LOCK)})")

if __name__ == "__main__":
    main()
