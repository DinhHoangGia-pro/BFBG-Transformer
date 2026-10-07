"""Metrics: balanced accuracy, PR-AUC, FPR@TPR, cluster-bootstrap CI.
Cluster-bootstrap: resample theo CUM (near-dup) de CI trung thuc khi co trung lap."""
import numpy as np
from sklearn.metrics import average_precision_score, balanced_accuracy_score

def pr_auc(y, score):
    y = np.asarray(y)
    if len(set(y)) < 2:
        return float('nan')
    return float(average_precision_score(y, score))

def balanced_acc(y, yhat):
    return float(balanced_accuracy_score(y, yhat))

def fpr_at_tpr(y, score, tpr_target=0.95):
    """Nguong tai TPR>=tpr_target tren lop duong; tra ve (FPR, threshold)."""
    y = np.asarray(y); score = np.asarray(score)
    pos = score[y == 1]; neg = score[y == 0]
    if len(pos) == 0 or len(neg) == 0:
        return float('nan'), float('nan')
    thr = np.quantile(pos, 1.0 - tpr_target)   # TPR>=target: giu nguong <= phan vi (1-target) cua pos
    fpr = float((neg >= thr).mean())
    return fpr, float(thr)

def cluster_bootstrap_ci(records, metric_fn, B=2000, seed=1, lo=2.5, hi=97.5):
    """records: list dict co 'cluster','y','score'. Resample CUM co lap lai.
    metric_fn(y_array, score_array) -> float. Tra ve (lo, hi)."""
    from collections import defaultdict
    cl = defaultdict(list)
    for r in records:
        cl[r['cluster']].append((r['y'], r['score']))
    keys = list(cl)
    if not keys:
        return (float('nan'), float('nan'))
    rnd = np.random.default_rng(seed)
    vals = []
    for _ in range(B):
        pick = rnd.choice(len(keys), size=len(keys), replace=True)
        ys = []; ss = []
        for i in pick:
            for yv, sv in cl[keys[i]]:
                ys.append(yv); ss.append(sv)
        try:
            v = metric_fn(np.array(ys), np.array(ss))
        except Exception:
            v = float('nan')
        if v == v:  # not nan
            vals.append(v)
    if not vals:
        return (float('nan'), float('nan'))
    vals.sort()
    return (float(np.percentile(vals, lo)), float(np.percentile(vals, hi)))

def wilson_ci(k, n, z=1.96):
    import math
    if n == 0: return (float('nan'), float('nan'))
    ph = k/n; d = 1+z*z/n; c = (ph+z*z/(2*n))/d
    h = (z/d)*math.sqrt(ph*(1-ph)/n + z*z/(4*n*n))
    return (max(0.0, c-h), min(1.0, c+h))
