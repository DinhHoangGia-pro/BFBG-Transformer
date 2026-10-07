"""Baseline probes (metadata + graph-feature) tren CUNG split/CV voi BFBG sau nay.
Streaming: trich feature tung mau (pefile raw + JSON), cache; RF; eval test_indist,
holdout_choco, holdout_bumblebee + group-kfold CV tren train_pool. Metrics: AUC,
PR-AUC, balanced-acc, FPR@TPR95, cluster-bootstrap CI. CHUA train BFBG."""
import os, sys, json, math, warnings
warnings.filterwarnings('ignore'); import numpy as np, pefile
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
from src.utils.path_resolver import REPO_ROOT
from src.training.splits import load_manifest, by_split, group_kfold, group_key
from src.training.metrics import pr_auc, balanced_acc, fpr_at_tpr, cluster_bootstrap_ci, wilson_ci

CACHE = os.path.expanduser('~/bfbg_benign_work/feat_cache.jsonl')
SECDIR = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
STD = {'.text','.data','.rdata','.rsrc','.reloc','.bss','.idata','.edata','.pdata','.tls','.gfids','.didat','.crt','.xdata','.rodata'}

def extract(sha, label):
    raw = os.path.join(REPO_ROOT, 'data/raw', 'malicious' if label==1 else 'benign', sha)
    jp  = os.path.join(REPO_ROOT, 'data/features_graph', f'{sha}_static.json')
    if not (os.path.exists(raw) and os.path.exists(jp)): return None
    import datetime
    pe = pefile.PE(raw)
    try:
        oh, fh = pe.OPTIONAL_HEADER, pe.FILE_HEADER
        dd = oh.DATA_DIRECTORY
        has_sig = 1 if (SECDIR < len(dd) and dd[SECDIR].Size > 0) else 0
        linker = oh.MajorLinkerVersion + oh.MinorLinkerVersion/100.0
        ts = fh.TimeDateStamp; year = 0
        if 0 < ts < 2**31:
            try: year = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).year
            except Exception: year = 0
        has_rich = 1 if getattr(pe,'RICH_HEADER',None) else 0
        secs = [s.Name.rstrip(b'\x00').decode('latin1','ignore') for s in pe.sections]
        n_sec = len(secs); nonstd = sum(1 for s in secs if s.lower() not in STD)
        try: max_ent = max((s.get_entropy() for s in pe.sections), default=0.0)
        except Exception: max_ent = 0.0
        fsize = os.path.getsize(raw)
        imps = set()
        if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
            for e in pe.DIRECTORY_ENTRY_IMPORT:
                if e.dll: imps.add(e.dll.decode('latin1','ignore').lower())
    finally: pe.close()
    sset = set(secs); lk = int(linker)
    if '.buildid' in sset or '.symtab' in sset: tbin='Go'
    elif 'CODE' in sset or 'DATA' in sset or '.itext' in sset: tbin='Delphi'
    elif '.eh_fram' in sset or any(d in ' '.join(imps) for d in ('libgcc','mingw','msys-')) or (lk<=2 and not has_rich and '.bss' in sset and ('.CRT' in sset or {'.edata','.pdata'}<=sset)): tbin='GNU/MinGW'
    elif has_rich or any(d in ' '.join(imps) for d in ('ucrtbase','vcruntime','api-ms-win-crt')) or ('msvcrt.dll' in imps and lk>=6):
        tbin = 'MSVC<=10' if lk<=10 else ('MSVC 11-12' if lk in (11,12) else 'MSVC 14')
    else: tbin='khac'
    d = json.load(open(jp)); si = d.get('structural_indicators',{})
    tn = sum(len(g.get('nodes',[])) for g in d.get('intra_procedural_graphs',{}).values())
    meta = [has_sig, linker, year, has_rich, n_sec, nonstd, max_ent, math.log10(max(fsize,1))]
    graph= [d.get('num_functions',0), d.get('num_api_calls',0), d.get('num_imports',0), fsize,
            si.get('max_section_entropy',0.0), 1 if si.get('is_likely_packed') else 0, tn]
    return dict(meta=meta, graph=graph, tbin=tbin)

def build_cache():
    man = load_manifest()
    if os.path.exists(CACHE):
        done = {json.loads(l)['sha256'] for l in open(CACHE)}
    else: done = set()
    with open(CACHE,'a') as out:
        for i,r in enumerate(man):
            if r['sha256'] in done: continue
            f = extract(r['sha256'], r['label'])
            if f is None: continue
            out.write(json.dumps({'sha256':r['sha256'],'label':r['label'],'split':r['split'],
                      'source':r['source'],'cluster':group_key(r), **f})+'\n')
            if (i+1)%300==0: print(f'...{i+1}', flush=True)
    return [json.loads(l) for l in open(CACHE)]

META=['has_sig','linker','year','has_rich','n_sec','nonstd_sec','max_ent','log_size']
GRAPH=['num_functions','num_api_calls','num_imports','file_size','max_section_entropy','is_likely_packed','total_nodes']

def run():
    rows = build_cache()
    idx = {r['sha256']: r for r in rows}
    man = load_manifest(); sp = by_split([r for r in man if r['sha256'] in idx])
    def mat(recs, which): return np.array([idx[r['sha256']][which] for r in recs], float)
    def y(recs): return np.array([r['label'] for r in recs])
    tr = sp['train_pool']
    print(f"train_pool={len(tr)} test_indist={len(sp['test_indist'])} "
          f"holdout_choco={len(sp.get('holdout_source_chocolatey',[]))} "
          f"holdout_bumblebee={len(sp.get('holdout_family_bumblebee',[]))}")
    for name, which in [('metadata', 'meta'), ('graph', 'graph')]:
        print(f"\n===== PROBE: {name} =====")
        Xtr, ytr = mat(tr, which), y(tr)
        # group-kfold CV tren train_pool
        folds = group_kfold(tr, k=5)
        aucs=[]; aps=[]
        for fv in folds:
            trn=[r for r in tr if r['sha256'] not in fv]; val=[r for r in tr if r['sha256'] in fv]
            if len(set(y(val)))<2: continue
            clf=RandomForestClassifier(n_estimators=200,random_state=42,n_jobs=-1,class_weight='balanced').fit(mat(trn,which),y(trn))
            s=clf.predict_proba(mat(val,which))[:,1]
            aucs.append(roc_auc_score(y(val),s)); aps.append(pr_auc(y(val),s))
        print(f"  CV(train_pool) AUC={np.mean(aucs):.3f}±{np.std(aucs):.3f}  PR-AUC={np.mean(aps):.3f}")
        clf=RandomForestClassifier(n_estimators=300,random_state=42,n_jobs=-1,class_weight='balanced').fit(Xtr,ytr)
        # threshold @ TPR95 tren test_indist positives
        ti=sp['test_indist']; sti=clf.predict_proba(mat(ti,which))[:,1]
        _,thr=fpr_at_tpr(y(ti),sti,0.95)
        def evalset(recs, tag):
            if not recs: return
            s=clf.predict_proba(mat(recs,which))[:,1]; yy=y(recs)
            auc=roc_auc_score(yy,s) if len(set(yy))>1 else float('nan')
            ap=pr_auc(yy,s); ba=balanced_acc(yy,(s>=thr).astype(int))
            fpr=float((s[yy==0]>=thr).mean()) if (yy==0).any() else float('nan')
            rec=float((s[yy==1]>=thr).mean()) if (yy==1).any() else float('nan')
            boot=[{'cluster':group_key(r),'y':r['label'],'score':sc} for r,sc in zip(recs,s)]
            lo,hi=cluster_bootstrap_ci(boot, lambda a,b: float((b[a==0]>=thr).mean()) if (a==0).any() else float('nan'))
            nben=int((yy==0).sum()); fpk=int((s[yy==0]>=thr).sum()); wlo,whi=wilson_ci(fpk,nben)
            ndc=len(set(group_key(r) for r in recs))
            print(f"  {tag:24s} n={len(recs):4d} AUC={auc:.3f} PR-AUC={ap:.3f} balAcc={ba:.3f} "
                  f"FPR@TPR95={fpr*100 if fpr==fpr else float('nan'):.1f}% boot[{lo*100:.1f},{hi*100:.1f}] Wilson[{wlo*100:.1f},{whi*100:.1f}] cl={ndc} rec={rec*100 if rec==rec else float('nan'):.1f}%")
        evalset(ti,'test_indist')
        evalset(sp.get('holdout_source_chocolatey',[]),'holdout_choco(FPR)')
        evalset(sp.get('holdout_family_bumblebee',[]),'holdout_bumblebee(rec)')

if __name__=='__main__':
    run()
