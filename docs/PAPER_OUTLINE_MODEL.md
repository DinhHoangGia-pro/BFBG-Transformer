# Paper outline — MODEL-FIRST direction

> **Working title (not final):** "Toolchain-Invariant Hierarchical Graph Transformers for Static
> Banking-Trojan Detection". The name is a *working* title; it is confirmed only after results.
> **Rename condition:** if the invariance criteria (see GRL_DESIGN.md) are NOT met — i.e. the
> toolchain/family linear probe does not fall near chance, or cross-source AUC drops beyond the
> pre-registered threshold — the paper reverts to the measurement/benchmark framing
> ("A Shortcut-Aware Evaluation Protocol and Benchmark ..."; see PAPER_OUTLINE_B.md, kept as history).
> Nothing here is a result yet; the invariant model is PROPOSED, not demonstrated.

## Thesis (one sentence)
A hierarchical graph-transformer for static PE banking-trojan detection can be trained to be
*toolchain-invariant* — via adversarial gradient reversal plus learned function selection — so that
its decision relies less on toolchain/size/token confounds, and we measure this with a toolchain-swap
test while keeping cross-source AUC within a pre-registered margin.

## Contributions (3)
1. **Toolchain-invariant model.** Add an adversarial head (gradient reversal) that predicts
   toolchain (and optionally family) from the program embedding; train the detector to make that
   embedding *non-predictive* of toolchain while preserving detection. Success is pre-registered
   (GRL_DESIGN.md), not assumed.
2. **Learned function selection** replacing the fixed first-150-functions-by-address window (which
   discards 77--100% of the rule-based seed evidence; see dev tables). Select functions by a learned
   or API-density saliency so the model input covers the behavioural evidence rather than the first
   addresses. (API-density is a label-free candidate already measured; a learned selector is the goal.)
3. **Toolchain-swap test + shortcut-aware evaluation protocol as the instrument.** The frozen,
   cluster-split benchmark with cross-source benign holdouts, OOF thresholds, probe baselines and
   bin-wise AUC/FPR is reused as the *measurement* of invariance (does swapping toolchain change the
   score?); the protocol is a means, not the headline.

## Section structure
1. Introduction (confounds motivate an invariant model; RQ: can we remove toolchain dependence
   without losing cross-source AUC?).
2. Scope and Threat Model (static, native PE x86/x86-64; .NET out of scope; five families).
3. Benchmark and Protocol (frozen manifests/hashes, cluster split, cross-source holdout, OOF
   thresholds, probe baselines, bin-wise reporting; the measurement instrument).
4. Method: toolchain-invariant model (gradient reversal) + learned function selection.
5. Experiments (motivating measurements [committed]; proposed invariance results [pending]).
6. Toolchain-swap / invariance evaluation (linear-probe near chance; cross-source AUC margin).
7. Discussion; 8. Limitations and Threats to Validity; 9. Reproducibility and Artifact.

## Tables / figures (each names its script)
- T1 dev baselines + BFBG 4-seed — `export_paper_tables.py` (dev_bfbg_4seed, dev_lofo_5family, dev_within_msvc14).
- T2 input-window seed coverage — `export_paper_tables.py` (dev_seed_cut).
- T3 held-out v3 AUC + FPR-by-bin — READ from `docs/v3_eval_result.json` (not recomputed).
- T4 [PENDING] invariance: toolchain/family linear-probe accuracy before/after GRL — new script.
- T5 [PENDING] cross-source AUC before/after GRL + learned selection — new script.
- F1 benign vs malware bin x size coverage (motivates v4) — `HOLDOUT_V4_MATCH_ESTIMATE.md` data.

## Status / honesty
- Motivating measurements are committed and reproducible. The *model* contributions (C1, C2) and
  tables T4/T5 are PENDING a training run that is not started (GRL_DESIGN.md; ask before training).
- Until T4/T5 exist, the paper cannot claim invariance; the working title is provisional.
