# Limitations and Threats to Validity (draft, English)

These limitations bound every claim in the study. They are stated plainly; none is a reason to
re-interpret the committed numbers.

1. **Benign labels are not externally verified.** Benign status is provenance-based (reputable
   repositories: Windows ISO, Chocolatey, Scoop, NirSoft). We did **not** check the benign programs
   with an external multi-scanner service (e.g. a VirusTotal-style aggregator). Mislabelled benign
   samples cannot be ruled out and would affect false-positive counts.

2. **The MSVC<=10 bin is dominated by NirSoft.** A large share of the MSVC<=10 benign are NirSoft
   utilities, so per-bin numbers for that bin confound *vendor* with *toolchain*. Any within-bin
   reading of MSVC<=10 is therefore not a clean toolchain-controlled comparison.

3. **A single BFBG fold / limited seeds.** The BFBG results come from one family-holdout fold
   (BumbleBee held out) and a small seed set (four seeds per variant). They characterise the
   configurations we actually ran; they are **not** an estimate of the architecture's best achievable
   performance, and seed variance is non-trivial.

4. **v3 contains negatives only.** The held-out set v3 is benign-only (165 programs), so AUC is
   computed against pre-registered BumbleBee positives that are **not** drawn from the training pool.
   Because v3 has no positives, FPR is read only *within* a model (across bins), never to rank models,
   and the absolute operating point depends on a threshold fixed on training data.

5. **One sample removed after freezing.** A single v3 benign sample (a large Qt core library,
   `Qt6Core.dll`) was removed after the manifest was frozen because its feature file had been
   truncated by an infrastructure interruption during construction. No model had produced any v3 score
   before the removal; the change is recorded with new manifest and config hashes (FREEZE_v3). We flag
   this as a deviation from strict pre-registration.

6. **The metadata probe can exploit within-bin linker/year signal.** Even within a single toolchain
   bin, the metadata features include minor-linker version, compile year and section statistics, so the
   metadata probe may separate benign from malicious using *within-bin* linker/year differences rather
   than toolchain identity. We therefore treat "metadata is strong because of toolchain" as a
   **hypothesis**, not a finding; distinguishing it would require confound-matched benign data.

## Scope of claims (restated)
We do **not** claim that the model learns program behaviour, that it outperforms or beats the
baselines, that PE metadata is a better malware detector, or that any single confound is the cause of
the observed separation. The audit reports associations on a specific, frozen benchmark; mechanisms
remain hypotheses pending confound-matched benign data and external label verification.
