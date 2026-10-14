# References to verify (fill DOI/venue yourself — NOT filled from memory)

Candidate citations for the shortcut-audit paper. Each row lists only what is plausibly known;
**DOI/URL and exact venue/pages are LEFT BLANK for you to verify** before adding to `references.bib`
and before any `\cite`. Do not add an entry to `\cite` until confirmed.

| key (suggested) | authors (approx) | title (approx) | venue/year (approx) | DOI/URL (FILL) | verified? |
|---|---|---|---|---|---|
| arp2022dodo | Arp, Quiring, Pendlebury, Warnecke, Pierazzi, Wressnegger, Cavallaro, Rieck | Dos and Don'ts of Machine Learning in Computer Security | USENIX Security, 2022 | ____________ | [ ] |
| anderson2018ember | Anderson, Roth | EMBER: An Open Dataset for Training Static PE Malware ML Models | arXiv / 2018 (preprint) | ____________ | [ ] |
| raff2018malconv | Raff, Barker, Sylvester, Brandon, Catanzaro, Nicholas | Malware Detection by Eating a Whole EXE | AAAI Workshop(?) / 2018 | ____________ | [ ] |
| pendlebury2019tesseract | Pendlebury, Pierazzi, Jordaney, Kinder, Cavallaro | TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time | USENIX Security, 2019 | ____________ | [ ] |
| (shortcut-learning) | Geirhos et al. | Shortcut Learning in Deep Neural Networks | Nature Machine Intelligence(?) / 2020 | ____________ | [ ] |
| (near-dup leakage) | ??? | Near-duplicate / temporal leakage in malware datasets | ??? | ____________ | [ ] |
| (ppdeep / ssdeep) | Kornblum | Identifying almost identical files using context triggered piecewise hashing (ssdeep) | DFRWS / 2006 | ____________ | [ ] |
| (angr) | Shoshitaishvili et al. | SoK: (State of) The Art of War: Offensive Techniques in Binary Analysis (angr) | IEEE S&P / 2016 | ____________ | [ ] |

## Notes
- The topic buckets requested: EMBER, MalConv, confound/shortcut learning in ML-based malware
  detection, and near-duplicate / dataset-leakage in malware benchmarking. The last two buckets
  need a concrete citation each; placeholders above are starting points, not confirmed works.
- Rule: no fabricated DOIs. Only `arp2022dodo` is currently cited in `main.tex`; its DOI/pages are
  still marked TODO-VERIFY in `references.bib`. All other rows are NOT cited until you verify them.
- When verified, add a proper BibTeX entry to the paper's `references.bib` (in the paper repo) and
  switch the corresponding `\cite`.
