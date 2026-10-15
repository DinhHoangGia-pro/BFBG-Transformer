# Holdout v4 — toolchain x size matched benign estimate (counts only, NOT collected)

Goal: a confound-matched benign holdout that mirrors the malware toolchain x size distribution, so
detection cannot trivially separate benign from malicious by toolchain or size. Counts below are from
`feat_cache.jsonl` (v1/v2, which carry `file_size`) + `dataset_v3_manifest.jsonl` (v3 benign, bins
only; v3 has no `file_size` in the manifest). No samples downloaded; this is an availability estimate.

Size buckets: `<256KB`, `256KB-1MB`, `1-4MB`, `4-12MB`, `>12MB`. Bins: MSVC<=10 / 11-12 / 14 /
GNU-MinGW / Go / Delphi / other.

## Malware (v1/v2, n=1382) by bin x size
| bin | <256KB | 256KB-1MB | 1-4MB | 4-12MB | >12MB | tot |
|---|---|---|---|---|---|---|
| MSVC<=10 | 27 | 634 | 19 | 1 | 0 | 681 |
| MSVC 11-12 | 15 | 30 | 27 | 0 | 0 | 72 |
| MSVC 14 | 33 | 275 | 248 | 10 | 0 | 566 |
| GNU/MinGW | 5 | 12 | 1 | 0 | 0 | 18 |
| Go | 4 | 3 | 0 | 1 | 0 | 8 |
| Delphi | 5 | 3 | 6 | 0 | 0 | 14 |
| other | 6 | 11 | 5 | 1 | 0 | 23 |

## Benign available (v1/v2, n=504) by bin x size
| bin | <256KB | 256KB-1MB | 1-4MB | 4-12MB | >12MB | tot |
|---|---|---|---|---|---|---|
| MSVC<=10 | 60 | 23 | 13 | 1 | 0 | 97 |
| MSVC 11-12 | 0 | 6 | 3 | 0 | 0 | 9 |
| MSVC 14 | 117 | 57 | 87 | 43 | 0 | 304 |
| GNU/MinGW | 4 | 9 | 15 | 12 | 0 | 40 |
| Go | 8 | 1 | 10 | 14 | 0 | 33 |
| Delphi | 0 | 0 | 1 | 1 | 0 | 2 |
| other | 4 | 6 | 6 | 3 | 0 | 19 |

v3 benign (165, bins only): MSVC<=10 74, MSVC 14 41, other 21, Go 17, GNU/MinGW 8, Delphi 4.

## Shortfall to match malware 1:1 per cell (benign needed − available)
Largest gaps:
- **MSVC<=10 x 256KB-1MB: need +611** (mal 634, benign 23) — the dominant gap (NirSoft-style small
  MSVC utilities are large benign but in a different size cell).
- **MSVC 14 x 256KB-1MB: +218**, **MSVC 14 x 1-4MB: +161**.
- MSVC 11-12: +15 / +24 / +24 across the three smaller buckets.
- Delphi: +5 / +3 / +5; GNU/MinGW +1/+3; Go +2; other +2/+5.
- **Total benign shortfall to match malware 1:1 by cell: ~1085** (v1/v2 only; v3 adds benign by bin
  but without size cells).

## Implication for v4
- A strictly matched v4 needs ~1085 additional benign concentrated in MSVC<=10 and MSVC 14 at
  256KB-1MB / 1-4MB. That is a large, targeted collection (and the easiest-to-find benign tend to
  land in different size cells), so full 1:1 matching is likely infeasible without heavy effort.
- A weaker but useful target: per-bin stratified matching (ignore size) or reweighting during
  evaluation. This estimate is to inform that choice; nothing is collected.
