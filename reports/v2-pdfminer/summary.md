# Results (runs-v2/, 9 records)

## Per model

| model | runs | not applied | not fixed | fixed, broke | fixed, clean | errors | median s | in tok | out tok | cost $ |
|---|---|---|---|---|---|---|---|---|---|---|
| claude-sonnet-5 | 3 | 0/3 (0%) | 0/3 (0%) | 1/3 (33%) | 2/3 (67%) | 0 | 30.4 | 8962 | 1068 | 0.0169 |
| gpt-5.3-codex | 3 | 0/3 (0%) | 0/3 (0%) | 1/3 (33%) | 2/3 (67%) | 0 | 21.7 | 5621 | 402 | 0.0309 |
| gpt-oss-120b | 3 | 3/3 (100%) | 0/3 (0%) | 0/3 (0%) | 0/3 (0%) | 0 | 16.7 | 5685 | 1315 | – |

## Model × case

| model | CVE-2025-64512 |
|---|---|
| claude-sonnet-5 | fixed, clean ×2, fixed, broke ×1 |
| gpt-5.3-codex | fixed, clean ×2, fixed, broke ×1 |
| gpt-oss-120b | not applied ×3 |

## Why patches did not apply

| model | reason | n |
|---|---|---|
| gpt-oss-120b | git-apply-failed | 3 |

## Scanner (Bandit) vs verdict

| scanner | not applied | not fixed | fixed, broke | fixed, clean |
|---|---|---|---|---|
| saw it; went quiet | 0 | 0 | 0 | 0 |
| saw it; still alerting | 0 | 0 | 2 | 4 |
| saw it; patch not applied | 3 | 0 | 0 | 0 |
| scanner blind before patch | 0 | 0 | 0 | 0 |

Scanner results are recorded only; they never decide an outcome (§5).
