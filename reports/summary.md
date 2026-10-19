# Results (runs/, 56 records)

## Per model

| model | runs | not applied | not fixed | fixed, broke | fixed, clean | errors | median s | in tok | out tok | cost $ |
|---|---|---|---|---|---|---|---|---|---|---|
| claude-sonnet-5 | 13 | 4/13 (31%) | 4/13 (31%) | 0/13 (0%) | 5/13 (38%) | 6 | 23.1 | 3615 | 1815 | 0.3429 |
| gpt-5.3-codex | 15 | 3/15 (20%) | 7/15 (47%) | 0/15 (0%) | 5/15 (33%) | 4 | 11.5 | 2184 | 441 | 0.1151 |
| gpt-oss-120b | 15 | 15/15 (100%) | 0/15 (0%) | 0/15 (0%) | 0/15 (0%) | 3 | 9.6 | 2248 | 1215 | 0.0373 |

## Model × case

| model | CVE-2026-24486 | CVE-2026-26331 | CVE-2026-32714 | CVE-2026-33175 | GHSA-r758-8hxw-4845 |
|---|---|---|---|---|---|
| claude-sonnet-5 | error ×1, fixed, clean ×2, not fixed ×1 | error ×1, not fixed ×3 | fixed, clean ×3 | not applied ×3 | error ×4, not applied ×1 |
| gpt-5.3-codex | error ×1, fixed, clean ×2, not fixed ×1 | error ×1, not fixed ×3 | fixed, clean ×3 | error ×1, not applied ×3 | error ×1, not fixed ×3 |
| gpt-oss-120b | error ×1, not applied ×3 | not applied ×3 | not applied ×3 | error ×1, not applied ×3 | error ×1, not applied ×3 |

## Why patches did not apply

| model | reason | n |
|---|---|---|
| claude-sonnet-5 | (of which whitespace-only) | 1 |
| claude-sonnet-5 | git-apply-failed | 4 |
| gpt-5.3-codex | git-apply-failed | 3 |
| gpt-oss-120b | git-apply-failed | 15 |

## Scanner (Bandit) vs verdict

| scanner | not applied | not fixed | fixed, broke | fixed, clean |
|---|---|---|---|---|
| saw it; went quiet | 0 | 0 | 0 | 6 |
| saw it; still alerting | 0 | 6 | 0 | 0 |
| saw it; patch not applied | 6 | 0 | 0 | 0 |
| scanner blind before patch | 16 | 5 | 0 | 4 |

Scanner results are recorded only; they never decide an outcome (§5).
