# Results (runs/, 53 records)

## Per model

| model | runs | not applied | not fixed | fixed, broke | fixed, clean | errors | median s | in tok | out tok | cost $ |
|---|---|---|---|---|---|---|---|---|---|---|
| claude-sonnet-5 | 13 | 4/13 (31%) | 4/13 (31%) | 0/13 (0%) | 5/13 (38%) | 6 | 23.1 | 3615 | 1815 | 0.3429 |
| gpt-5.3-codex | 13 | 2/13 (15%) | 6/13 (46%) | 0/13 (0%) | 5/13 (38%) | 4 | 11.2 | 2337 | 472 | 0.115 |
| gpt-oss-120b | 14 | 14/14 (100%) | 0/14 (0%) | 0/14 (0%) | 0/14 (0%) | 3 | 10.4 | 2334 | 1214 | 0.0373 |

## Model × case

| model | CVE-2026-24486 | CVE-2026-26331 | CVE-2026-32714 | CVE-2026-33175 | GHSA-r758-8hxw-4845 |
|---|---|---|---|---|---|
| claude-sonnet-5 | error ×1, fixed, clean ×2, not fixed ×1 | error ×1, not fixed ×3 | fixed, clean ×3 | not applied ×3 | error ×4, not applied ×1 |
| gpt-5.3-codex | error ×1, fixed, clean ×2, not fixed ×1 | error ×1, not fixed ×2 | fixed, clean ×3 | error ×1, not applied ×2 | error ×1, not fixed ×3 |
| gpt-oss-120b | error ×1, not applied ×3 | not applied ×3 | not applied ×3 | error ×1, not applied ×2 | error ×1, not applied ×3 |

## Why patches did not apply

| model | reason | n |
|---|---|---|
| claude-sonnet-5 | (of which whitespace-only) | 1 |
| claude-sonnet-5 | git-apply-failed | 4 |
| gpt-5.3-codex | git-apply-failed | 2 |
| gpt-oss-120b | git-apply-failed | 14 |

## Scanner (Bandit) vs verdict

| scanner | not applied | not fixed | fixed, broke | fixed, clean |
|---|---|---|---|---|
| saw it; went quiet | 0 | 0 | 0 | 6 |
| saw it; still alerting | 0 | 5 | 0 | 0 |
| saw it; patch not applied | 6 | 0 | 0 | 0 |
| scanner blind before patch | 14 | 5 | 0 | 4 |

Scanner results are recorded only; they never decide an outcome (§5).
