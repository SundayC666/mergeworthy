# Results (runs/, 45 records)

## Per model

| model | runs | not applied | not fixed | fixed, broke | fixed, clean | errors | median s | in tok | out tok | cost $ |
|---|---|---|---|---|---|---|---|---|---|---|
| claude-sonnet-5 | 11 | 4/11 (36%) | 3/11 (27%) | 0/11 (0%) | 4/11 (36%) | 4 | 21.3 | 3964 | 2069 | 0.1556 |
| gpt-5.3-codex | 11 | 2/11 (18%) | 5/11 (45%) | 0/11 (0%) | 4/11 (36%) | 4 | 11.2 | 2486 | 491 | 0.1108 |
| gpt-oss-120b | 12 | 12/12 (100%) | 0/12 (0%) | 0/12 (0%) | 0/12 (0%) | 3 | 10.4 | 2459 | 1178 | 0.0373 |

## Model × case

| model | CVE-2026-24486 | CVE-2026-26331 | CVE-2026-32714 | CVE-2026-33175 | GHSA-r758-8hxw-4845 |
|---|---|---|---|---|---|
| claude-sonnet-5 | error ×1, fixed, clean ×1, not fixed ×1 | error ×1, not fixed ×2 | fixed, clean ×3 | not applied ×3 | error ×2, not applied ×1 |
| gpt-5.3-codex | error ×1, fixed, clean ×1, not fixed ×1 | error ×1, not fixed ×2 | fixed, clean ×3 | error ×1, not applied ×2 | error ×1, not fixed ×2 |
| gpt-oss-120b | error ×1, not applied ×2 | not applied ×3 | not applied ×3 | error ×1, not applied ×2 | error ×1, not applied ×2 |

## Why patches did not apply

| model | reason | n |
|---|---|---|
| claude-sonnet-5 | (of which whitespace-only) | 1 |
| claude-sonnet-5 | git-apply-failed | 4 |
| gpt-5.3-codex | git-apply-failed | 2 |
| gpt-oss-120b | git-apply-failed | 12 |

## Scanner (Bandit) vs verdict

| scanner | not applied | not fixed | fixed, broke | fixed, clean |
|---|---|---|---|---|
| saw it; went quiet | 0 | 0 | 0 | 6 |
| saw it; still alerting | 0 | 4 | 0 | 0 |
| saw it; patch not applied | 6 | 0 | 0 | 0 |
| scanner blind before patch | 12 | 4 | 0 | 2 |

Scanner results are recorded only; they never decide an outcome (§5).
