# Results (runs/, 101 records)

## Per model

| model | runs | not applied | not fixed | fixed, broke | fixed, clean | errors | median s | in tok | out tok | cost $ |
|---|---|---|---|---|---|---|---|---|---|---|
| claude-sonnet-5 | 28 | 7/28 (25%) | 5/28 (18%) | 1/28 (4%) | 15/28 (54%) | 6 | 24.8 | 2798 | 1284 | 0.4275 |
| gpt-5.3-codex | 30 | 7/30 (23%) | 7/30 (23%) | 1/30 (3%) | 15/30 (50%) | 4 | 16.1 | 1724 | 399 | 0.181 |
| gpt-oss-120b | 30 | 30/30 (100%) | 0/30 (0%) | 0/30 (0%) | 0/30 (0%) | 3 | 11.0 | 1788 | 1161 | 0.0865 |

## Model × case

| model | CVE-2025-64512 | CVE-2026-22250 | CVE-2026-24486 | CVE-2026-26331 | CVE-2026-32714 | CVE-2026-33175 | CVE-2026-35171 | CVE-2026-42215 | CVE-2026-44502 | GHSA-r758-8hxw-4845 |
|---|---|---|---|---|---|---|---|---|---|---|
| claude-sonnet-5 | fixed, clean ×2, fixed, broke ×1 | fixed, clean ×2, not fixed ×1 | error ×1, fixed, clean ×2, not fixed ×1 | error ×1, not fixed ×3 | fixed, clean ×3 | not applied ×3 | not applied ×3 | fixed, clean ×3 | fixed, clean ×3 | error ×4, not applied ×1 |
| gpt-5.3-codex | fixed, clean ×1, fixed, broke ×1, not applied ×1 | fixed, clean ×3 | error ×1, fixed, clean ×2, not fixed ×1 | error ×1, not fixed ×3 | fixed, clean ×3 | error ×1, not applied ×3 | not applied ×3 | fixed, clean ×3 | fixed, clean ×3 | error ×1, not fixed ×3 |
| gpt-oss-120b | not applied ×3 | not applied ×3 | error ×1, not applied ×3 | not applied ×3 | not applied ×3 | error ×1, not applied ×3 | not applied ×3 | not applied ×3 | not applied ×3 | error ×1, not applied ×3 |

## Why patches did not apply

| model | reason | n |
|---|---|---|
| claude-sonnet-5 | (of which whitespace-only) | 1 |
| claude-sonnet-5 | git-apply-failed | 7 |
| gpt-5.3-codex | git-apply-failed | 7 |
| gpt-oss-120b | git-apply-failed | 30 |

## Scanner (Bandit) vs verdict

| scanner | not applied | not fixed | fixed, broke | fixed, clean |
|---|---|---|---|---|
| saw it; went quiet | 0 | 0 | 0 | 6 |
| saw it; still alerting | 0 | 6 | 2 | 9 |
| saw it; patch not applied | 13 | 0 | 0 | 0 |
| scanner blind before patch | 31 | 6 | 0 | 15 |

Scanner results are recorded only; they never decide an outcome (§5).
