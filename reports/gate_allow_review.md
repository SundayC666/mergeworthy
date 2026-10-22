# Gate `allow` review (2026-10-22)

The gate would open a PR for these runs with no human-review flag. Review each diff against the
official fix (`~/cve-bench/tasks/<case>/fix.patch`) and record whether you would merge it.
This is the only ground truth for the gate's precision. Fill the last two columns.

| # | case | project | model | run folder | diff ±lines | official ±lines | files | would merge? | why not |
|---|---|---|---|---|---|---|---|---|---|
| 1 | CVE-2026-32714 | scitokens | claude-sonnet-5 | `20261018T210315Z-CVE-2026-32714-claude-sonnet-5` | 29 | 165 | src/scitokens/utils/keycache.py | | |
| 2 | CVE-2026-32714 | scitokens | gpt-5.3-codex | `20261018T210335Z-CVE-2026-32714-gpt-5.3-codex` | 33 | 165 | src/scitokens/utils/keycache.py | | |
| 3 | CVE-2026-32714 | scitokens | claude-sonnet-5 | `20261018T210757Z-CVE-2026-32714-claude-sonnet-5` | 29 | 165 | src/scitokens/utils/keycache.py | | |
| 4 | CVE-2026-32714 | scitokens | gpt-5.3-codex | `20261018T210818Z-CVE-2026-32714-gpt-5.3-codex` | 33 | 165 | src/scitokens/utils/keycache.py | | |
| 5 | CVE-2026-32714 | scitokens | claude-sonnet-5 | `20261018T211002Z-CVE-2026-32714-claude-sonnet-5` | 33 | 165 | src/scitokens/utils/keycache.py | | |
| 6 | CVE-2026-32714 | scitokens | gpt-5.3-codex | `20261018T211025Z-CVE-2026-32714-gpt-5.3-codex` | 36 | 165 | src/scitokens/utils/keycache.py | | |
| 7 | CVE-2026-42215 | GitPython | claude-sonnet-5 | `20261021T141259Z-CVE-2026-42215-claude-sonnet-5` | 8 | 64 | git/cmd.py | | |
| 8 | CVE-2026-42215 | GitPython | gpt-5.3-codex | `20261021T141434Z-CVE-2026-42215-gpt-5.3-codex` | 10 | 64 | git/cmd.py | | |
| 9 | CVE-2026-44502 | bugsink | claude-sonnet-5 | `20261021T141813Z-CVE-2026-44502-claude-sonnet-5` | 18 | 112 | alerts/service_backends/webhook_security.py | | |
| 10 | CVE-2026-44502 | bugsink | gpt-5.3-codex | `20261021T141842Z-CVE-2026-44502-gpt-5.3-codex` | 9 | 112 | alerts/service_backends/webhook_security.py | | |
| 11 | CVE-2026-22250 | wlc | gpt-5.3-codex | `20261021T141948Z-CVE-2026-22250-gpt-5.3-codex` | 10 | 18 | wlc/__init__.py | | |
| 12 | CVE-2026-42215 | GitPython | claude-sonnet-5 | `20261021T142117Z-CVE-2026-42215-claude-sonnet-5` | 3 | 64 | git/cmd.py | | |
| 13 | CVE-2026-42215 | GitPython | gpt-5.3-codex | `20261021T142250Z-CVE-2026-42215-gpt-5.3-codex` | 14 | 64 | git/cmd.py | | |
| 14 | CVE-2026-44502 | bugsink | claude-sonnet-5 | `20261021T142558Z-CVE-2026-44502-claude-sonnet-5` | 9 | 112 | alerts/service_backends/webhook_security.py | | |
| 15 | CVE-2026-44502 | bugsink | gpt-5.3-codex | `20261021T142630Z-CVE-2026-44502-gpt-5.3-codex` | 19 | 112 | alerts/service_backends/webhook_security.py | | |
| 16 | CVE-2026-22250 | wlc | gpt-5.3-codex | `20261021T142725Z-CVE-2026-22250-gpt-5.3-codex` | 3 | 18 | wlc/__init__.py | | |
| 17 | CVE-2026-42215 | GitPython | claude-sonnet-5 | `20261021T142844Z-CVE-2026-42215-claude-sonnet-5` | 6 | 64 | git/cmd.py | | |
| 18 | CVE-2026-42215 | GitPython | gpt-5.3-codex | `20261021T143019Z-CVE-2026-42215-gpt-5.3-codex` | 18 | 64 | git/cmd.py | | |
| 19 | CVE-2026-44502 | bugsink | claude-sonnet-5 | `20261021T143335Z-CVE-2026-44502-claude-sonnet-5` | 25 | 112 | alerts/service_backends/webhook_security.py | | |
| 20 | CVE-2026-44502 | bugsink | gpt-5.3-codex | `20261021T143406Z-CVE-2026-44502-gpt-5.3-codex` | 18 | 112 | alerts/service_backends/webhook_security.py | | |
| 21 | CVE-2026-22250 | wlc | gpt-5.3-codex | `20261021T143458Z-CVE-2026-22250-gpt-5.3-codex` | 7 | 18 | wlc/__init__.py | | |

21 runs. Open a diff with: `cat runs/<run folder>/model.patch`; the official fix: `cat ~/cve-bench/tasks/<case>/fix.patch`.
