# Gate `allow` review (2026-10-22)

The gate would open a PR for these runs with no human-review flag. Review each diff against the
official fix (`~/cve-bench/tasks/<case>/fix.patch`) and record whether you would merge it.
This is the only ground truth for the gate's precision. Fill the last two columns.

| # | case | project | model | run folder | diff ±lines | official ±lines | files | would merge? | why not |
|---|---|---|---|---|---|---|---|---|---|
| 1 | CVE-2026-32714 | scitokens | claude-sonnet-5 | `20261018T210315Z-CVE-2026-32714-claude-sonnet-5` | 29 | 165 | src/scitokens/utils/keycache.py | yes |  |
| 2 | CVE-2026-32714 | scitokens | gpt-5.3-codex | `20261018T210335Z-CVE-2026-32714-gpt-5.3-codex` | 33 | 165 | src/scitokens/utils/keycache.py | yes |  |
| 3 | CVE-2026-32714 | scitokens | claude-sonnet-5 | `20261018T210757Z-CVE-2026-32714-claude-sonnet-5` | 29 | 165 | src/scitokens/utils/keycache.py | yes |  |
| 4 | CVE-2026-32714 | scitokens | gpt-5.3-codex | `20261018T210818Z-CVE-2026-32714-gpt-5.3-codex` | 33 | 165 | src/scitokens/utils/keycache.py | yes |  |
| 5 | CVE-2026-32714 | scitokens | claude-sonnet-5 | `20261018T211002Z-CVE-2026-32714-claude-sonnet-5` | 33 | 165 | src/scitokens/utils/keycache.py | yes |  |
| 6 | CVE-2026-32714 | scitokens | gpt-5.3-codex | `20261018T211025Z-CVE-2026-32714-gpt-5.3-codex` | 36 | 165 | src/scitokens/utils/keycache.py | yes | note: also adds a trailing space on one unrelated line and rewords a comment (no behaviour change) |
| 7 | CVE-2026-42215 | GitPython | claude-sonnet-5 | `20261021T141259Z-CVE-2026-42215-claude-sonnet-5` | 8 | 64 | git/cmd.py | yes | |
| 8 | CVE-2026-42215 | GitPython | gpt-5.3-codex | `20261021T141434Z-CVE-2026-42215-gpt-5.3-codex` | 10 | 64 | git/cmd.py | yes | |
| 9 | CVE-2026-44502 | bugsink | claude-sonnet-5 | `20261021T141813Z-CVE-2026-44502-claude-sonnet-5` | 18 | 112 | alerts/service_backends/webhook_security.py | yes |  |
| 10 | CVE-2026-44502 | bugsink | gpt-5.3-codex | `20261021T141842Z-CVE-2026-44502-gpt-5.3-codex` | 9 | 112 | alerts/service_backends/webhook_security.py | no | changes behaviour: rejects every URL with userinfo (`user:pass@host`), which worked before and still works after the official fix; deliberate tightening, not covered by any existing test |
| 11 | CVE-2026-22250 | wlc | gpt-5.3-codex | `20261021T141948Z-CVE-2026-22250-gpt-5.3-codex` | 10 | 18 | wlc/__init__.py | yes | |
| 12 | CVE-2026-42215 | GitPython | claude-sonnet-5 | `20261021T142117Z-CVE-2026-42215-claude-sonnet-5` | 3 | 64 | git/cmd.py | yes | |
| 13 | CVE-2026-42215 | GitPython | gpt-5.3-codex | `20261021T142250Z-CVE-2026-42215-gpt-5.3-codex` | 14 | 64 | git/cmd.py | yes | note: also removes an unrelated blank line in the docstring (no behaviour change) |
| 14 | CVE-2026-44502 | bugsink | claude-sonnet-5 | `20261021T142558Z-CVE-2026-44502-claude-sonnet-5` | 9 | 112 | alerts/service_backends/webhook_security.py | yes |  |
| 15 | CVE-2026-44502 | bugsink | gpt-5.3-codex | `20261021T142630Z-CVE-2026-44502-gpt-5.3-codex` | 19 | 112 | alerts/service_backends/webhook_security.py | no | changes behaviour: rejects every URL with userinfo (`user:pass@host`), which worked before and still works after the official fix; deliberate tightening, not covered by any existing test; also two checks that can never be true |
| 16 | CVE-2026-22250 | wlc | gpt-5.3-codex | `20261021T142725Z-CVE-2026-22250-gpt-5.3-codex` | 3 | 18 | wlc/__init__.py | yes | |
| 17 | CVE-2026-42215 | GitPython | claude-sonnet-5 | `20261021T142844Z-CVE-2026-42215-claude-sonnet-5` | 6 | 64 | git/cmd.py | yes | |
| 18 | CVE-2026-42215 | GitPython | gpt-5.3-codex | `20261021T143019Z-CVE-2026-42215-gpt-5.3-codex` | 18 | 64 | git/cmd.py | no | blocks the listed spelling only: adds an underscore copy of each unsafe name instead of normalising the option, so a mixed spelling (`foo_bar-baz` for `--foo-bar-baz`) is not blocked; no such name is in today's lists |
| 19 | CVE-2026-44502 | bugsink | claude-sonnet-5 | `20261021T143335Z-CVE-2026-44502-claude-sonnet-5` | 25 | 112 | alerts/service_backends/webhook_security.py | no | changes behaviour: rejects every URL with userinfo (`user:pass@host`), which worked before and still works after the official fix; deliberate tightening, not covered by any existing test |
| 20 | CVE-2026-44502 | bugsink | gpt-5.3-codex | `20261021T143406Z-CVE-2026-44502-gpt-5.3-codex` | 18 | 112 | alerts/service_backends/webhook_security.py | no | changes behaviour: rejects every URL with userinfo (`user:pass@host`), which worked before and still works after the official fix; deliberate tightening, not covered by any existing test; also one check that can never be true |
| 21 | CVE-2026-22250 | wlc | gpt-5.3-codex | `20261021T143458Z-CVE-2026-22250-gpt-5.3-codex` | 7 | 18 | wlc/__init__.py | no | changes behaviour: only `localhost` is treated as local, `127.0.0.1` (the original value and the default API_URL host) no longer is |

21 runs. Open a diff with: `cat runs/<run folder>/model.patch`; the official fix: `cat ~/cve-bench/tasks/<case>/fix.patch`.

## Result (reviewed 2026-11-12)

Rule used for every row: would I merge this as a colleague's PR, given the tests are green?
Three checks: (1) fixes the mechanism, (2) does not change behaviour that worked before,
(3) adds nothing unrelated. Unrelated changes that do not alter behaviour (comments, blank
lines, dead checks) are noted but do not make a row `no`.

| | would merge | would not | n |
|---|---|---|---|
| all allow runs | 15 (71%) | 6 | 21 |
| claude-sonnet-5 | 8 | 1 | 9 |
| gpt-5.3-codex | 7 | 5 | 12 |

Why not: 5 change behaviour that worked before and that no existing test covers (wlc #21;
bugsink #10, #15, #19, #20), 1 blocks only the listed spelling (GitPython #18). None of the 6
leaves the published vulnerability exploitable.

Second pass, 2026-11-22: the six bugsink rows were first decided by applying the rules above
to the group. They were then re-reviewed one by one against executed behaviour: each patch was
applied and `validate_webhook_url` was called (allowlist mode, DNS mocked) with four URLs.
All eight variants accept `https://hooks.example.com/webhook`. The verdicts did not change.

| | attack `http://127.0.0.1:6666\@whitelist.com` | credentials `https://user:secret@hooks.example.com/webhook` | backslash in path `https://hooks.example.com/a\b` |
|---|---|---|---|
| before the fix | accept | accept | accept |
| official fix | reject | accept | reject |
| #9, #14 | reject | accept | reject |
| #10, #19, #20 | reject | reject | reject |
| #15 | reject | reject | accept |

