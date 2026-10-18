# Architecture

> Status: draft, in progress.

## 1. Problem Statement

In my previous roles, I wrote Python scripts to parse NVD feeds, cutting vulnerability triage time by 90%. I also prioritized 11 CISA KEV vulnerabilities and coordinated the remediation across different teams. But the actual fixes still relied entirely on humans. I personally remediated SQL injection issues using parameterized queries, reducing recurring findings by 60%. Through that hands-on experience, I learned early on that just because a scanner stops flagging an alert doesn't mean the vulnerability is actually fixed. Today, AI can generate patches automatically, which shifts the real question to: how do we verify that a fix actually works without breaking anything else?

**Where the bottleneck moves.** Keller & Nowakowski (2024) report that within Google's internal codebase alone, sanitizers uncover thousands of new bugs every year, and engineers spend an average of two hours writing a single fix. They used Gemini to automatically fix 15% of those sanitizer bugs, yet even their pipeline ends with every generated fix going to human review before submission. That still leaves the remaining unpatched issues, plus the need to verify whether that 15% was handled correctly. Human effort shifts toward finding out whether the patch itself is broken.

**Two modes of failure.** Looking closely at Keller & Nowakowski (2024), I see two main ways an AI patch can fail.

The first is an incomplete or bogus fix. Developers sometimes leave temporary workarounds marked with "TODO" comments. If that kind of code isn't filtered out of training sets, LLMs pick up the habit and suggest the same provisional fixes. Even worse are fake fixes: Google observed suggestions that "resolved" an error by deleting the failing test case entirely. Everything looks green on the surface, but the vulnerability is still wide open.

The second mode is fixing the vulnerability while breaking functionality. In one real case, to resolve a data race, a model made the code run sequentially and added a comment saying, "cannot run in parallel because it causes a data race." The race condition was gone and the code still ran, but the parallelism was gone with it.

**The cost of missing data.** Right now, nobody knows how often these failures happen. Without concrete data, teams hesitate to touch AI-generated patches, and the problematic code simply sits there. One option is reviewing every patch manually, which makes humans the bottleneck; nobody has published what that review costs per patch, either. The alternative is skipping the patches altogether, leaving vulnerabilities exposed longer and risking product security. The data we are missing includes: what percentage of a model's patches break existing features, how long it takes to generate and validate them, and what the success-to-failure ratio looks like across different models.

**Why not just follow Google's playbook?** Google's answer is to improve the quality of the training data. But the vast majority of security teams are end users of these models; we can't touch the training data. My approach is to evaluate whether we can rigorously validate the model's output instead: measuring regression rates, generation and validation times, and success/failure splits to decide which patches genuinely require human eyes.

**The core question.** Under what conditions can an AI-generated security patch be safely merged? In this project, "safely merged" means the previously failing security test now passes (the vulnerability is truly gone), the application builds and runs, and all existing regression tests pass (nothing broke). Re-scan results from vulnerability scanners are logged for tracking, but they are not used as the pass/fail criteria. The goal is to back this up with visualized metrics, using hard data to decide when a human actually needs to step in.

**Reference.** Jan Keller and Jan Nowakowski, *AI-powered patching: the future of automated vulnerability fixes*, Google Security Engineering Technical Report, 2024. https://research.google/pubs/ai-powered-patching-the-future-of-automated-vulnerability-fixes/

## 2. Related Work and What This Project Adds

<!--
- CVE-Bench、PatchEval、SWE-bench 各自量了什麼？用什麼判定「修好」與「沒弄壞」？
- 它們「沒有」做的是哪一段？（提示：部署閘門、掃描器綠燈 vs 真的修好、在自己 fork 的實戰）
- 用一句話回答面試官會問的：「這跟 CVE-Bench 差在哪？」
- 你沿用了什麼（資料集、判定方法），並註明來源與授權。

查證過的事實（2026-10-18），寫的時候從這裡取材，用自己的話：
沿用：
  - 判定方法 FAIL_TO_PASS / PASS_TO_PASS 來自 SWE-bench（Jimenez et al., 2023）
  - 案例、安全測試、setup 腳本、「跑測試前注入可信測試檔」的設計來自 CVE-Bench
    （GiovanniGatti/cve-bench, MIT, commit 45cb1bf）
與 CVE-Bench 的差異（每一條都是你的決定，§12 有理由）：
  1. 它沒有 baseline；本專案套 patch 前先跑一次原有測試，只看原本通過的
  2. 它只判「解沒解」；本專案分四類，把「修好但弄壞」獨立量出來
  3. 它沒有「patch 動到測試檔」旗標，沒有嚴格套用 + --ignore-whitespace 乾跑的雙紀錄
  4. 它是 benchmark，到判定為止；本專案的數字接到合併閘門（§6）
  5. 它不記成本與時間；本專案每筆記 token、秒數、Gateway spend
-->

## 3. Scope and Non-goals

<!--
- 這個專案「做」什麼？列 3–5 條。
- Non-goals：不自己寫掃描器、不追求高修補成功率、不做 agent、不碰釣魚分析、不送上游 PR。
- 每一條 Non-goal 都補一句「為什麼不做」——這比清單本身更重要。
-->

## 4. System Overview

**Three phases, in a fixed order.** Phase 1, *calibrate*: on historical CVEs whose
answers are known, measure each model's fix rate and break rate. Phase 2, *gate*: turn
those numbers into merge rules that a patch bot enforces in CI. Phase 3, *field test*:
run the whole pipeline on a real open-source package in my own fork and publish the
result.

The order cannot be reversed because the point of the project is to quantify "fixed
without breaking anything". Without Phase 1's numbers, the Phase 2 rules could still
be written, but the thresholds would be my guesses; only Phase 1 can say what "break
rate below X%" should be. Without the Phase 2 gate, Phase 3 would produce what every
existing tool already produces, "an AI opened a PR", with nobody answering whether that
PR may be merged and no data for a reviewer to decide with.

**One run.** The unit of Phase 1 is one case × one model × one attempt, driven by
`harness/run_case.py` across the harness modules. The input is one case from
`benchmarks/cves.yaml`, which points at a CVE-Bench task directory pinned to a fixed
commit. Before anything else, the runner checks the remaining Gateway budget and
refuses to start a run when it is below the reserve (§7). Then:

| Step | Module | What happens | Output |
|---|---|---|---|
| 1 | `setup_case.setup` | runs the task's `setup.sh`: the repo is reset to the vulnerable commit | `repo/` at the vulnerable commit |
| 2 | `verify.run_regression_tests` | runs the project's own pytest suite **before** the patch and records which tests pass (the baseline) | `regression_baseline.json` |
| 3 | `patch.load_target`, `build_prompt_v1` | reads `advisory.md`, cuts the function or class that `locate.md` names out of the source with `ast`, builds the prompt | `prompt.md` |
| 4 | `scan.scan_target` | Bandit and Semgrep scan the target file; two booleans are recorded (a matching-CWE finding anywhere in the file / inside the target range). Record only | `scan_before` in the record |
| 5 | `llm.call_model` | calls the model; records tokens, latency, finish reason and the parameters actually accepted | `reply.md` |
| 6 | `patch.apply_reply` | extracts the unified diff and applies it strictly with `git apply --recount`; on failure records why (no diff / git refused, with git's message) and whether ignoring whitespace would have applied it; flags patches that touch test files | `model.patch` |
| 7 | `scan.scan_target` | scans again after the patch | `scan_after` |
| 8 | `setup_case.run_security_tests` | runs the task's `run_tests.sh`, which first copies the **trusted** `test_security.py` into the repo, so a patch that deletes or edits the test has no effect | `security_report.json` |
| 9 | `verify.run_regression_tests` | runs the project's own suite again | `regression_after.json` |
| 10 | `verify.classify` | combines 6, 8, 2 and 9 into one of four outcomes (rules in §5) | `outcome` and `verdict` in `record.json` |

**What one run leaves behind.** One folder named `<timestamp>-<case>-<model>` with
up to seven files: `prompt.md`, `reply.md`, `model.patch`, three test reports, and
`record.json` (model parameters, tokens, seconds, Gateway spend before and after, apply
details, both scans, the baseline and after test counts with the list of tests that
did not pass, the verdict). A run that stops early (the diff did not apply) has fewer
files, because the later steps never ran. Official runs go to `runs/` and are
committed; development and smoke runs go to `runs-dev/`, which is ignored by git. Any
number in a report can be traced back to the folder that produced it.

**What is not a result.** A diff that does not apply is one of the four outcomes
(*not applied*), not an error. Errors are failures of the pipeline itself: the setup
script crashes, the model returns an empty reply, the budget is insufficient, a test run
produces no report, the baseline suite cannot run, a timeout. These are recorded as
`outcome: error`, the folder is kept, and they never enter the four-way count; the
cause is fixed and the run repeated. The test for telling the two apart: in this
failure, did the model actually get a chance?

**A whole wave.** `harness/wave.py` expands cases × models × repeats into a job list,
ordered so that within each round every model runs once on a case before the next case;
if the budget runs out halfway, every model still has data. On restart it skips
(case, model) pairs that already have enough non-error records, and on budget
exhaustion it stops explicitly and lists what is left.

```
cves.yaml ─► budget check ─► setup ─► baseline tests ─► prompt ─► scan ─► model ─► git apply
                                                                                      │
                        record.json ◄── verdict ◄── tests after ◄── security test ◄── scan
```

## 5. Outcome Classification

**Two criteria, both borrowed.** "Fixed" is decided by FAIL_TO_PASS: every case ships
a security test that fails on the vulnerable commit; after the patch it must pass.
"Nothing broke" is decided by PASS_TO_PASS: every test of the project's own suite that
passed before the patch must still pass after it. Neither criterion is mine. Both come
from SWE-bench (2023) and are reused by CVE-Bench; this project reuses them too, so that
its numbers are comparable with prior work. What this project adds is the baseline step
(below), the four-way split, and what happens around the criteria, not the criteria
themselves.

**Four outcomes, one order.** Every run ends in exactly one of these:

| Outcome | Security test (was failing) | Existing tests (were passing) |
|---|---|---|
| not applied | the diff did not apply; nothing was run | |
| not fixed | still fails | |
| fixed but broke | passes | at least one no longer passes |
| fixed and clean | passes | all still pass |

The rules are evaluated in this order and the first one that matches stops the
evaluation: *not applied* → *not fixed* → *fixed but broke* → *fixed and clean*. The
order follows from the evidence: if the diff did not apply there is nothing to test; if
the security test still fails, regression results do not change the verdict. In code
this is four `if` statements in `harness/verify.py` (`classify`), and each rule below
has a unit test.

**Baseline before the patch.** The project's own test suite is run twice in every run:
once right after the repository is reset to the vulnerable commit, once after the
patch is applied. Only tests that passed in the first run can count as broken in the
second. Tests that were already failing, erroring or skipped before the patch are
recorded as *pre-existing failures* and excluded from the judgment, so a project's old
red tests are never charged to the model. The baseline is taken on every run rather
than stored once per case: it costs one to three seconds on the current cases, and
flaky tests (network, timing, ordering) are handled most fairly by comparing before and
after within the same run. CVE-Bench skips this step because it validated that every
task's suite is green on the fixed commit; this harness keeps it because Phase 3 will
run on repositories nobody has validated, and the rule should not change halfway.

**Detail rules.** The first four are single tests in `tests/test_verify.py`; the flag
in the fifth is tested in `tests/test_patch.py`:

- A test that passed at baseline and is *missing* afterwards (deleted or renamed)
  counts as broken. This is the "fix the bug by deleting the test" failure mode from the
  Google report, and the reason the security test itself is re-copied from a trusted
  location before it runs (§4, step 8).
- A test that passed at baseline and is *skipped* afterwards counts as broken: a
  skipped test no longer proves anything.
- A test that failed at baseline and passes afterwards is recorded as *newly passing*
  and does not affect the verdict.
- A patch that applied but whose security run is missing is *not fixed*, never
  *clean*: absence of evidence is not evidence.
- A patch that touches test files is flagged (`touches_tests`) and classified normally.
  It cannot change the security verdict because the trusted test file is copied in
  before the run; the flag is kept as a signal for the gate (§6).

**What "the project's own tests" means.** Whatever `pytest` runs by default in that
repository: the project's own `pytest.ini` or `pyproject.toml` settings are inherited
(yt-dlp, for example, excludes network download tests by default), and only the
harness's injected security test file is removed from the run. The whole default
suite is run, never a subset chosen around the patched file; one clear target, with no
per-case exceptions, is what keeps results comparable. A suite that exceeds its time
limit (`regression_timeout_s` in `benchmarks/cves.yaml`, default 600 s) is an error,
not a failure; the number may differ per case, the rule does not. The known limit of
PASS_TO_PASS is stated plainly: it only catches breakage that the existing tests
exercise. Behaviour nobody tested (performance, concurrency, edge cases) is a blind
spot of this method, and of every method built on it.

**What is not an outcome.** A failure of the pipeline is recorded as `outcome: error`
and never enters the four-way count: the setup script crashes, the model returns an
empty reply, the budget is insufficient, a test run produces no report, the baseline
suite cannot run, a step times out. The run folder is kept, the cause is fixed, and the
run is repeated. A diff that git refuses is *not* an error but a result (*not applied*),
because a real patch bot would be rejected the same way; the harness records why (no
diff in the reply, or git refused it and whether ignoring whitespace would have
accepted it) so that formatting failures can later be separated from wrong fixes. The
question that separates the two categories: in this failure, did the model actually get
a chance? One error subtype is already known to be a model property rather than a
harness fault: claude-sonnet-5 on the justhtml case sometimes spends the entire
16,384-token output budget without producing a patch (`finish_reason: length`). The
ceiling is not raised for it; the case is logged in §13. One run that sits on the
boundary between *not fixed* and *fixed but broke* (a patch that blocked the traversal
but mangled the file name) is worked through in §12; the ordering rule decides it.

**Scanner results are recorded, never used to judge.** Bandit and Semgrep scan the
target file before and after the patch, and two booleans are kept per tool: whether a
finding with the case's CWE exists anywhere in the file, and whether it falls inside the
function that the advisory points at. A scanner going quiet is not evidence of a fix;
deleting the failing test also makes scanners quiet. The record exists so the report
can show how often the scanner saw the vulnerability at all, and how often it went quiet
after a patch that the tests say did not fix anything.

**Non-determinism.** Each case × model pair is run three times with the model's
temperature set explicitly to 1.0 (§7) and the gateway's response cache disabled.
Results are reported as counts per outcome over those runs, not as a single label per
pair; on the first night of Wave 1 the same model gave three different results on the
same case (fixed, not fixed, error), which is exactly what the repeats are for. How the
three runs feed the merge gate (majority, worst case, or rate thresholds) is decided in
§6 once Phase 1 data exists.

## 6. Merge Gate Policy

<!--
- patch-bot 在什麼條件下自動開 PR？什麼條件下改開 issue 給人看？
- 每一條規則都要能指回第一階段的某個量測數字（例：「模型 X 的弄壞功能率是 Y%，所以……」）。
  數字還沒出來的話，先寫「待階段 1 結果」和你預期要看哪個數字。
- 什麼情況一律需要人工審查？
-->

## 7. Model Layer and Reproducibility

**Models.** Four: three through the Duke AI Gateway (claude-sonnet-5, gpt-5.3-codex,
gpt-oss-120b) and one run locally with Ollama (gpt-oss:20b). Two comparisons drive the
choice: across vendors (Anthropic's sonnet against OpenAI's codex) and within one family
across sizes (gpt-oss 120b against 20b). The local model is also the free, offline,
reproducible control; the three Gateway models produce the official numbers. The Gateway
is a LiteLLM deployment with an OpenAI-compatible endpoint, so all four models share one
calling path that differs only in base URL and key.

**What is reused from cwe-explainer.** cwe-explainer is the code-review tool I built in
a course (the course has agreed to its publication). Four practices carry over, not the
code: all configuration comes from the environment and no key or URL is hard-coded;
switching between the Gateway and Ollama is a change of `base_url`; when a model rejects
a parameter (reasoning models refuse `temperature`, some endpoints want
`max_completion_tokens`), the harness reads the 400 message to find which parameter,
drops or renames it, retries, and records the adjustment, instead of keeping a
hand-written parameter table per model; and the model's output is untrusted input: the
harness only extracts a diff from the reply, applies it strictly and runs tests, and
believes nothing the model says about itself.

**What is fixed so that others can re-run this.**
- The model id is given on the command line and written into every record.
- `temperature` is set explicitly to 1.0. Two reasons: the measurement is of a model
  under ordinary use, so the vendor default is the right value; but "default" cannot be
  left implicit, because Claude and GPT on the Gateway default to 1.0 while Ollama
  defaults to 0.8, and the same experiment would silently run under different
  conditions. The parameters actually accepted are recorded in `params_used`.
- `max_tokens` is 16,384, set once and not tuned. It started at 4,096 and was raised
  after claude-sonnet-5 spent the whole budget thinking on the justhtml case and
  returned nothing; a model that hits the ceiling again is recorded as an error subtype,
  not given more, because the ceiling is a cost cap, not a quality knob. The full-length
  reply is the most expensive call the harness makes; measured costs are in the results
  report.
- The prompt version is recorded (currently `v1.1-snippet`: the full advisory plus the
  function or class that `locate.md` names, cut from the source with `ast` and shown
  verbatim; v1.0 added a line-number gutter, the model copied it into the diff, and those
  runs are not counted).
- The Gateway's response cache is disabled per request (`cache: no-cache`). It was found
  when an identical prompt came back in 0.06 s byte-for-byte; left on, "three runs per
  pair" would have been one run copied three times.
- Each case × model pair is run three times.
- Cases are pinned to CVE-Bench commit 45cb1bf; the repository runs on Python 3.12.
- Timeouts: 300 s per HTTP request; 600 s per project regression suite (the number can
  change per case in `cves.yaml`, the rule does not).

**What every run records.** One `record.json` with: case, model, provider, temperature,
prompt version, start time; setup seconds; baseline test counts and the list of tests
not passing; target file, function and line range, prompt size; the model call's
accepted parameters, adjustment notes, input and output tokens, latency,
`finish_reason`, the exact cost of the call, the Gateway's spend counter at that moment
and the remaining per-minute token quota; the apply result and reason, files touched,
whether tests were touched, whether ignoring whitespace would have applied it; the two
scanner booleans before and after; security test counts; regression counts and
not-passing list after the patch; the four-way verdict with its three lists; total
seconds; Gateway spend before and after. Next to it sit the prompt, the reply, the
patch, three test reports and the test output log.

**Gateway limits and how the harness respects them.** The key allows $1 per 24 hours
(reset at midnight US Eastern), 20 requests and 20,000 tokens per minute, with a soft
limit at $0.80; it expires in January 2027. Four rules follow. Before every run the
harness reads `/key/info` and refuses to start when less than $0.50 remains (room for
several worst-case calls) or when the budget cannot be read at all (VPN down). A 422
"budget exceeded" from the Gateway stops the whole wave, because the counter the Gateway
enforces can run ahead of the one it reports (observed once at almost three times the
reported spend, recovering within a minute); so the harness no longer trusts `/key/info`
alone and also records the enforced counter from each response's headers. Transient
errors (429, 5xx, connection) are retried twice quickly by the SDK and then twice more
by the harness after 30 s and 60 s before the run is recorded as an error. On resume, a
pair that keeps erroring gets at most two extra attempts, so one case cannot drain a
day's budget. A preflight runs before every wave: case files present, scanners
installed, Gateway reachable, one five-token ping per model.

**Storage.** Results are kept as one JSON folder per run and aggregated directly by
`harness/report.py` and `harness/report_html.py`; no database. Whether to load the
records into SQLite and express the report in SQL is deferred to the Phase 2 gate,
which is the first component that will need to query them (§13).

## 8. Relationship to Existing Code

<!--
- 原本的 CVE 查詢／KEV 對照／SLA 追蹤保留下來扮演什麼角色？
- 什麼已經移走（釣魚分析 → phishing-analyzer branch）？
- 已知但還沒修的既有問題：NVD 查詢失敗時顯示「系統安全」（fail-open）、CVE 頁面 XSS。
-->

## 9. Security of the Harness

<!--
這一節是 THREAT_MODEL.md 的摘要。
- 你會執行別人的程式碼和模型產生的修補——要怎麼隔離？
- patch-bot 的 token 需要哪些權限？最少可以少到哪裡？fork 來的 PR 拿得到 secrets 嗎？
- 被修補的程式碼裡如果藏了對模型的指令（prompt injection），會發生什麼事？
- 模型 API key 放哪裡？
-->

## 10. Disclosure and Contribution Rules (Phase 3)

<!--
- 只在自己的 fork 做實驗，不送上游 PR。為什麼？
- 公開報告放什麼、不放什麼？
- 如果發現尚未公開、可被利用的漏洞怎麼辦？（負責任揭露、SECURITY.md）
-->

## 11. Secure SDLC Mapping

<!--
用一張表把 SDLC 各階段對應到專案裡的具體東西：
  設計 → THREAT_MODEL.md
  建置 → SAST（Bandit、Semgrep）、SCA（pip-audit）、秘密掃描（gitleaks）
  發佈 → patch-bot 合併閘門、分支保護
可以對照 NIST SSDF 的四個實踐群組（PO、PS、PW、RV）。
-->

## 12. Decision Log

<!--
每個重要決定一小段：背景 → 考慮過的選項 → 選了什麼 → 為什麼 → 代價。
這是證明「是你做的決定」最有力的地方。第一條可以寫：
  「沿用 CVE-Bench 的案例，而不是自己挑 10 個 CVE 自己架環境」
-->

## 13. Open Questions

## 13. Open Questions

- **Phase 3 has no ready-made security test.** CVE-Bench ships `test_security.py`; a
  real package does not. Candidates: pick a package with a published CVE and write the
  test from the advisory, or start from a scanner finding and write the test for it.
  Decide before mid-November.
- **`finish_reason: length` as a model property.** claude-sonnet-5 on justhtml exceeds
  16,384 output tokens in some runs. It is recorded as an error subtype; whether to report
  it as a model failure rate is open.
- **Aggregating three runs per pair** (majority, worst case, or rates) is decided with
  the gate (§6).
- **10 or 20 cases.** Decided in early November from Wave 1's measured per-run cost
  (see `reports/`).
- **`git apply --ignore-whitespace`** stays off; the dry-run flag is recorded instead.
- **Two Gateway spend counters.** The enforced counter and `/key/info` disagreed once by
  almost 3×. Cause unknown; both are now recorded per run.
- **SQLite for results** (§7): deferred until the gate needs queries.

## 14. AI Assistance

<!--
照 cwe-explainer README 的做法：誠實說明哪些是你決定的、AI 幫了什麼。
-->
