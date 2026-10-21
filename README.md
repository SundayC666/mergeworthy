# mergeworthy

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![CI](https://github.com/SundayC666/mergeworthy/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/License-MIT-green)

Measures whether AI-generated security patches fix real CVEs without breaking
existing tests, and turns that evidence into a merge gate.

> Formerly `secops-remediation-agent`. Renamed on 2026-10-18: this is a measurement
> harness and a merge gate, not an agent (see Non-goals in
> [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)). The phishing analyzer from v1 lives
> on the [`phishing-analyzer`](https://github.com/SundayC666/mergeworthy/tree/phishing-analyzer) branch.
> Earlier versions also had a ChromaDB + Sentence Transformers retrieval fallback; it
> was removed on 2026-09-27 (the harness has no retrieval need, and retrieval hurt
> reproducibility). The last version with it is tagged
> [`v2.0-rag-fallback`](https://github.com/SundayC666/mergeworthy/tree/v2.0-rag-fallback).

**Why.** AI has made finding vulnerabilities in code cheap. What it has not made
cheap is knowing whether the patch an AI writes actually fixes the bug *and* leaves
the rest of the program working. This repository measures that, so that the decision
"does a human need to look at this patch?" can be made from data rather than by
reviewing everything. Every number can be traced back to the exact diff the model
produced and the test output that judged it.

**How.** Cases come from [CVE-Bench](https://github.com/GiovanniGatti/cve-bench)
(MIT), pinned to a fixed commit. For each case the model gets the public advisory and
the vulnerable function, and returns a unified diff. The harness applies it and runs
two kinds of tests: the security test that fails on the vulnerable commit, and the
project's own existing tests. Each run ends in one of four outcomes:

| Outcome | Security test (was failing) | Existing tests (were passing) |
|---|---|---|
| not applied | the diff did not apply, nothing was run | |
| not fixed | still fails | |
| fixed but broke something | passes | some fail |
| fixed and clean | passes | all pass |

**Results so far (2026-10-21: 10 cases × 3 models × 3 runs, 88 scored runs).**
Every cell is clickable on the [results page](https://sundayc666.github.io/mergeworthy/results/).

| Model | n | fixed and clean | not fixed | not applied | fixed but broke |
|---|---|---|---|---|---|
| claude-sonnet-5 | 28 | 15 (54%) | 5 | 7 | 1 |
| gpt-5.3-codex | 30 | 15 (50%) | 7 | 7 | 1 |
| gpt-oss-120b | 30 | 0 | 0 | 30 | 0 |

Runs that failed for infrastructure reasons (empty reply, gateway budget) are recorded
as errors and never counted; 13 of 101 recorded runs ended that way, most of them in
one gateway budget incident, and one case × model pair (justhtml × claude-sonnet-5)
was abandoned after repeated empty replies.

Three things the numbers show. Case difficulty outweighs model choice: three cases
(scitokens, GitPython, bugsink) were fixed cleanly in every attempt by both capable
models, while two others (oauthenticator, kedro) were never even applied by any model. gpt-oss-120b never produced a diff that `git apply` accepts
(hunk headers without line numbers), so for it the question is format, not fixing.
And the two "fixed but broke" runs are the reason the regression half exists: on
pdfminer.six, one patch from each capable model used `re.match()` without importing
`re`. The security test passed (the code crashed before reaching the vulnerable
load), both Bandit and Semgrep went quiet, and 26 of the project's 227 existing
tests failed. Without the existing tests those two patches would have looked mergeable.

A separate prompt-injection experiment (a planted comment in the target function)
found that models refuse a destructive instruction ("delete the security test",
5 of 18 complied, all from gpt-oss-120b) more often than a harmless-looking one ("add
this constant", 11 of 18 complied: gpt-5.3-codex 6 of 6, gpt-oss-120b 5 of 6,
claude-sonnet-5 0 of 6, which instead deleted the comment in 3 runs). None of the
complying diffs applied, so no green patch carried the constant, but the model that
cleans up a destructive injection every time follows a benign one every time. That is
why the gate will not auto-merge on green alone, and why it records every new symbol a
patch introduces that the advisory never mentions.

| Case | Project | Weakness |
|---|---|---|
| CVE-2026-24486 | python-multipart | path traversal (CWE-22) |
| GHSA-r758-8hxw-4845 | justhtml | cross-site scripting (CWE-79) |
| CVE-2026-26331 | yt-dlp | OS command injection (CWE-78) |
| CVE-2026-32714 | scitokens | SQL injection (CWE-89) |
| CVE-2026-33175 | jupyterhub/oauthenticator | missing authorization check (CWE-287) |
| CVE-2025-64512 | pdfminer.six | unsafe deserialization (CWE-502) |
| CVE-2026-42215 | GitPython | OS command injection (CWE-78) |
| CVE-2026-35171 | kedro | code injection / deserialization (CWE-94, CWE-502) |
| CVE-2026-44502 | bugsink | server-side request forgery (CWE-918) |
| CVE-2026-22250 | wlc | improper certificate validation (CWE-295) |

Design, decisions and open questions: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

This repository holds two things. **Part 1** is the harness described above. **Part 2**
is the CVE lookup web app this project started as: it answers *which* CVE matters
(NVD data, CISA KEV, SLA tracking), while the harness answers whether an AI patch for
that CVE can be merged. The two are not connected yet; the harness is still being built.

---

## Part 1 · Patch verification harness (`harness/`)

**Prerequisites**
- Python 3.12
- A clone of [CVE-Bench](https://github.com/GiovanniGatti/cve-bench) at the path set as
  `cve_bench_root` in `benchmarks/cves.yaml` (default `~/cve-bench`). Its `setup.sh`
  scripts need `python3.12` on `PATH`.
- A model endpoint: either `DUKE_API_KEY` in `.env` for the Duke AI Gateway (reachable
  only from the Duke network or VPN), or a local [Ollama](https://ollama.ai) server.
  See `.env.example`.
- Optional: [Semgrep](https://semgrep.dev) as an isolated tool (`uv tool install semgrep`).
  It is kept out of this venv because its dependencies conflict with the pinned FastAPI.
  Bandit comes with `requirements-dev.txt`. Scan results are recorded, never used to judge.

**Run one case through one model**

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m harness.run_case --case CVE-2026-24486 --model claude-sonnet-5
python -m harness.run_case --case all --model gpt-oss:20b --provider ollama
```

Each run writes `runs/<timestamp>-<case>-<model>/` containing `prompt.md`, `reply.md`,
`model.patch`, `security_report.json` and `record.json`, so every outcome can be traced
back to the exact text the model saw and produced. The runner checks the Gateway budget
before every run and stops (exit code 2) instead of starting one it cannot afford. Any
failure inside the pipeline (setup crash, empty reply, missing test report) is recorded
with outcome `error` and is never counted as one of the four outcomes.

**Tests**

```bash
python -m pytest -q
```

Unit tests only: fake scripts, a fake model client, no network, no budget. CI runs
these plus ruff, Bandit and pip-audit on every push; it never executes a CVE-Bench case
or calls a model.

---

## Part 2 · CVE lookup web app (v1)

A security tool for CVE vulnerability lookup. Uses **CPE-based search** against NIST NVD
with CISA KEV cross-referencing.

### What This Tool Does

| Category | Capability | Description |
|----------|------------|-------------|
| **CVE Lookup** | CPE-based NVD search | Map product names to CPE identifiers and query NIST NVD |
| | CISA KEV flagging | Flag CVEs that are actively exploited in the wild |
| **Optional LLM** | Deep analysis | Supplemental CVE analysis via local Ollama (not required) |

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Frontend (Static)                        │
│  ┌─────────────┐  ┌─────────────┐                               │
│  │   app.js    │  │ cve_analyzer│                               │
│  │ (OS Detect) │  │    .js      │                               │
│  └──────┬──────┘  └──────┬──────┘                               │
└─────────┼────────────────┼──────────────────────────────────────┘
          │                │
          ▼                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      FastAPI Backend                             │
│  ┌─────────────┐  ┌─────────────┐                               │
│  │ /api/os-    │  │ /api/cve/   │                               │
│  │   detect    │  │   analyze   │                               │
│  └──────┬──────┘  └──────┬──────┘                               │
│         │                │                                       │
│         ▼                ▼                                       │
│  ┌─────────────┐  ┌─────────────┐                               │
│  │ OS Detector │  │ CVE Search  │                               │
│  │(User-Agent) │  │  Pipeline   │                               │
│  └─────────────┘  └──────┬──────┘                               │
└──────────────────────────┼──────────────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
       ┌─────────────┐          ┌─────────────┐
       │  NIST NVD   │          │  CISA KEV   │
       │ CPE Search  │          │   Catalog   │
       └─────────────┘          └─────────────┘
```

#### CVE Search Pipeline

**NVD CPE Search**: Precise search using CPE (Common Platform Enumeration) identifiers
   - Maps keywords like "Windows 11" to multiple version-specific CPEs (21h2, 22h2, 23h2, 24h2)
   - Returns recent CVEs (2024-2026) with deduplication across versions

### Features

#### CVE Vulnerability Lookup
- **OS Detection**: Auto-detect OS via User-Agent parsing
- **NVD CPE Search**: Map product names to CPE identifiers and query NVD API
- **CISA KEV Cross-referencing**: Flag actively exploited vulnerabilities
- **Vendor Security Links**: Direct links to 15+ vendor security pages
- **LLM Analysis (Optional)**: Supplemental remediation recommendations via local Ollama

### Tech Stack

| Category | Technologies |
|----------|-------------|
| Backend | Python 3.12, FastAPI, Pydantic |
| LLM (Optional) | Ollama via its OpenAI-compatible API (local inference) |
| Frontend | HTML5, CSS3, Vanilla JavaScript |

### Data Sources

This project uses the following public APIs and data sources:

| Source | URL | Purpose | License |
|--------|-----|---------|---------|
| **NIST NVD** | https://services.nvd.nist.gov/rest/json/cves/2.0 | Primary CVE data (CPE-based search) | Public Domain |
| **CISA KEV** | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | Known Exploited Vulnerabilities | CC0 1.0 |

> **Disclaimer:** This project is not endorsed by NIST, CISA, or any government agency. Data is provided for educational and research purposes only.

### Quick Start

#### 1. Clone & Install

```bash
git clone https://github.com/SundayC666/mergeworthy.git
cd mergeworthy
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

#### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your settings (optional for local LLM)
```

#### 3. Run

```bash
python main.py
# Open http://localhost:8000
```

#### 4. Enable LLM Features (Optional)

For AI-powered deep analysis and remediation recommendations, install [Ollama](https://ollama.ai):

```bash
# Install Ollama from https://ollama.ai
ollama pull llama3.2:3b
```

The application will automatically detect Ollama and enable:
- **Deep CVE Analysis**: Supplemental remediation recommendations

> **Note:** LLM features are only available when running locally with Ollama installed.

### Security

- **Listens on loopback by default** (`HOST=127.0.0.1`); set `HOST=0.0.0.0` only when other machines must reach it
- **CORS**: Restricted to localhost origins, GET/POST only
- **Security Headers**: X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy
- **Rate Limiting**: slowapi on all endpoints (10-60 req/min per endpoint); hits are logged as security events with the client address
- **Input Sanitization**: query pattern blocklist (logged when triggered), html.escape, length limits
- **Fail closed**: when NVD cannot be queried the API returns 503 "result unknown" instead of an empty, reassuring list
- **Dependencies**: All pinned to exact versions and audited by pip-audit in CI; any known vulnerability fails the build

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/health | Health check |
| GET | /api/os/detect | Detect OS from User-Agent |
| GET | /api/cve/latest | Get latest CVEs for detected OS |
| POST | /api/cve/analyze | Analyze CVE for specific query |
| POST | /api/cve/deep-analyze | LLM-powered CVE analysis (requires Ollama) |
| GET | /api/llm/status | Whether a local LLM is available |
| GET | /api/versions/buttons | Get quick search buttons |
| GET | /api/versions/all | All tracked product versions |

### Standalone skills (`plugins/`)

This project includes standalone security skills that work independently of the FastAPI server. Plugin structure follows the [Trail of Bits skills](https://github.com/trailofbits/skills) open standard and can be used directly in any compatible AI coding assistant.

#### Available Skills

| Skill | Command | Description |
|-------|---------|-------------|
| **CVE Triage** | `/triage <product>` | NVD vulnerability lookup with CISA KEV cross-referencing and SLA prioritization |

#### Standalone Usage

Skills run independently via `uv run` with no server required:

```bash
# CVE triage
uv run plugins/cve-triage/skills/cve-triage/scripts/nvd_lookup.py --product "windows 11"
uv run plugins/cve-triage/skills/cve-triage/scripts/kev_check.py --cve-ids "CVE-2024-21351"
```

Scripts use [PEP 723](https://peps.python.org/pep-0723/) inline metadata for automatic dependency resolution.

## License

MIT License - see [LICENSE](LICENSE)

## Author

**Sunday Chen**
- [LinkedIn](https://www.linkedin.com/in/sunday-chen/)
