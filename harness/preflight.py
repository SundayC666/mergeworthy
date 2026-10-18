"""Checks to run BEFORE a wave spends anything.

    python -m harness.preflight --models claude-sonnet-5,gpt-5.3-codex,gpt-oss-120b

A wave is an evening of unattended runs. Everything that can be verified for free in
ten seconds is verified here first: the CVE-Bench checkout, the scanners, the Gateway
(VPN, key, budget) and, per model, one five-token completion so that a wrong model id
or a rejected parameter shows up now and not in run 17.

What this cannot catch: the Gateway's own budget counter running ahead of /key/info
mid-wave (seen 2026-10-18 as 422 "Budget has been exceeded"). That is handled by the
runner, which stops the wave on that error.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from harness.llm import (
    BudgetExhausted,
    ModelConfigError,
    assert_budget,
    build_client,
    load_model_config,
)
from harness.setup_case import REPO_ROOT, Case, load_cases

PING_MAX_TOKENS = 5


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    fatal: bool = True  # a non-fatal failure is reported but does not block the wave


def check_cases(cases: list[Case]) -> list[Check]:
    out = []
    for c in cases:
        missing = [
            n
            for n in ("setup.sh", "run_tests.sh", "test_security.py", "advisory.md", "locate.md")
            if not (c.task_dir / n).exists()
        ]
        out.append(
            Check(f"case {c.id}", not missing, f"missing {missing}" if missing else str(c.task_dir))
        )
    return out


def check_tools() -> list[Check]:
    bandit = Path(sys.executable).parent / "bandit"
    semgrep = shutil.which("semgrep") or (Path.home() / ".local" / "bin" / "semgrep")
    return [
        Check("bandit", bandit.exists(), str(bandit)),
        Check(
            "semgrep",
            Path(semgrep).exists(),
            str(semgrep)
            if Path(semgrep).exists()
            else "not installed; semgrep column will be error",
            fatal=False,
        ),
    ]


def ping_model(model: str, provider: str | None, client_factory=build_client) -> Check:
    """One tiny completion: proves VPN, key, model id and default params in one go."""
    try:
        cfg = load_model_config(model, provider)
        budget = assert_budget(cfg)
    except (ModelConfigError, BudgetExhausted) as exc:
        return Check(f"model {model}", False, f"{type(exc).__name__}: {exc}")
    client = client_factory(cfg)
    started = time.monotonic()
    try:
        response = client.chat.completions.create(
            model=cfg.model,
            messages=[{"role": "user", "content": "Reply with the single word OK."}],
            max_tokens=PING_MAX_TOKENS,
            **({"extra_body": {"cache": {"no-cache": True}}} if cfg.provider == "gateway" else {}),
        )
    except Exception as exc:  # noqa: BLE001 - any failure here is exactly what we want to see
        return Check(f"model {model}", False, f"{type(exc).__name__}: {str(exc)[:160]}")
    latency = time.monotonic() - started
    text = (response.choices[0].message.content or "").strip()
    remaining = (
        "" if budget is None or budget.remaining is None else f", ${budget.remaining:.2f} left"
    )
    return Check(f"model {model}", True, f"{latency:.1f}s, replied {text[:20]!r}{remaining}")


def run_preflight(
    cases: list[Case], models: list[str], provider: str | None, client_factory=build_client
) -> list[Check]:
    checks = check_cases(cases) + check_tools()
    checks += [ping_model(m, provider, client_factory) for m in models]
    return checks


def render(checks: list[Check]) -> str:
    lines = []
    for c in checks:
        mark = "ok  " if c.ok else ("WARN" if not c.fatal else "FAIL")
        lines.append(f"[{mark}] {c.name}: {c.detail}")
    blocking = [c for c in checks if not c.ok and c.fatal]
    lines.append("preflight: " + ("GO" if not blocking else f"NO-GO ({len(blocking)} blocking)"))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--models", required=True, help="comma-separated model ids")
    parser.add_argument("--provider", choices=["gateway", "ollama"], default=None)
    args = parser.parse_args(argv)
    load_dotenv(REPO_ROOT / ".env")
    models = [m.strip() for m in args.models.split(",") if m.strip()]
    checks = run_preflight(load_cases(), models, args.provider)
    print(render(checks))
    return 0 if all(c.ok or not c.fatal for c in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
