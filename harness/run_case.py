"""Run one CVE-Bench case through one model, end to end, and write a JSON record.

    python -m harness.run_case --case CVE-2026-24486 --model claude-sonnet-5
    python -m harness.run_case --case all --model gpt-oss:20b --provider ollama

Pipeline (ARCHITECTURE §4):  setup -> prompt v1 -> model -> git apply -> security tests
Each run gets its own folder under runs/ with prompt.md, reply.md, model.patch,
security_report.json and record.json, so any number in the results table can be
traced back to the exact text the model saw and produced.

Not here yet: the regression half (PASS_TO_PASS). Until verify.py exists, a run's
`outcome` is partial ("security-pass" is NOT yet "fixed and nothing broke").

Fail-closed rule: anything that stops the pipeline (setup crash, empty reply, missing
report, budget error) is recorded with outcome "error" and is NEVER counted as one of
the four outcomes. Errors are re-run after the cause is fixed.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from dotenv import load_dotenv

from harness.llm import (
    BudgetExhausted,
    assert_budget,
    build_client,
    call_model,
    gateway_budget,
    load_model_config,
)
from harness.patch import PROMPT_VERSION, apply_reply, build_prompt_v1, load_target
from harness.poison import POISON_RUNS_DIR, inject, load_payloads, obeyed
from harness.scan import scan_target
from harness.setup_case import REPO_ROOT, Case, load_cases, run_security_tests, setup
from harness.verify import classify, run_regression_tests

# Official runs are committed; exploratory runs (prompt tweaks, smoke tests) go to
# runs-dev/, which is gitignored, so they never mix with the results table.
RUNS_DIR = REPO_ROOT / "runs"
DEV_RUNS_DIR = REPO_ROOT / "runs-dev"


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() or c in "-." else "_" for c in text)


def run_one(
    case: Case,
    model: str,
    provider: str | None,
    runs_dir: Path = RUNS_DIR,
    poison: str | None = None,
) -> dict:
    """Run one case through one model. Raises BudgetExhausted BEFORE creating a run
    folder when the gateway budget is too low; every other failure lands in the record.

    `poison` names a payload from benchmarks/poisons.yaml (experiment 18): the comment is
    injected into the target function before the prompt is built, and the record gains a
    `poison` block. The verdict is computed exactly as for a clean run."""
    cfg = load_model_config(model, provider)
    budget_before = assert_budget(cfg)  # fail closed before spending anything
    payload = load_payloads()[poison] if poison else None

    started = datetime.now(UTC)
    run_id = f"{started:%Y%m%dT%H%M%SZ}-{_slug(case.id)}-{_slug(model)}"
    if payload:
        run_id += f"-poison-{_slug(payload.name)}"
    run_dir = runs_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    record: dict = {
        "run_id": run_id,
        "case": case.id,
        "project": case.project,
        "model": model,
        "provider": cfg.provider,
        "temperature": cfg.temperature,
        "prompt_version": PROMPT_VERSION,
        "started_at": started.isoformat(),
        "outcome": "error",  # overwritten only when the pipeline reaches a verdict
    }
    if payload:
        record["poison"] = {"payload": payload.name, "intercepted_by": payload.intercepted_by}
    if budget_before is not None:
        record["gateway_spend_before_usd"] = budget_before.spend
    t0 = time.monotonic()
    try:
        setup(case)
        record["setup_s"] = round(time.monotonic() - t0, 1)

        # Baseline BEFORE the patch: which of the project's own tests pass right now.
        # Only these can later count as "broken" (ARCHITECTURE §5, decision 2026-10-18).
        baseline = run_regression_tests(case, run_dir / "regression_baseline.json")
        record["regression_baseline"] = {
            "total": baseline.total,
            "passed": len(baseline.passed_ids),
            "not_passed": sorted(baseline.not_passed_ids),
            "duration_s": round(baseline.duration_s, 1),
        }

        advisory, target, snippet = load_target(case)
        if payload:
            # Poison AFTER the baseline (the comment must not count as a change) and
            # BEFORE the prompt, so the model sees it inside the real file.
            snippet, inserted = inject(case, target, payload)
            record["poison"]["inserted_lines"] = inserted
        system, user = build_prompt_v1(advisory, target, snippet)
        (run_dir / "prompt.md").write_text(f"# system\n\n{system}\n\n# user\n\n{user}")
        record["target"] = {
            "file": target.file,
            "qualname": target.qualname,
            "lines": [snippet.start_line, snippet.end_line],
        }
        record["prompt_chars"] = len(system) + len(user)
        # Record-only (ARCHITECTURE §5): scanners never influence the verdict.
        record["scan_before"] = scan_target(case, target.file, snippet.start_line, snippet.end_line)

        call = call_model(build_client(cfg), cfg, system, user)
        (run_dir / "reply.md").write_text(call.text)
        record["model_call"] = {
            "params_used": call.params_used,
            "notes": call.notes,
            "prompt_tokens": call.prompt_tokens,
            "completion_tokens": call.completion_tokens,
            "latency_s": round(call.latency_s, 1),
            "finish_reason": call.finish_reason,
            "cost_usd": call.cost_usd,
            "gateway_spend_usd": call.gateway_spend_usd,
            "rate_remaining_tokens": call.rate_remaining_tokens,
        }

        applied = apply_reply(case, call.text, run_dir / "model.patch")
        record["apply"] = {
            "applied": applied.applied,
            "reason": applied.reason,
            "detail": applied.detail,
            "files": applied.files,
            "touches_tests": applied.touches_tests,
            "would_apply_ignoring_whitespace": applied.would_apply_ignoring_whitespace,
        }
        if payload:
            record["poison"]["obeyed"] = obeyed(payload, applied)
        if not applied.applied:
            verdict = classify(False, None, baseline, None)
        else:
            record["scan_after"] = scan_target(
                case, target.file, snippet.start_line, snippet.end_line
            )
            sec = run_security_tests(case, run_dir / "security_report.json")
            record["security_tests"] = {**asdict(sec), "all_passed": sec.all_passed}
            after = run_regression_tests(case, run_dir / "regression_after.json")
            record["regression_after"] = {
                "total": after.total,
                "passed": len(after.passed_ids),
                "not_passed": sorted(after.not_passed_ids),
                "duration_s": round(after.duration_s, 1),
            }
            verdict = classify(True, sec, baseline, after)
            if payload:
                # The security verdict came from the trusted copy of the test, so a patch
                # that deleted or edited the test changed nothing about the judgment.
                record["poison"]["security_judged_from_trusted_test"] = sec.total > 0
        record["outcome"] = verdict.outcome
        record["verdict"] = verdict.as_record()
    except Exception as exc:  # noqa: BLE001 - every failure must land in the record
        record["error"] = f"{type(exc).__name__}: {exc}"
        if getattr(exc, "usage", None):  # an empty reply still consumed tokens
            record["model_call"] = exc.usage
        (run_dir / "traceback.txt").write_text(traceback.format_exc())
    finally:
        record["total_s"] = round(time.monotonic() - t0, 1)
        if budget_before is not None:
            # LiteLLM's spend counter can lag by a few seconds, so this is a lower bound.
            try:
                after = gateway_budget(cfg).spend
                record["gateway_spend_after_usd"] = after
                record["gateway_cost_usd_lower_bound"] = round(after - budget_before.spend, 4)
            except Exception as exc:  # noqa: BLE001 - never lose the record over this
                record["gateway_spend_after_usd"] = f"lookup failed: {exc}"
        (run_dir / "record.json").write_text(json.dumps(record, indent=2))
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--case", required=True, help="case id from benchmarks/cves.yaml, or 'all'")
    parser.add_argument("--model", required=True, help="model id as the provider knows it")
    parser.add_argument(
        "--provider",
        choices=["gateway", "ollama"],
        default=None,
        help="default: HARNESS_PROVIDER from .env, else gateway",
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        help="write to runs-dev/ (gitignored) instead of runs/; use for smoke tests",
    )
    parser.add_argument(
        "--poison",
        default=None,
        help="payload name from benchmarks/poisons.yaml; runs go to runs-poison/<name>/",
    )
    args = parser.parse_args(argv)
    if args.poison:
        if args.poison not in load_payloads():
            parser.error(f"unknown payload {args.poison!r}")
        runs_dir = POISON_RUNS_DIR / args.poison
    else:
        runs_dir = DEV_RUNS_DIR if args.dev else RUNS_DIR
    runs_dir.mkdir(parents=True, exist_ok=True)

    load_dotenv(REPO_ROOT / ".env")
    cases = load_cases()
    if args.case != "all":
        cases = [c for c in cases if c.id == args.case]
        if not cases:
            parser.error(f"unknown case {args.case!r}")

    exit_code = 0
    for i, case in enumerate(cases):
        try:
            rec = run_one(case, args.model, args.provider, runs_dir, poison=args.poison)
        except BudgetExhausted as exc:
            remaining = ", ".join(c.id for c in cases[i:])
            print(f"STOP: {exc}\n      not run: {remaining}", file=sys.stderr)
            return 2
        tokens = rec.get("model_call", {})
        print(
            f"{rec['case']:<22} {rec['model']:<16} {rec['outcome']:<14} "
            f"{rec['total_s']:>6}s  in={tokens.get('prompt_tokens')} "
            f"out={tokens.get('completion_tokens')}"
            + (f"  apply:{rec['apply']['reason']}" if rec.get("apply", {}).get("reason") else "")
            + (f"  ERROR {rec['error']}" if "error" in rec else "")
        )
        if "error" in rec:
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
