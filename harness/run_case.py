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
from datetime import datetime, timezone

from dotenv import load_dotenv

from harness.llm import build_client, call_model, load_model_config
from harness.patch import PROMPT_VERSION, apply_reply, build_prompt_v1, load_target
from harness.setup_case import REPO_ROOT, Case, load_cases, run_security_tests, setup

RUNS_DIR = REPO_ROOT / "runs"


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() or c in "-." else "_" for c in text)


def run_one(case: Case, model: str, provider: str | None) -> dict:
    started = datetime.now(timezone.utc)
    run_id = f"{started:%Y%m%dT%H%M%SZ}-{_slug(case.id)}-{_slug(model)}"
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    record: dict = {
        "run_id": run_id,
        "case": case.id,
        "project": case.project,
        "model": model,
        "provider": provider,
        "prompt_version": PROMPT_VERSION,
        "started_at": started.isoformat(),
        "outcome": "error",  # overwritten only when the pipeline reaches a verdict
    }
    t0 = time.monotonic()
    try:
        setup(case)
        record["setup_s"] = round(time.monotonic() - t0, 1)

        advisory, target, snippet = load_target(case)
        system, user = build_prompt_v1(advisory, target, snippet)
        (run_dir / "prompt.md").write_text(f"# system\n\n{system}\n\n# user\n\n{user}")
        record["target"] = {
            "file": target.file,
            "qualname": target.qualname,
            "lines": [snippet.start_line, snippet.end_line],
        }
        record["prompt_chars"] = len(system) + len(user)

        cfg = load_model_config(model, provider)
        record["provider"] = cfg.provider
        record["temperature"] = cfg.temperature
        call = call_model(build_client(cfg), cfg, system, user)
        (run_dir / "reply.md").write_text(call.text)
        record["model_call"] = {
            "params_used": call.params_used,
            "notes": call.notes,
            "prompt_tokens": call.prompt_tokens,
            "completion_tokens": call.completion_tokens,
            "latency_s": round(call.latency_s, 1),
            "finish_reason": call.finish_reason,
        }

        applied = apply_reply(case, call.text, run_dir / "model.patch")
        record["apply"] = {
            "applied": applied.applied,
            "reason": applied.reason,
            "detail": applied.detail,
            "files": applied.files,
            "touches_tests": applied.touches_tests,
        }
        if not applied.applied:
            record["outcome"] = "not-applied"
        else:
            sec = run_security_tests(case, run_dir / "security_report.json")
            record["security_tests"] = {**asdict(sec), "all_passed": sec.all_passed}
            record["outcome"] = "security-pass" if sec.all_passed else "security-fail"
            record["regression_tests"] = "not run yet (verify.py pending)"
    except Exception as exc:  # noqa: BLE001 - every failure must land in the record
        record["error"] = f"{type(exc).__name__}: {exc}"
        if getattr(exc, "usage", None):  # an empty reply still consumed tokens
            record["model_call"] = exc.usage
        (run_dir / "traceback.txt").write_text(traceback.format_exc())
    finally:
        record["total_s"] = round(time.monotonic() - t0, 1)
        (run_dir / "record.json").write_text(json.dumps(record, indent=2))
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--case", required=True, help="case id from benchmarks/cves.yaml, or 'all'")
    parser.add_argument("--model", required=True, help="model id as the provider knows it")
    parser.add_argument("--provider", choices=["gateway", "ollama"], default=None,
                        help="default: HARNESS_PROVIDER from .env, else gateway")
    args = parser.parse_args(argv)

    load_dotenv(REPO_ROOT / ".env")
    cases = load_cases()
    if args.case != "all":
        cases = [c for c in cases if c.id == args.case]
        if not cases:
            parser.error(f"unknown case {args.case!r}")

    exit_code = 0
    for case in cases:
        rec = run_one(case, args.model, args.provider)
        tokens = rec.get("model_call", {})
        print(
            f"{rec['case']:<22} {rec['model']:<16} {rec['outcome']:<14} "
            f"{rec['total_s']:>6}s  in={tokens.get('prompt_tokens')} out={tokens.get('completion_tokens')}"
            + (f"  apply:{rec['apply']['reason']}" if rec.get("apply", {}).get("reason") else "")
            + (f"  ERROR {rec['error']}" if "error" in rec else "")
        )
        if "error" in rec:
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
