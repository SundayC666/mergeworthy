"""Run a whole wave: every case × every model × N repeats, resumably.

    python -m harness.wave --models claude-sonnet-5,gpt-5.3-codex,gpt-oss-120b --repeats 3
    python -m harness.wave --models gpt-oss:20b --provider ollama --repeats 3 --dev

Rules (decision log 2026-09-26 and 2026-10-18):
  * Interleaved order: for each repeat, for each case, every model runs once before
    the next case. If the budget runs out halfway, every model still has data.
  * Resumable: a (case, model) pair is "done" when runs_dir holds `--repeats` records
    whose outcome is one of the four real outcomes. Records with outcome `error`
    do not count, so a restart automatically re-runs what failed for harness reasons
    and never re-spends on what already succeeded.
  * Stops explicitly on BudgetExhausted (exit code 2) and prints what is left, so the
    next evening starts exactly there.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from dotenv import load_dotenv

from harness.llm import BudgetExhausted
from harness.run_case import DEV_RUNS_DIR, RUNS_DIR, run_one
from harness.setup_case import REPO_ROOT, Case, load_cases
from harness.verify import OUTCOMES


def completed_counts(runs_dir: Path) -> Counter[tuple[str, str]]:
    """How many real (non-error) records exist per (case, model) in runs_dir."""
    counts: Counter[tuple[str, str]] = Counter()
    for record_file in runs_dir.glob("*/record.json"):
        try:
            rec = json.loads(record_file.read_text())
        except json.JSONDecodeError:
            continue  # a half-written record is not a result
        if rec.get("outcome") in OUTCOMES:
            counts[(rec["case"], rec["model"])] += 1
    return counts


def plan(cases: list[Case], models: list[str], repeats: int) -> list[tuple[Case, str, int]]:
    """Interleaved job list: repeat-major, then case, then model."""
    return [(case, model, r) for r in range(repeats) for case in cases for model in models]


def pending(
    jobs: list[tuple[Case, str, int]], done: Counter[tuple[str, str]]
) -> list[tuple[Case, str, int]]:
    """Drop jobs whose (case, model) already has enough real records."""
    return [(c, m, r) for c, m, r in jobs if done[(c.id, m)] <= r]


def run_wave(
    cases: list[Case],
    models: list[str],
    repeats: int,
    provider: str | None,
    runs_dir: Path,
    runner=run_one,
    out=sys.stdout,
) -> int:
    done = completed_counts(runs_dir)
    jobs = pending(plan(cases, models, repeats), done)
    total = len(cases) * len(models) * repeats
    print(f"wave: {total} jobs, {total - len(jobs)} already done, {len(jobs)} to run", file=out)

    results: Counter[tuple[str, str, str]] = Counter()
    for i, (case, model, r) in enumerate(jobs):
        try:
            rec = runner(case, model, provider, runs_dir)
        except BudgetExhausted as exc:
            left = jobs[i:]
            print(f"STOP after {i} runs: {exc}", file=out)
            print(f"      {len(left)} jobs left; rerun the same command to continue.", file=out)
            return 2
        results[(model, case.id, rec["outcome"])] += 1
        print(
            f"[{i + 1}/{len(jobs)}] {case.id:<22} {model:<16} r{r + 1}  {rec['outcome']:<16} "
            f"{rec.get('total_s', '?')}s",
            file=out,
        )

    print("\nthis session:", file=out)
    for (model, case_id, outcome), n in sorted(results.items()):
        print(f"  {model:<16} {case_id:<22} {outcome:<16} ×{n}", file=out)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--models", required=True, help="comma-separated model ids")
    parser.add_argument("--cases", default="all", help="comma-separated case ids, or 'all'")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--provider", choices=["gateway", "ollama"], default=None)
    parser.add_argument("--dev", action="store_true", help="write to runs-dev/ (gitignored)")
    args = parser.parse_args(argv)

    load_dotenv(REPO_ROOT / ".env")
    cases = load_cases()
    if args.cases != "all":
        wanted = set(args.cases.split(","))
        cases = [c for c in cases if c.id in wanted]
        missing = wanted - {c.id for c in cases}
        if missing:
            parser.error(f"unknown case(s): {', '.join(sorted(missing))}")
    models = [m.strip() for m in args.models.split(",") if m.strip()]
    runs_dir = DEV_RUNS_DIR if args.dev else RUNS_DIR
    runs_dir.mkdir(exist_ok=True)
    return run_wave(cases, models, args.repeats, args.provider, runs_dir)


if __name__ == "__main__":
    sys.exit(main())
