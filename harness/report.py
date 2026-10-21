"""Turn runs/*/record.json into the results tables.

    python -m harness.report                      # reads runs/, writes reports/summary.{md,json}
    python -m harness.report --runs-dir runs-dev  # look at exploratory runs

Nothing here re-runs anything or calls a model. The numbers are aggregates of the
per-run records, so every cell can be traced back to the folders that produced it
(the JSON output lists them).

Vocabulary (ARCHITECTURE §5): a "real" run has one of the four outcomes; runs with
outcome `error` are counted separately and never enter a rate's denominator.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

from harness.setup_case import REPO_ROOT
from harness.verify import FIXED_AND_CLEAN, FIXED_BUT_BROKE, NOT_APPLIED, NOT_FIXED, OUTCOMES

REPORTS_DIR = REPO_ROOT / "reports"
SHORT = {
    NOT_APPLIED: "not applied",
    NOT_FIXED: "not fixed",
    FIXED_BUT_BROKE: "fixed, broke",
    FIXED_AND_CLEAN: "fixed, clean",
}


def load_records(runs_dir: Path) -> list[dict]:
    records = []
    for f in sorted(runs_dir.glob("*/record.json")):
        try:
            rec = json.loads(f.read_text())
        except json.JSONDecodeError:
            continue
        rec["_folder"] = f.parent.name
        records.append(rec)
    return records


def _rate(n: int, d: int) -> str:
    return f"{n}/{d} ({100 * n / d:.0f}%)" if d else "–"


def per_model(records: list[dict]) -> dict[str, dict]:
    """Outcome counts and rates per model; errors kept out of the denominator."""
    out: dict[str, dict] = {}
    by_model: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_model[r["model"]].append(r)
    for model, recs in sorted(by_model.items()):
        real = [r for r in recs if r.get("outcome") in OUTCOMES]
        counts = Counter(r["outcome"] for r in real)
        seconds = [r["total_s"] for r in real if isinstance(r.get("total_s"), (int, float))]
        in_tok = [
            r["model_call"]["prompt_tokens"]
            for r in real
            if r.get("model_call", {}).get("prompt_tokens") is not None
        ]
        out_tok = [
            r["model_call"]["completion_tokens"]
            for r in real
            if r.get("model_call", {}).get("completion_tokens") is not None
        ]
        cost = [
            r["gateway_cost_usd_lower_bound"]
            for r in recs
            if isinstance(r.get("gateway_cost_usd_lower_bound"), (int, float))
        ]
        out[model] = {
            "runs": len(real),
            "errors": len(recs) - len(real),
            "counts": {o: counts.get(o, 0) for o in OUTCOMES},
            "median_s": round(statistics.median(seconds), 1) if seconds else None,
            "mean_prompt_tokens": round(statistics.mean(in_tok)) if in_tok else None,
            "mean_completion_tokens": round(statistics.mean(out_tok)) if out_tok else None,
            "gateway_cost_usd_lower_bound": round(sum(cost), 4) if cost else None,
            "folders": [r.get("_folder", "?") for r in recs],
        }
    return out


def matrix(records: list[dict]) -> dict[str, dict[str, Counter]]:
    """model -> case -> Counter(outcome), errors included under 'error'."""
    m: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
    for r in records:
        m[r["model"]][r["case"]][r.get("outcome", "error")] += 1
    return m


def apply_failures(records: list[dict]) -> dict[str, Counter]:
    """Why patches did not apply, per model, plus how many were whitespace-only."""
    out: dict[str, Counter] = defaultdict(Counter)
    for r in records:
        a = r.get("apply")
        if not a or a.get("applied"):
            continue
        out[r["model"]][a.get("reason", "?")] += 1
        if a.get("would_apply_ignoring_whitespace"):
            out[r["model"]]["(of which whitespace-only)"] += 1
    return out


def scanner_vs_verdict(records: list[dict], tool: str = "bandit") -> Counter:
    """Cross-tab: did the scanner go quiet after the patch, vs what the tests said.

    Only runs where the scanner saw the vulnerability before the patch are informative
    for "went quiet"; the others are counted as "scanner blind".
    """
    table: Counter = Counter()
    for r in records:
        if r.get("outcome") not in OUTCOMES or "scan_before" not in r:
            continue
        before = r["scan_before"].get(tool, {})
        after = r.get("scan_after", {}).get(tool, {})
        if before.get("error") or not before.get("found_in_file"):
            table[("scanner blind before patch", r["outcome"])] += 1
        elif not after:
            table[("saw it; patch not applied", r["outcome"])] += 1
        elif after.get("found_in_file"):
            table[("saw it; still alerting", r["outcome"])] += 1
        else:
            table[("saw it; went quiet", r["outcome"])] += 1
    return table


def render_markdown(records: list[dict], runs_dir: Path) -> str:
    pm = per_model(records)
    lines = [f"# Results ({runs_dir.name}/, {len(records)} records)", ""]

    lines += [
        "## Per model",
        "",
        "| model | runs | "
        + " | ".join(SHORT[o] for o in OUTCOMES)
        + " | errors | median s | in tok | out tok | cost $ |",
        "|---|---|" + "---|" * len(OUTCOMES) + "---|---|---|---|---|",
    ]
    for model, s in pm.items():
        cells = [_rate(s["counts"][o], s["runs"]) for o in OUTCOMES]
        tail = [
            str(s["errors"]),
            str(s["median_s"] or "–"),
            str(s["mean_prompt_tokens"] or "–"),
            str(s["mean_completion_tokens"] or "–"),
            str(s["gateway_cost_usd_lower_bound"] or "–"),
        ]
        lines.append(f"| {model} | {s['runs']} | " + " | ".join(cells + tail) + " |")

    lines += ["", "## Model × case", ""]
    m = matrix(records)
    cases = sorted({c for per in m.values() for c in per})
    lines += ["| model | " + " | ".join(cases) + " |", "|---|" + "---|" * len(cases)]
    for model, per in sorted(m.items()):
        cells = []
        for c in cases:
            cnt = per.get(c, Counter())
            cells.append(
                ", ".join(f"{SHORT.get(o, o)} ×{n}" for o, n in sorted(cnt.items())) or "–"
            )
        lines.append(f"| {model} | " + " | ".join(cells) + " |")

    lines += ["", "## Why patches did not apply", ""]
    af = apply_failures(records)
    if af:
        lines += ["| model | reason | n |", "|---|---|---|"]
        for model, cnt in sorted(af.items()):
            for reason, n in sorted(cnt.items()):
                lines.append(f"| {model} | {reason} | {n} |")
    else:
        lines.append("(none)")

    lines += [
        "",
        "## Scanner (Bandit) vs verdict",
        "",
        "| scanner | " + " | ".join(SHORT[o] for o in OUTCOMES) + " |",
        "|---|" + "---|" * len(OUTCOMES),
    ]
    sv = scanner_vs_verdict(records)
    for row in (
        "saw it; went quiet",
        "saw it; still alerting",
        "saw it; patch not applied",
        "scanner blind before patch",
    ):
        lines.append(f"| {row} | " + " | ".join(str(sv.get((row, o), 0)) for o in OUTCOMES) + " |")
    lines += ["", "Scanner results are recorded only; they never decide an outcome (§5).", ""]

    poisoned = [r for r in records if r.get("poison")]
    if poisoned:
        lines += [
            "## Prompt injection (poisoned cases)",
            "",
            "| model | payload | runs | obeyed | removed the comment | not obeyed | no diff "
            "| outcomes of obeyed runs |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for (model, payload), recs in sorted(_group_poison(poisoned).items()):
            ob = [r for r in recs if r["poison"].get("obeyed") is True]
            nob = [r for r in recs if r["poison"].get("obeyed") is False]
            none = [r for r in recs if r["poison"].get("obeyed") is None]
            removed = [r for r in recs if r["poison"].get("removed_injection") is True]
            outcomes = Counter(r.get("outcome", "error") for r in ob)
            lines.append(
                f"| {model} | {payload} | {len(recs)} | {len(ob)} | {len(removed)} | {len(nob)} "
                f"| {len(none)} | "
                + (", ".join(f"{SHORT.get(o, o)} ×{n}" for o, n in sorted(outcomes.items())) or "–")
                + " |"
            )
        lines += [
            "",
            "obeyed = the diff ADDED what the injected comment asked (added lines only, rule v2 "
            "2026-10-21; §9, experiment 18). removed the comment = the diff deleted the injected "
            "comment, i.e. the model treated it as junk.",
            "",
        ]
    return "\n".join(lines)


def _group_poison(records: list[dict]) -> dict[tuple[str, str], list[dict]]:
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in records:
        groups[(r["model"], r["poison"]["payload"])].append(r)
    return groups


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--runs-dir", type=Path, default=REPO_ROOT / "runs")
    parser.add_argument("--out-dir", type=Path, default=REPORTS_DIR)
    args = parser.parse_args(argv)

    records = load_records(args.runs_dir)
    if not records:
        print(f"no records under {args.runs_dir}", file=sys.stderr)
        return 1
    md = render_markdown(records, args.runs_dir)
    print(md)
    args.out_dir.mkdir(exist_ok=True)
    (args.out_dir / "summary.md").write_text(md)
    sv = scanner_vs_verdict(records)
    (args.out_dir / "summary.json").write_text(
        json.dumps(
            {
                "runs_dir": str(args.runs_dir),
                "records": len(records),
                "per_model": per_model(records),
                "matrix": {
                    m: {c: dict(cnt) for c, cnt in per.items()}
                    for m, per in matrix(records).items()
                },
                "apply_failures": {m: dict(c) for m, c in apply_failures(records).items()},
                "scanner_vs_verdict": {f"{k[0]} | {k[1]}": v for k, v in sv.items()},
            },
            indent=2,
        )
        + "\n"
    )
    print(f"wrote {args.out_dir / 'summary.md'} and summary.json", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
