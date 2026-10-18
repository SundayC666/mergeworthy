"""Unit tests for harness/report.py on a handful of synthetic records."""

import json
from pathlib import Path

from harness.report import (
    apply_failures,
    load_records,
    per_model,
    render_markdown,
    scanner_vs_verdict,
)


def rec(
    model,
    case,
    outcome,
    *,
    applied=True,
    reason="",
    ws=False,
    before=True,
    after=False,
    seconds=10,
    cost=0.01,
):
    r = {
        "model": model,
        "case": case,
        "outcome": outcome,
        "total_s": seconds,
        "model_call": {"prompt_tokens": 1000, "completion_tokens": 500},
        "gateway_cost_usd_lower_bound": cost,
        "apply": {"applied": applied, "reason": reason, "would_apply_ignoring_whitespace": ws},
        "scan_before": {"bandit": {"found_in_file": before, "error": None}},
    }
    if applied:
        r["scan_after"] = {"bandit": {"found_in_file": after, "error": None}}
    return r


def write(runs: Path, i: int, r: dict) -> None:
    d = runs / f"{i:03d}-{r['case']}-{r['model']}"
    d.mkdir(parents=True)
    (d / "record.json").write_text(json.dumps(r))


RECORDS = [
    rec("m", "C1", "fixed-and-clean", before=True, after=False),
    rec("m", "C1", "not-fixed", before=True, after=False),  # scanner quiet but NOT fixed
    rec("m", "C2", "not-applied", applied=False, reason="git-apply-failed", ws=True),
    rec("m", "C2", "fixed-but-broke", before=False),
    {"model": "m", "case": "C2", "outcome": "error", "error": "ModelCallError: empty"},
    rec("n", "C1", "not-applied", applied=False, reason="no-diff-in-reply"),
]


def test_per_model_keeps_errors_out_of_the_denominator():
    pm = per_model(RECORDS)
    assert pm["m"]["runs"] == 4 and pm["m"]["errors"] == 1
    assert pm["m"]["counts"] == {
        "not-applied": 1,
        "not-fixed": 1,
        "fixed-but-broke": 1,
        "fixed-and-clean": 1,
    }
    assert pm["n"]["runs"] == 1 and pm["n"]["gateway_cost_usd_lower_bound"] == 0.01


def test_apply_failures_split_reason_and_whitespace():
    af = apply_failures(RECORDS)
    assert af["m"] == {"git-apply-failed": 1, "(of which whitespace-only)": 1}
    assert af["n"] == {"no-diff-in-reply": 1}


def test_scanner_quiet_is_crossed_with_the_verdict():
    sv = scanner_vs_verdict(RECORDS)
    assert sv[("saw it; went quiet", "fixed-and-clean")] == 1
    assert sv[("saw it; went quiet", "not-fixed")] == 1  # the "scanner green != fixed" cell
    assert sv[("scanner blind before patch", "fixed-but-broke")] == 1
    assert sv[("saw it; patch not applied", "not-applied")] == 2


def test_markdown_has_the_four_tables_and_rates(tmp_path):
    md = render_markdown(RECORDS, tmp_path)
    assert "## Per model" in md and "## Model × case" in md
    assert "1/4 (25%)" in md  # each outcome once out of four real runs for model m
    assert "Scanner results are recorded only" in md


def test_load_records_skips_half_written_files(tmp_path):
    write(tmp_path, 1, RECORDS[0])
    (tmp_path / "002-bad").mkdir()
    (tmp_path / "002-bad" / "record.json").write_text("{")
    recs = load_records(tmp_path)
    assert len(recs) == 1 and recs[0]["_folder"].startswith("001-")
