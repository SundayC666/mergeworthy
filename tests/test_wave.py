"""Unit tests for harness/wave.py: ordering, resume, error re-runs, budget stop.
run_one is replaced by a fake that writes record.json files like the real one."""

import io
import json
from pathlib import Path

from harness.llm import BudgetExhausted
from harness.setup_case import Case
from harness.wave import completed_counts, pending, plan, run_wave


def case(cid: str) -> Case:
    return Case(cid, "x/y", ["CWE-1"], 1.0, "a^", "a", "t", Path("/nonexistent") / cid)


C1, C2 = case("CVE-1"), case("CVE-2")
MODELS = ["m-a", "m-b"]


def write_record(runs_dir: Path, case_id: str, model: str, outcome: str, n: int) -> None:
    d = runs_dir / f"{n:03d}-{case_id}-{model}"
    d.mkdir(parents=True)
    (d / "record.json").write_text(
        json.dumps({"case": case_id, "model": model, "outcome": outcome})
    )


class FakeRunner:
    """Returns scripted outcomes and writes a record per call, like run_one."""

    def __init__(self, runs_dir: Path, outcomes):
        self.runs_dir, self.outcomes, self.calls, self.n = runs_dir, list(outcomes), [], 100

    def __call__(self, case, model, provider, runs_dir):
        self.calls.append((case.id, model))
        item = self.outcomes.pop(0)
        if isinstance(item, Exception):
            raise item
        self.n += 1
        write_record(runs_dir, case.id, model, item, self.n)
        return {"outcome": item, "total_s": 1}


def test_plan_interleaves_models_within_each_case():
    jobs = [(c.id, m, r) for c, m, r in plan([C1, C2], MODELS, 2)]
    assert jobs[:4] == [
        ("CVE-1", "m-a", 0),
        ("CVE-1", "m-b", 0),
        ("CVE-2", "m-a", 0),
        ("CVE-2", "m-b", 0),
    ]
    assert jobs[4][2] == 1  # second repeat only starts after every (case, model) ran once


def test_completed_counts_ignores_errors_and_half_written_records(tmp_path):
    write_record(tmp_path, "CVE-1", "m-a", "fixed-and-clean", 1)
    write_record(tmp_path, "CVE-1", "m-a", "error", 2)
    (tmp_path / "003-broken").mkdir()
    (tmp_path / "003-broken" / "record.json").write_text("{not json")
    assert completed_counts(tmp_path) == {("CVE-1", "m-a"): 1}


def test_pending_skips_pairs_that_already_have_enough_records(tmp_path):
    write_record(tmp_path, "CVE-1", "m-a", "not-fixed", 1)
    write_record(tmp_path, "CVE-1", "m-a", "not-fixed", 2)
    jobs = pending(plan([C1], ["m-a", "m-b"], 2), completed_counts(tmp_path))
    assert [(c.id, m, r) for c, m, r in jobs] == [("CVE-1", "m-b", 0), ("CVE-1", "m-b", 1)]


def test_wave_runs_everything_and_summarises(tmp_path):
    runner = FakeRunner(
        tmp_path, ["fixed-and-clean", "not-applied", "not-fixed", "fixed-but-broke"]
    )
    out = io.StringIO()
    code = run_wave([C1, C2], MODELS, 1, None, tmp_path, runner=runner, out=out)
    assert code == 0 and len(runner.calls) == 4
    assert "4 jobs, 0 already done, 4 to run" in out.getvalue()


def test_wave_resumes_after_budget_stop(tmp_path):
    out = io.StringIO()
    first = FakeRunner(tmp_path, ["fixed-and-clean", BudgetExhausted("only $0.10 left")])
    code = run_wave([C1, C2], MODELS, 1, None, tmp_path, runner=first, out=out)
    assert code == 2 and len(first.calls) == 2
    assert "3 jobs left" in out.getvalue()

    second = FakeRunner(tmp_path, ["not-fixed", "not-fixed", "not-fixed"])
    code = run_wave([C1, C2], MODELS, 1, None, tmp_path, runner=second, out=io.StringIO())
    assert code == 0
    # The one job that succeeded before the stop is not paid for twice.
    assert second.calls == [("CVE-1", "m-b"), ("CVE-2", "m-a"), ("CVE-2", "m-b")]


def test_wave_reruns_error_records(tmp_path):
    write_record(tmp_path, "CVE-1", "m-a", "error", 1)
    runner = FakeRunner(tmp_path, ["fixed-and-clean"])
    assert run_wave([C1], ["m-a"], 1, None, tmp_path, runner=runner, out=io.StringIO()) == 0
    assert runner.calls == [("CVE-1", "m-a")]
