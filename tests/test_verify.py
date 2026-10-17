"""Unit tests for harness/verify.py. The project's pytest is replaced by a fake script
that writes a given JSON report, so no CVE-Bench checkout is needed."""

import json
import os
from pathlib import Path

import pytest

from harness.setup_case import Case, HarnessError, SecurityResult
from harness.verify import (
    FIXED_AND_CLEAN,
    FIXED_BUT_BROKE,
    NOT_APPLIED,
    NOT_FIXED,
    RegressionResult,
    classify,
    run_regression_tests,
)

# --- fake project suite ---------------------------------------------------------------


def fake_case(
    tmp_path: Path, tests: dict[str, str], exit_code=None, write_report=True, sleep_s=0
) -> Case:
    """A task dir whose .venv/bin/pytest writes `tests` (nodeid -> outcome) as a report."""
    task_dir = tmp_path / "tasks" / "CVE-0000-0001"
    (task_dir / "repo").mkdir(parents=True)
    (task_dir / ".venv" / "bin").mkdir(parents=True)
    report = {"tests": [{"nodeid": k, "outcome": v} for k, v in tests.items()]}
    if exit_code is None:
        exit_code = 1 if any(v != "passed" for v in tests.values()) else 0
    script = f"""#!/usr/bin/env bash
sleep {sleep_s}
for a in "$@"; do case "$a" in --json-report-file=*) f="${{a#--json-report-file=}}";; esac; done
{"printf %s " + repr(json.dumps(report)) + ' > "$f"' if write_report else ""}
exit {exit_code}
"""
    pytest_bin = task_dir / ".venv" / "bin" / "pytest"
    pytest_bin.write_text(script)
    pytest_bin.chmod(pytest_bin.stat().st_mode | 0o111)
    return Case("CVE-0000-0001", "x/y", ["CWE-1"], 1.0, "a^", "a", "t", task_dir)


def test_regression_run_parses_every_test(tmp_path):
    case = fake_case(tmp_path, {"t::a": "passed", "t::b": "failed", "t::c": "skipped"})
    r = run_regression_tests(case, tmp_path / "r.json")
    assert r.total == 3 and r.exit_code == 1
    assert r.passed_ids == {"t::a"}
    assert r.not_passed_ids == {"t::b", "t::c"}


def test_regression_excludes_security_test_by_name(tmp_path):
    case = fake_case(tmp_path, {"t::a": "passed"})
    log = tmp_path / "args.txt"
    pytest_bin = case.task_dir / ".venv" / "bin" / "pytest"
    pytest_bin.write_text(
        f'#!/usr/bin/env bash\necho "$@" > {log}\n' + pytest_bin.read_text().split("\n", 1)[1]
    )
    run_regression_tests(case, tmp_path / "r.json")
    assert "--ignore-glob=*test_security.py" in log.read_text()


@pytest.mark.parametrize("exit_code", [2, 3, 4, 5])
def test_suite_that_did_not_run_fails_closed(tmp_path, exit_code):
    case = fake_case(tmp_path, {"t::a": "passed"}, exit_code=exit_code)
    with pytest.raises(HarnessError):
        run_regression_tests(case, tmp_path / "r.json")


def test_missing_report_fails_closed(tmp_path):
    case = fake_case(tmp_path, {"t::a": "passed"}, exit_code=0, write_report=False)
    with pytest.raises(HarnessError):
        run_regression_tests(case, tmp_path / "r.json")


def test_zero_tests_fails_closed(tmp_path):
    case = fake_case(tmp_path, {}, exit_code=0)
    with pytest.raises(HarnessError):
        run_regression_tests(case, tmp_path / "r.json")


def test_timeout_is_an_error_not_a_failure(tmp_path):
    case = fake_case(tmp_path, {"t::a": "passed"}, sleep_s=3)
    with pytest.raises(HarnessError, match="exceeded"):
        run_regression_tests(case, tmp_path / "r.json", timeout_s=1)


# --- the four outcomes ------------------------------------------------------------------

SEC_PASS = SecurityResult(passed=1, failed=0, total=1, exit_code=0)
SEC_FAIL = SecurityResult(passed=0, failed=1, total=1, exit_code=1)


def reg(**tests) -> RegressionResult:
    return RegressionResult(outcomes=tests, exit_code=0, duration_s=0.1)


def test_not_applied_wins_over_everything():
    v = classify(applied=False, security=None, baseline=reg(a="passed"), after=None)
    assert v.outcome == NOT_APPLIED


def test_not_fixed_when_security_test_still_fails():
    v = classify(True, SEC_FAIL, reg(a="passed"), reg(a="passed"))
    assert v.outcome == NOT_FIXED


def test_fixed_but_broke_when_a_passing_test_stops_passing():
    v = classify(True, SEC_PASS, reg(a="passed", b="passed"), reg(a="passed", b="failed"))
    assert v.outcome == FIXED_BUT_BROKE
    assert v.broke == ["b"]


def test_fixed_and_clean():
    v = classify(True, SEC_PASS, reg(a="passed", b="passed"), reg(a="passed", b="passed"))
    assert v.outcome == FIXED_AND_CLEAN and v.broke == []


def test_pre_existing_failure_is_excluded_not_charged():
    # `b` was already failing before the patch: still failing afterwards is NOT "broke".
    v = classify(True, SEC_PASS, reg(a="passed", b="failed"), reg(a="passed", b="failed"))
    assert v.outcome == FIXED_AND_CLEAN
    assert v.pre_existing_failures == ["b"]


def test_a_test_that_disappears_counts_as_broken():
    # The patch deleted or renamed a test that used to pass: that is a regression too.
    v = classify(True, SEC_PASS, reg(a="passed", b="passed"), reg(a="passed"))
    assert v.outcome == FIXED_BUT_BROKE and v.broke == ["b"]


def test_newly_passing_is_recorded_not_judged():
    v = classify(True, SEC_PASS, reg(a="passed", b="failed"), reg(a="passed", b="passed"))
    assert v.outcome == FIXED_AND_CLEAN and v.newly_passing == ["b"]


def test_skipped_after_passing_counts_as_broken():
    # A test that passed and is now skipped no longer proves anything: treat as broken,
    # and let the record show it was "skipped" rather than "failed".
    v = classify(True, SEC_PASS, reg(a="passed"), reg(a="skipped"))
    assert v.outcome == FIXED_BUT_BROKE


def test_security_never_ran_is_not_fixed():
    # Applied, but the security run is missing: nothing proves the fix. Not "clean".
    v = classify(True, None, reg(a="passed"), reg(a="passed"))
    assert v.outcome == NOT_FIXED


@pytest.mark.skipif(os.name == "nt", reason="bash fake scripts")
def test_fake_script_is_executable(tmp_path):
    case = fake_case(tmp_path, {"t::a": "passed"})
    assert os.access(case.task_dir / ".venv" / "bin" / "pytest", os.X_OK)
