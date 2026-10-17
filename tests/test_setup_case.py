"""Tests for harness/setup_case.py.

The fake task directory below stands in for a real CVE-Bench task so these tests need
neither the network nor Docker. Each fake script records that it ran and writes the kind
of JSON report pytest-json-report would write.
"""

import json
import stat
from pathlib import Path

import pytest

from harness.setup_case import (
    CASES_FILE,
    Case,
    HarnessError,
    load_cases,
    run_security_tests,
    setup,
)


def _write_script(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def fake_case(
    tmp_path: Path, *, passed: int, failed: int, write_report: bool = True, setup_exit: int = 0
) -> Case:
    task_dir = tmp_path / "tasks" / "CVE-0000-0001"
    task_dir.mkdir(parents=True)
    _write_script(task_dir / "setup.sh", f"touch setup_ran\nexit {setup_exit}\n")
    total = passed + failed
    report = json.dumps(
        {
            "summary": {"passed": passed, "failed": failed, "total": total},
            "exitcode": 1 if failed else 0,
        }
    )
    body = 'REPORT="${1:-/tmp/eval_report.json}"\n'
    if write_report:
        body += f"printf '%s' '{report}' > \"$REPORT\"\n"
    body += f"exit {1 if failed else 0}\n"
    _write_script(task_dir / "run_tests.sh", body)
    return Case(
        id="CVE-0000-0001",
        project="x/y",
        cwe=["CWE-1"],
        cvss=1.0,
        vulnerable_sha="a^",
        fixed_sha="a",
        why="test",
        task_dir=task_dir,
    )


# ---- load_cases: reads the real benchmarks/cves.yaml --------------------------------


def test_load_cases_reads_the_five_phase1_cases():
    cases = load_cases(CASES_FILE)
    assert [c.id for c in cases] == [
        "CVE-2026-24486",
        "GHSA-r758-8hxw-4845",
        "CVE-2026-26331",
        "CVE-2026-32714",
        "CVE-2026-33175",
    ]
    assert all(c.task_dir.name == c.id for c in cases)
    assert all(c.why for c in cases)


# ---- setup --------------------------------------------------------------------------


def test_setup_runs_the_task_script(tmp_path):
    case = fake_case(tmp_path, passed=0, failed=1)
    setup(case)
    assert (case.task_dir / "setup_ran").exists()


def test_setup_fails_closed_when_script_fails(tmp_path):
    case = fake_case(tmp_path, passed=0, failed=1, setup_exit=3)
    with pytest.raises(HarnessError):
        setup(case)


# ---- run_security_tests ---------------------------------------------------------------


def test_failing_security_tests_are_reported_not_raised(tmp_path):
    # On the vulnerable commit the security test FAILS. That is a result, not an error.
    case = fake_case(tmp_path, passed=0, failed=1)
    result = run_security_tests(case, tmp_path / "report.json")
    assert (result.passed, result.failed, result.total) == (0, 1, 1)
    assert result.exit_code != 0
    assert result.all_passed is False


def test_passing_security_tests(tmp_path):
    case = fake_case(tmp_path, passed=4, failed=0)
    result = run_security_tests(case, tmp_path / "report.json")
    assert (result.passed, result.failed, result.total) == (4, 0, 4)
    assert result.all_passed is True


def test_missing_report_fails_closed(tmp_path):
    # The script exited 0 but wrote no report: the tests never ran.
    # This must NOT come back as "0 failed" (that would be the NVD fail-open bug again).
    case = fake_case(tmp_path, passed=0, failed=0, write_report=False)
    with pytest.raises(HarnessError):
        run_security_tests(case, tmp_path / "report.json")


def test_zero_tests_is_not_a_pass(tmp_path):
    case = fake_case(tmp_path, passed=0, failed=0)
    result = run_security_tests(case, tmp_path / "report.json")
    assert result.all_passed is False
