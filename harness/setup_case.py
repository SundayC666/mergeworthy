"""Step 1 of the pipeline: put a CVE-Bench case into its vulnerable state and run its
hidden security tests.

This is a thin wrapper around CVE-Bench's own scripts. For a case <id>:

    <cve_bench_root>/tasks/<id>/setup.sh      clones the project, resets it to the
                                              vulnerable commit, builds a venv
    <cve_bench_root>/tasks/<id>/run_tests.sh  copies the trusted test_security.py into
                                              the repo and runs it; writes a JSON report

Fail-closed rule (see ARCHITECTURE §5): a run that cannot be evaluated (script crashed,
report missing or unreadable) must raise HarnessError. It must never be reported as
"0 tests failed".
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_FILE = REPO_ROOT / "benchmarks" / "cves.yaml"


class HarnessError(RuntimeError):
    """A pipeline step could not produce a trustworthy result."""


@dataclass(frozen=True)
class Case:
    id: str
    project: str
    cwe: list[str]
    cvss: float
    vulnerable_sha: str
    fixed_sha: str
    why: str
    task_dir: Path  # <cve_bench_root>/tasks/<id>
    # Wall-clock limit for one run of the project's own test suite. The rule never
    # changes per case (ARCHITECTURE §5: run everything); only this number may.
    regression_timeout_s: int = 600

    @property
    def repo_dir(self) -> Path:
        """Where setup.sh leaves the project checkout."""
        return self.task_dir / "repo"


@dataclass(frozen=True)
class SecurityResult:
    passed: int
    failed: int
    total: int
    exit_code: int

    @property
    def all_passed(self) -> bool:
        return self.total > 0 and self.failed == 0


def load_cases(cases_file: Path = CASES_FILE) -> list[Case]:
    """Read benchmarks/cves.yaml and resolve each case's task directory."""
    data = yaml.safe_load(cases_file.read_text(encoding="utf-8"))
    root = Path(os.path.expanduser(data["cve_bench_root"]))
    cases = []
    for c in data["cases"]:
        cases.append(
            Case(
                id=c["id"],
                project=c["project"],
                cwe=list(c["cwe"]),
                cvss=float(c["cvss"]),
                vulnerable_sha=str(c["vulnerable_sha"]),
                fixed_sha=str(c["fixed_sha"]),
                why=c["why"],
                task_dir=root / "tasks" / c["id"],
                regression_timeout_s=int(c.get("regression_timeout_s", 600)),
            )
        )
    return cases


def setup(case: Case) -> None:
    """Run the case's setup.sh. Idempotent: always leaves repo/ at the vulnerable commit."""
    result = subprocess.run(
        ["bash", "setup.sh"],
        cwd=case.task_dir,
        check=False,
    )
    if result.returncode != 0:
        raise HarnessError(f"setup.sh failed for {case.id} (exit {result.returncode})")


def run_security_tests(case: Case, report_path: Path) -> SecurityResult:
    """Run the case's run_tests.sh and parse the pytest JSON report it writes.

    run_tests.sh takes the report path as its first argument and exits non-zero when
    any test fails, so a non-zero exit is NORMAL on the vulnerable commit. The only
    error is a missing report: then the tests never ran and nothing can be concluded.
    """
    result = subprocess.run(
        ["bash", "run_tests.sh", str(report_path)],
        cwd=case.task_dir,
        check=False,
    )
    if not report_path.exists():
        raise HarnessError(
            f"run_tests.sh produced no report for {case.id} (exit {result.returncode})"
        )
    report = json.loads(report_path.read_text())
    summary = report.get("summary", {})
    return SecurityResult(
        passed=summary.get("passed", 0),
        failed=summary.get("failed", 0),
        total=summary.get("total", 0),
        exit_code=result.returncode,
    )
