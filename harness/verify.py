"""Step 3 of the pipeline: the regression half, and the four-way verdict.

"Fixed" is decided by the security test (FAIL_TO_PASS, see setup_case.py).
"Nothing broke" is decided here (PASS_TO_PASS): the project's OWN test suite is run
twice, once before the patch (baseline) and once after. A test counts as broken when
it passed at baseline and no longer passes afterwards. Tests that were not passing at
baseline are excluded from the judgment and recorded, so a project's pre-existing
red tests are never charged to the model.

What "the project's own test suite" means: whatever `pytest` runs by default in that
repository, i.e. the project's pytest.ini / pyproject settings are inherited (yt-dlp,
for example, excludes network download tests by default). Only the harness's injected
security test file is removed from the run. Decision log, 2026-10-18.

Fail-closed rules: a suite that cannot run (pytest crashed, timed out, produced no
report, collected zero tests) raises HarnessError, so the run becomes `error`, not
one of the four outcomes.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from harness.setup_case import Case, HarnessError, SecurityResult

NOT_APPLIED = "not-applied"
NOT_FIXED = "not-fixed"
FIXED_BUT_BROKE = "fixed-but-broke"
FIXED_AND_CLEAN = "fixed-and-clean"
OUTCOMES = (NOT_APPLIED, NOT_FIXED, FIXED_BUT_BROKE, FIXED_AND_CLEAN)

# pytest exit codes: 0 all passed, 1 some failed, 2 interrupted, 3 internal error,
# 4 usage error, 5 no tests collected. Only 0 and 1 are "the suite ran".
_SUITE_RAN = (0, 1)


@dataclass(frozen=True)
class RegressionResult:
    """One run of the project's own test suite, test by test."""

    outcomes: dict[str, str]  # pytest nodeid -> "passed" | "failed" | "error" | "skipped" | ...
    exit_code: int
    duration_s: float

    @property
    def passed_ids(self) -> frozenset[str]:
        return frozenset(t for t, o in self.outcomes.items() if o == "passed")

    @property
    def not_passed_ids(self) -> frozenset[str]:
        return frozenset(self.outcomes) - self.passed_ids

    @property
    def total(self) -> int:
        return len(self.outcomes)


def run_regression_tests(
    case: Case, report_path: Path, timeout_s: int | None = None
) -> RegressionResult:
    """Run the project's own pytest suite in case.repo_dir with the task's venv.

    The harness's security test file is excluded by name (not by a hard-coded
    `tests/` path: yt-dlp keeps its tests in `test/`).
    """
    pytest_bin = case.task_dir / ".venv" / "bin" / "pytest"
    timeout = timeout_s or case.regression_timeout_s
    cmd = [
        str(pytest_bin),
        "--json-report",
        f"--json-report-file={report_path}",
        "--ignore-glob=*test_security.py",
        "-q",
        "--no-header",
        "-p",
        "no:cacheprovider",
    ]
    started = time.monotonic()
    try:
        result = subprocess.run(
            cmd, cwd=case.repo_dir, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise HarnessError(f"regression suite for {case.id} exceeded {timeout}s") from exc
    duration = time.monotonic() - started

    if result.returncode not in _SUITE_RAN:
        raise HarnessError(
            f"regression suite for {case.id} did not run (pytest exit {result.returncode}): "
            f"{result.stderr.strip()[:300]}"
        )
    if not report_path.exists():
        raise HarnessError(f"regression suite for {case.id} produced no report")

    report = json.loads(report_path.read_text())
    outcomes = {t["nodeid"]: t["outcome"] for t in report.get("tests", [])}
    if not outcomes:
        raise HarnessError(f"regression suite for {case.id} collected zero tests")
    return RegressionResult(outcomes=outcomes, exit_code=result.returncode, duration_s=duration)


@dataclass
class Verdict:
    outcome: str
    broke: list[str] = field(default_factory=list)  # passed at baseline, not passing now
    pre_existing_failures: list[str] = field(default_factory=list)  # excluded from judgment
    newly_passing: list[str] = field(default_factory=list)  # recorded, never judged

    def as_record(self) -> dict:
        return {
            "outcome": self.outcome,
            "broke": self.broke,
            "pre_existing_failures": self.pre_existing_failures,
            "newly_passing": self.newly_passing,
        }


def classify(
    applied: bool,
    security: SecurityResult | None,
    baseline: RegressionResult | None,
    after: RegressionResult | None,
) -> Verdict:
    """Turn one run's evidence into exactly one of the four outcomes.

    `security`, `baseline` and `after` are None when the pipeline never got that far
    (e.g. the diff did not apply, so no tests were run on the patched tree).

    The three lists below are computed for you; the four decisions are yours.
    """
    pre_existing = sorted(baseline.not_passed_ids) if baseline else []
    broke: list[str] = []
    newly_passing: list[str] = []
    if baseline is not None and after is not None:
        broke = sorted(t for t in baseline.passed_ids if after.outcomes.get(t) != "passed")
        newly_passing = sorted(
            t for t in baseline.not_passed_ids if after.outcomes.get(t) == "passed"
        )

    # ARCHITECTURE §5: the four rules, in the order that stops the evaluation.
    # Only `broke` is used to judge; `pre_existing` and `newly_passing` are recorded.
    if not applied:  # the diff never went into the tree
        return Verdict(NOT_APPLIED, pre_existing_failures=pre_existing)
    if security is None or not security.all_passed:  # still fails, or never ran
        return Verdict(NOT_FIXED, pre_existing_failures=pre_existing, newly_passing=newly_passing)
    if broke:  # something that passed at baseline no longer passes
        return Verdict(
            FIXED_BUT_BROKE,
            broke=broke,
            pre_existing_failures=pre_existing,
            newly_passing=newly_passing,
        )
    return Verdict(FIXED_AND_CLEAN, pre_existing_failures=pre_existing, newly_passing=newly_passing)
