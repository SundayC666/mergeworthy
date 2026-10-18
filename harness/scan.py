"""SAST scan of the target file, before and after the patch. Record-only.

Why it exists (ARCHITECTURE §1, §5): a scanner going quiet is NOT evidence that a
vulnerability is fixed (deleting the failing test also makes scanners quiet), so scan
results never influence the four-way verdict. They are recorded so the report can show
two things: how often the scanner saw the vulnerability at all, and how often it goes
quiet after a patch that the tests say did not fix anything.

Two tools, deliberately different in style:
  * Bandit (Python-only, syntactic: any call with shell=True is reported)
  * Semgrep (multi-language, pattern rules that are more specific)
For each tool and case we record two booleans, not one (decision 2026-10-19):
  found_in_file    a finding with the case's CWE anywhere in the target file
  found_in_target  the same, but inside the function/class that locate.md names
plus the distance in lines from the nearest matching finding to the target range.
Which of the two is the headline "detected" number is decided once data exists.

Bandit comes from requirements-dev.txt (same venv). Semgrep is an external tool
(`uv tool install semgrep`): it pulls a large dependency tree that conflicts with the
web app's pinned FastAPI, so it must not live in this venv. Missing Semgrep is recorded
as an error for that tool, never a crash.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from harness.setup_case import Case

SEMGREP_CONFIGS = ("p/python", "p/security-audit", "p/owasp-top-ten")
SCAN_TIMEOUT_S = 300


class ScanUnavailable(RuntimeError):
    """The tool is not installed or could not run; recorded, not fatal."""


@dataclass(frozen=True)
class Finding:
    tool: str
    rule: str
    cwe: str | None  # "CWE-78" or None when the rule carries no CWE
    line: int
    severity: str
    message: str


def _bandit_bin() -> Path:
    return Path(sys.executable).parent / "bandit"


def _semgrep_bin() -> Path | None:
    found = shutil.which("semgrep")
    if found:
        return Path(found)
    candidate = Path.home() / ".local" / "bin" / "semgrep"
    return candidate if candidate.exists() else None


def parse_bandit(report: dict) -> list[Finding]:
    out = []
    for r in report.get("results", []):
        cwe = r.get("issue_cwe") or {}
        out.append(
            Finding(
                tool="bandit",
                rule=r.get("test_id", "?"),
                cwe=f"CWE-{cwe['id']}" if cwe.get("id") else None,
                line=int(r.get("line_number", 0)),
                severity=str(r.get("issue_severity", "")),
                message=str(r.get("issue_text", ""))[:200],
            )
        )
    return out


def parse_semgrep(report: dict) -> list[Finding]:
    out, seen = [], set()
    for r in report.get("results", []):
        key = (r.get("check_id"), r.get("start", {}).get("line"))
        if key in seen:  # the same rule can appear in several configs
            continue
        seen.add(key)
        meta = r.get("extra", {}).get("metadata", {})
        cwes = meta.get("cwe") or []
        if isinstance(cwes, str):
            cwes = [cwes]
        cwe = str(cwes[0]).split(":")[0].strip() if cwes else None
        out.append(
            Finding(
                tool="semgrep",
                rule=str(r.get("check_id", "?")).split(".")[-1],
                cwe=cwe,
                line=int(r.get("start", {}).get("line", 0)),
                severity=str(r.get("extra", {}).get("severity", "")),
                message=str(r.get("extra", {}).get("message", ""))[:200],
            )
        )
    return out


def run_bandit(repo_dir: Path, rel_file: str) -> list[Finding]:
    result = subprocess.run(
        [str(_bandit_bin()), "-f", "json", "-q", rel_file],
        cwd=repo_dir,
        capture_output=True,
        text=True,
        timeout=SCAN_TIMEOUT_S,
        check=False,
    )
    # Bandit exits 1 when it reports anything; only "no output" means it did not run.
    if not result.stdout.strip():
        raise ScanUnavailable(f"bandit produced no report: {result.stderr.strip()[:200]}")
    return parse_bandit(json.loads(result.stdout))


def run_semgrep(repo_dir: Path, rel_file: str) -> list[Finding]:
    binary = _semgrep_bin()
    if binary is None:
        raise ScanUnavailable("semgrep is not installed (uv tool install semgrep)")
    cmd = [str(binary), "scan", "--json", "--metrics=off", "--quiet"]
    for cfg in SEMGREP_CONFIGS:
        cmd += ["--config", cfg]
    cmd.append(rel_file)
    result = subprocess.run(
        cmd, cwd=repo_dir, capture_output=True, text=True, timeout=SCAN_TIMEOUT_S, check=False
    )
    if not result.stdout.strip():
        raise ScanUnavailable(f"semgrep produced no report: {result.stderr.strip()[:200]}")
    report = json.loads(result.stdout)
    if report.get("errors") and not report.get("results"):
        first = report["errors"][0]
        raise ScanUnavailable(f"semgrep error: {str(first.get('message', first))[:200]}")
    return parse_semgrep(report)


@dataclass
class ScanSummary:
    tool: str
    total_findings: int = 0
    relevant: list[dict] = field(default_factory=list)  # findings whose CWE matches the case
    found_in_file: bool = False
    found_in_target: bool = False
    nearest_distance: int | None = None  # 0 when inside the target range
    error: str | None = None

    def as_record(self) -> dict:
        return asdict(self)


def summarize(
    tool: str, findings: list[Finding], case_cwes: list[str], start_line: int, end_line: int
) -> ScanSummary:
    """Apply the two-boolean rule to one tool's findings on one file."""
    wanted = set(case_cwes)
    relevant = [f for f in findings if f.cwe in wanted]

    def distance(line: int) -> int:
        if start_line <= line <= end_line:
            return 0
        return start_line - line if line < start_line else line - end_line

    distances = [distance(f.line) for f in relevant]
    return ScanSummary(
        tool=tool,
        total_findings=len(findings),
        relevant=[asdict(f) for f in relevant],
        found_in_file=bool(relevant),
        found_in_target=any(d == 0 for d in distances),
        nearest_distance=min(distances) if distances else None,
    )


def scan_target(case: Case, rel_file: str, start_line: int, end_line: int) -> dict[str, dict]:
    """Run both tools on the target file. Never raises: tool problems land in `error`."""
    out: dict[str, dict] = {}
    for tool, runner in (("bandit", run_bandit), ("semgrep", run_semgrep)):
        try:
            findings = runner(case.repo_dir, rel_file)
            summary = summarize(tool, findings, case.cwe, start_line, end_line)
        except (ScanUnavailable, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            summary = ScanSummary(tool=tool, error=f"{type(exc).__name__}: {exc}")
        out[tool] = summary.as_record()
    return out


# --- baseline over all cases -------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """python -m harness.scan  →  benchmarks/scan_baseline.json + a table on stdout.

    Scans every case's target file on the VULNERABLE commit. This is the "does the
    scanner see it at all" half of the scanner metric; the per-run before/after scan
    in run_case.py is the "does it go quiet" half.
    """
    import argparse
    from datetime import UTC, datetime

    from harness.patch import load_target
    from harness.setup_case import REPO_ROOT, load_cases, setup

    parser = argparse.ArgumentParser(description=main.__doc__.split("\n")[0])
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "benchmarks" / "scan_baseline.json")
    args = parser.parse_args(argv)

    rows = []
    print(f"{'case':<22} {'cwe':<16} {'tool':<8} {'in_file':<8} {'in_target':<10} nearest")
    for case in load_cases():
        setup(case)
        _, target, snippet = load_target(case)
        scans = scan_target(case, target.file, snippet.start_line, snippet.end_line)
        rows.append(
            {
                "case": case.id,
                "cwe": case.cwe,
                "file": target.file,
                "target": target.qualname,
                "lines": [snippet.start_line, snippet.end_line],
                "scans": scans,
            }
        )
        for tool, s in scans.items():
            cell = "ERROR" if s["error"] else ""
            print(
                f"{case.id:<22} {','.join(case.cwe):<16} {tool:<8} "
                f"{str(s['found_in_file']):<8} {str(s['found_in_target']):<10} "
                f"{s['nearest_distance'] if s['nearest_distance'] is not None else '-'} {cell}"
            )

    args.out.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(UTC).isoformat(),
                "semgrep_configs": list(SEMGREP_CONFIGS),
                "note": "record-only; see harness/scan.py docstring",
                "cases": rows,
            },
            indent=2,
        )
        + "\n"
    )
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
