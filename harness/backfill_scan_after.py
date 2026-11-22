"""One-off migration (2026-11-13): recompute `scan_after.*.found_in_target` in old records.

    python -m harness.backfill_scan_after            # dry run: what would change
    python -m harness.backfill_scan_after --write    # rewrite the records

Before the fix in scan.scan_after_patch, the after-patch scan judged "in target" against
the PRE-patch line range of the function. A patch that adds lines above the vulnerable
call pushes the same finding past the old end line, so it looked like the scanner went
quiet when it had not (pdfminer CVE-2025-64512: pickle.load moved from line 246 to 255,
old range 232-249).

For every record that has a scan_after, this rebuilds the patched target file without
touching the case checkout: the file at the vulnerable commit (`git show`), plus the
poison comment for runs-poison records (same `inject` the run used), plus the run's own
`model.patch`. It then locates the function with the same `extract_snippet` the harness
uses. Self-check: the rebuilt PRE-patch range must equal `target.lines` in the record;
a record that fails the check is reported and left alone. No scanner is rerun: the
stored findings already carry their line numbers, `retarget` only re-judges them.
Old values stay in the record as found_in_target_v1 / nearest_distance_v1.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import subprocess
import tempfile
from pathlib import Path

from harness.patch import Target, extract_snippet
from harness.poison import inject, load_payloads
from harness.scan import retarget
from harness.setup_case import REPO_ROOT, Case, HarnessError, load_cases

RUN_DIRS = ("runs", "runs-v2", "runs-poison")
NOTE = (
    "2026-11-13: found_in_target recomputed against the patched target range "
    "(harness/backfill_scan_after.py); old values in *_v1"
)


def lines_after(case: Case, record: dict, patch: Path) -> list[int] | None:
    """Rebuild the patched target file in a temp dir and locate the target in it."""
    t = record["target"]
    target = Target(t["file"], t["qualname"])
    original = subprocess.run(
        ["git", "-C", str(case.repo_dir), "show", f"{case.vulnerable_sha}:{t['file']}"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    with tempfile.TemporaryDirectory() as tmp:
        fake = dataclasses.replace(case, task_dir=Path(tmp))
        path = fake.repo_dir / t["file"]
        path.parent.mkdir(parents=True)
        path.write_text(original)
        if record.get("poison"):
            snippet, _ = inject(fake, target, load_payloads()[record["poison"]["payload"]])
        else:
            snippet = extract_snippet(fake.repo_dir, target)
        if [snippet.start_line, snippet.end_line] != t["lines"]:
            raise HarnessError(
                f"rebuilt pre-patch range {snippet.start_line}-{snippet.end_line} "
                f"!= recorded {t['lines']}"
            )
        subprocess.run(
            ["git", "apply", "--recount", f"--include={t['file']}", str(patch)],
            cwd=fake.repo_dir,
            capture_output=True,
            text=True,
            check=True,
        )
        try:
            after = extract_snippet(fake.repo_dir, target)
        except HarnessError:
            return None
        return [after.start_line, after.end_line]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--write", action="store_true", help="rewrite the records")
    args = parser.parse_args(argv)

    cases = {c.id: c for c in load_cases()}
    seen = changed = failed = 0
    for top in RUN_DIRS:
        for rec_path in sorted((REPO_ROOT / top).glob("**/record.json")):
            record = json.loads(rec_path.read_text())
            if not record.get("scan_after") or "lines_after" in record.get("target", {}):
                continue
            seen += 1
            try:
                new_lines = lines_after(
                    cases[record["case"]], record, rec_path.parent / "model.patch"
                )
            except (HarnessError, subprocess.CalledProcessError, KeyError) as exc:
                failed += 1
                print(f"SKIP {rec_path.parent.relative_to(REPO_ROOT)}: {exc}")
                continue
            record["target"]["lines_after"] = new_lines
            for tool, summary in record["scan_after"].items():
                fixed = retarget(summary, new_lines)
                if fixed.get("found_in_target") != summary.get("found_in_target"):
                    changed += 1
                    print(
                        f"{tool:<8} {summary.get('found_in_target')!s:>5} -> "
                        f"{fixed.get('found_in_target')!s:<5} {record['outcome']:<16} "
                        f"{rec_path.parent.relative_to(REPO_ROOT)}"
                    )
                record["scan_after"][tool] = fixed
            record["scan_after_backfill"] = NOTE
            if args.write:
                rec_path.write_text(json.dumps(record, indent=2))  # same as run_case
    print(f"\n{seen} records with an after-scan, {changed} verdicts flipped, {failed} skipped")
    print("written" if args.write else "dry run: nothing written (use --write)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
