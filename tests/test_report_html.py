"""The HTML results page embeds every run and never invents data."""

import json
import re
from pathlib import Path

from harness.report_html import build_page, run_payload


def make_run(runs: Path, folder: str, rec: dict, patch: str | None = None) -> dict:
    d = runs / folder
    d.mkdir(parents=True)
    (d / "record.json").write_text(json.dumps(rec))
    if patch is not None:
        (d / "model.patch").write_text(patch)
    return {**rec, "_folder": folder}


def test_page_embeds_runs_and_patch(tmp_path):
    r1 = make_run(
        tmp_path,
        "001-C1-m",
        {
            "case": "C1",
            "model": "m",
            "outcome": "fixed-and-clean",
            "total_s": 8.0,
            "model_call": {"prompt_tokens": 10, "completion_tokens": 5, "cost_usd": 0.01},
            "apply": {"applied": True, "reason": "", "files": ["a.py"]},
            "security_tests": {"passed": 1, "total": 1},
            "regression_baseline": {"passed": 3, "total": 3},
            "regression_after": {"passed": 3, "total": 3},
            "verdict": {"outcome": "fixed-and-clean", "broke": [], "pre_existing_failures": []},
            "scan_before": {"bandit": {"found_in_file": True, "found_in_target": True}},
        },
        patch="--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-x\n+y\n",
    )
    r2 = make_run(
        tmp_path, "002-C1-n", {"case": "C1", "model": "n", "outcome": "error", "error": "boom"}
    )
    page = build_page([r1, r2], tmp_path)
    assert "mergeworthy" in page and 'data-model="m"' in page and 'data-case="C1"' in page
    embedded = json.loads(re.search(r"const RUNS = (\[.*?\]);\n", page, re.S).group(1))
    assert {e["folder"] for e in embedded} == {"001-C1-m", "002-C1-n"}
    assert "+y" in embedded[0]["patch"] and embedded[1]["patch"] is None
    assert embedded[1]["error"] == "boom"


def test_patch_is_truncated_not_dropped(tmp_path):
    rec = make_run(
        tmp_path,
        "003-C2-m",
        {"case": "C2", "model": "m", "outcome": "not-fixed"},
        patch="x" * 30_000,
    )
    payload = run_payload(rec, tmp_path)
    assert payload["patch"].startswith("x" * 100) and "more characters" in payload["patch"]


def test_script_safe_escaping(tmp_path):
    rec = make_run(
        tmp_path,
        "004-C3-m",
        {"case": "C3", "model": "m", "outcome": "not-applied"},
        patch="</script><script>alert(1)</script>",
    )
    page = build_page([rec], tmp_path)
    assert "</script><script>alert(1)" not in page  # closing tag is escaped inside the JSON blob
