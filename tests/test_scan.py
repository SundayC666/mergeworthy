"""Unit tests for harness/scan.py: report parsing and the two-boolean rule. No tools run."""

from harness import scan
from harness.patch import Target
from harness.scan import (
    Finding,
    parse_bandit,
    parse_semgrep,
    retarget,
    scan_after_patch,
    summarize,
)
from harness.setup_case import Case

BANDIT_REPORT = {
    "results": [
        {
            "test_id": "B101",
            "issue_cwe": {"id": 703},
            "line_number": 178,
            "issue_severity": "LOW",
            "issue_text": "Use of assert detected.",
        },
        {
            "test_id": "B604",
            "issue_cwe": {"id": 78},
            "line_number": 1393,
            "issue_severity": "MEDIUM",
            "issue_text": "Function call with shell=True",
        },
    ]
}

SEMGREP_REPORT = {
    "results": [
        {
            "check_id": "python.lang.security.use-defused-xml",
            "start": {"line": 23},
            "extra": {"severity": "ERROR", "message": "xml", "metadata": {"cwe": ["CWE-611: XXE"]}},
        },
        {
            "check_id": "python.lang.security.use-defused-xml",
            "start": {"line": 23},
            "extra": {"severity": "ERROR", "message": "xml", "metadata": {"cwe": ["CWE-611: XXE"]}},
        },
        {
            "check_id": "python.sqli.string-format",
            "start": {"line": 83},
            "extra": {
                "severity": "WARNING",
                "message": "sqli",
                "metadata": {"cwe": "CWE-89: SQLi"},
            },
        },
    ],
    "errors": [],
}


def test_parse_bandit_maps_cwe_and_line():
    f = parse_bandit(BANDIT_REPORT)
    assert [(x.rule, x.cwe, x.line) for x in f] == [
        ("B101", "CWE-703", 178),
        ("B604", "CWE-78", 1393),
    ]


def test_parse_semgrep_dedupes_and_normalises_cwe():
    f = parse_semgrep(SEMGREP_REPORT)
    assert [(x.rule, x.cwe, x.line) for x in f] == [
        ("use-defused-xml", "CWE-611", 23),
        ("string-format", "CWE-89", 83),
    ]


def fx(cwe, line) -> Finding:
    return Finding("bandit", "Bxxx", cwe, line, "MEDIUM", "m")


def test_found_in_target_when_matching_cwe_inside_range():
    s = summarize("bandit", [fx("CWE-78", 1393), fx("CWE-703", 10)], ["CWE-78"], 1386, 1418)
    assert s.found_in_file and s.found_in_target and s.nearest_distance == 0
    assert s.total_findings == 2 and len(s.relevant) == 1


def test_found_in_file_but_not_target_records_distance():
    # Right CWE, right file, wrong function: the two booleans disagree on purpose.
    s = summarize("bandit", [fx("CWE-22", 485)], ["CWE-22"], 360, 380)
    assert s.found_in_file and not s.found_in_target and s.nearest_distance == 105


def test_wrong_cwe_is_not_a_detection():
    # python-multipart: Bandit reports only asserts (CWE-703); the case is CWE-22.
    s = summarize("bandit", [fx("CWE-703", 370)], ["CWE-22"], 360, 380)
    assert not s.found_in_file and not s.found_in_target and s.nearest_distance is None


def test_any_of_several_case_cwes_counts():
    s = summarize("semgrep", [fx("CWE-290", 50)], ["CWE-287", "CWE-290"], 13, 87)
    assert s.found_in_target


def test_distance_before_range_is_positive_too():
    s = summarize("bandit", [fx("CWE-89", 40)], ["CWE-89"], 45, 531)
    assert s.nearest_distance == 5 and not s.found_in_target


def test_summarize_without_a_range_leaves_target_unknown():
    # The patched file no longer contains the target: "in target" cannot be answered.
    s = summarize("bandit", [fx("CWE-502", 255)], ["CWE-502"], None, None)
    assert s.found_in_file
    assert s.found_in_target is None and s.nearest_distance is None


# --- the after-patch scan must use the PATCHED function's lines (bug found 2026-11-04) ---
# pdfminer: the patch added 9 lines above pickle.load, the finding moved from line 246
# to 255, and the old range 232-249 reported it as "outside the target": a false quiet.

BEFORE = "import pickle\n\n\ndef load(name):\n    return pickle.load(open(name, 'rb'))\n"
AFTER = (
    "import pickle\n\n\ndef load(name):\n"
    "    name = name.strip()\n    name = name.lower()\n    name = name[:64]\n"
    "    return pickle.load(open(name, 'rb'))\n"
)


def _case_with(tmp_path, source: str) -> Case:
    task = tmp_path / "task"
    (task / "repo").mkdir(parents=True)
    (task / "repo" / "m.py").write_text(source)
    return Case("C", "p", ["CWE-502"], 9.8, "a", "b", "why", task)


def _fake_tools(monkeypatch, line: int) -> None:
    finding = Finding("bandit", "B301", "CWE-502", line, "MEDIUM", "pickle")
    monkeypatch.setattr(scan, "run_bandit", lambda repo, rel: [finding])
    monkeypatch.setattr(scan, "run_semgrep", lambda repo, rel: [])


def test_scan_after_patch_relocates_the_target(tmp_path, monkeypatch):
    case = _case_with(tmp_path, AFTER)
    _fake_tools(monkeypatch, line=8)  # pickle.load, pushed down from line 5 by the patch
    lines, scans = scan_after_patch(case, Target("m.py", "load"))
    assert lines == [4, 8]
    assert scans["bandit"]["found_in_target"] is True


def test_scan_after_patch_when_the_target_is_gone(tmp_path, monkeypatch):
    case = _case_with(tmp_path, "import pickle\n")  # patch deleted the function
    _fake_tools(monkeypatch, line=1)
    lines, scans = scan_after_patch(case, Target("m.py", "load"))
    assert lines is None
    assert scans["bandit"]["found_in_target"] is None and scans["bandit"]["found_in_file"]


def test_retarget_recomputes_from_stored_findings_and_keeps_the_old_value():
    stored = summarize("bandit", [fx("CWE-502", 255)], ["CWE-502"], 232, 249).as_record()
    assert stored["found_in_target"] is False  # what the old records say
    fixed = retarget(stored, [232, 258])
    assert fixed["found_in_target"] is True and fixed["nearest_distance"] == 0
    assert fixed["found_in_target_v1"] is False and fixed["nearest_distance_v1"] == 6
