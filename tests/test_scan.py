"""Unit tests for harness/scan.py: report parsing and the two-boolean rule. No tools run."""

from harness.scan import Finding, parse_bandit, parse_semgrep, summarize

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
