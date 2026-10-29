"""patch-bot: a gate decision becomes the PR or issue text a bot would open; nothing
touches GitHub unless --apply, and PRs are refused until the phase-3 fork exists."""

import json

import pytest

from harness.gate import Decision
from harness.patchbot import (
    REVIEW_LABEL,
    build_proposal,
    gh_create,
    main,
    propose_for_run,
)

RECORD = {
    "run_id": "r1",
    "case": "CVE-1",
    "project": "x/y",
    "model": "m",
    "prompt_version": "v1.1-snippet",
    "outcome": "fixed-and-clean",
    "apply": {"applied": True, "reason": "", "files": ["a.py"], "touches_tests": False},
    "security_tests": {"passed": 1, "total": 1},
    "regression_baseline": {"passed": 10, "total": 10},
    "regression_after": {"passed": 10, "total": 10},
    "verdict": {"outcome": "fixed-and-clean", "broke": []},
}


def test_allow_becomes_an_unlabelled_pr_with_evidence_and_diff():
    d = Decision("r1", "allow", ["door 1: fixed and clean"], env_reads=['os.environ.get("L")'])
    p = build_proposal(RECORD, d, "+x = 1\n")
    assert p.kind == "pr" and p.labels == [] and p.branch == "mergeworthy/CVE-1/m"
    assert "proposed" in p.title
    assert "Security test: 1/1 passed" in p.body and "```diff\n+x = 1\n```" in p.body
    assert 'os.environ.get("L")' in p.body  # recorded signals are shown, not judged
    assert "Auto-merge is never enabled" in p.body


def test_review_becomes_a_labelled_pr_with_history_count():
    d = Decision("r1", "review", ["door 2: history", "door 1: fixed and clean"], history=["h1"])
    p = build_proposal(RECORD, d, "+x\n")
    assert p.kind == "pr" and p.labels == [REVIEW_LABEL]
    assert "needs human review" in p.title and "door 2: history" in p.body
    assert "not fixed or broke something: 1" in p.body


def test_block_becomes_an_issue_without_a_branch_and_lists_broken_tests():
    rec = dict(RECORD, outcome="fixed-but-broke", verdict={"broke": ["t1", "t2"]})
    d = Decision("r1", "block", ["door 1: fixed but broke 2 of 10 previously passing tests"])
    p = build_proposal(rec, d, "+x\n")
    assert p.kind == "issue" and p.branch is None and "blocked" in p.title
    assert "Broke 2 previously passing test(s): `t1`, `t2`" in p.body


def test_not_applied_issue_has_no_diff_section():
    rec = dict(
        RECORD,
        outcome="not-applied",
        apply={"applied": False, "reason": "git-apply-failed", "files": []},
    )
    d = Decision("r1", "block", ["door 1: diff did not apply (git-apply-failed)"])
    p = build_proposal(rec, d, None)
    assert "## Diff" not in p.body and "no (git-apply-failed)" in p.body


def test_long_diffs_are_truncated_not_dropped():
    d = Decision("r1", "allow", ["ok"])
    p = build_proposal(RECORD, d, "+" + "x" * 20_000 + "\n")
    assert "[truncated]" in p.body and len(p.body) < 14_000


def test_propose_for_run_reads_the_folder_and_uses_sibling_history(tmp_path):
    runs = tmp_path / "runs"
    for rid, outcome in (("old", "not-fixed"), ("new", "fixed-and-clean")):
        d = runs / rid
        d.mkdir(parents=True)
        (d / "record.json").write_text(json.dumps(dict(RECORD, run_id=rid, outcome=outcome)))
        (d / "model.patch").write_text("+y = 2\n")
    decision, proposal = propose_for_run(runs / "new")
    assert decision.decision == "review" and proposal.labels == [REVIEW_LABEL]
    assert "+y = 2" in proposal.body


def test_gh_create_refuses_prs_and_opens_issues_through_gh():
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)

        class R:
            stdout = "https://github.com/o/r/issues/7\n"

        return R()

    issue = build_proposal(
        dict(RECORD, outcome="not-applied"), Decision("r1", "block", ["x"]), None
    )
    assert gh_create(issue, "o/r", runner=fake_run) == "https://github.com/o/r/issues/7"
    assert calls[0][:4] == ["gh", "issue", "create", "--repo"] and "o/r" in calls[0]
    pr = build_proposal(RECORD, Decision("r1", "allow", ["x"]), "+x\n")
    with pytest.raises(RuntimeError):
        gh_create(pr, "o/r", runner=fake_run)
    assert len(calls) == 1  # the PR never reached gh


def test_cli_dry_run_prints_and_writes_without_touching_github(tmp_path, capsys):
    d = tmp_path / "runs" / "r1"
    d.mkdir(parents=True)
    (d / "record.json").write_text(json.dumps(RECORD))
    (d / "model.patch").write_text("+x\n")
    out = tmp_path / "p.md"
    assert main([str(d / "record.json"), "--out", str(out)]) == 0
    printed = capsys.readouterr().out
    assert printed.startswith("PR (allow)") and out.read_text().startswith("# [mergeworthy]")
