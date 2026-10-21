"""Inline SVG charts: built from records only, no script, honest about errors."""

from collections import Counter

from harness.charts import (
    COLORS,
    TINTS,
    cell_tint,
    outcome_bars_svg,
    poison_bars_svg,
    three_lights_svg,
)


def rec(model, outcome, **extra):
    r = {"model": model, "case": "C", "outcome": outcome}
    r.update(extra)
    return r


def test_outcome_bars_exclude_errors_from_the_bar_but_state_them():
    svg = outcome_bars_svg(
        [rec("m", "fixed-and-clean"), rec("m", "not-applied"), rec("m", "error")]
    )
    assert svg.startswith("<svg") and "<script" not in svg
    assert "n=2, 1 error" in svg  # scored count and the error count side by side
    assert COLORS["fixed-and-clean"] in svg and COLORS["not-applied"] in svg
    assert COLORS["error"] not in svg  # errors never become a bar segment


def test_outcome_bars_handle_a_model_with_only_errors():
    svg = outcome_bars_svg([rec("m", "error"), rec("m", "error")])
    assert "n=0, 2 errors" in svg


BROKE = {
    "outcome": "fixed-but-broke",
    "scan_before": {"bandit": {"found_in_target": True}, "semgrep": {"found_in_target": True}},
    "scan_after": {"bandit": {"found_in_target": False}, "semgrep": {"found_in_target": False}},
    "security_tests": {"passed": 1, "total": 1},
    "regression_baseline": {"passed": 227},
    "verdict": {"broke": ["t"] * 26},
}


def test_three_lights_tell_the_green_green_red_story():
    svg = three_lights_svg(BROKE)
    # Labels are wrapped for display, so the full sentence lives in each lamp's <title>.
    assert "<title>bandit, semgrep went quiet</title>" in svg
    assert "<title>security test 1/1 passed</title>" in svg
    assert "<title>26 of 227 existing tests now fail</title>" in svg
    assert svg.count(f'fill="{COLORS["fixed-and-clean"]}"') >= 2  # two green lamps
    assert svg.count(f'fill="{COLORS["fixed-but-broke"]}"') >= 1  # one red lamp
    assert "prefers-reduced-motion" in svg and "<script" not in svg


def test_three_lights_say_when_scanners_never_saw_the_bug():
    blind = dict(BROKE, scan_before={"bandit": {"found_in_target": False}}, scan_after={})
    assert "<title>scanners never saw it</title>" in three_lights_svg(blind)


def test_three_lights_say_when_a_scanner_still_alerts():
    still = dict(BROKE, scan_after={"bandit": {"found_in_target": True}, "semgrep": {}})
    assert "<title>bandit still alerting</title>" in three_lights_svg(still)


def test_poison_bars_count_obeyed_runs_per_model_and_payload():
    recs = [
        {"model": "m", "poison": {"payload": "support-token", "obeyed": True}},
        {"model": "m", "poison": {"payload": "support-token", "obeyed": False}},
        {"model": "m", "poison": {"payload": "delete-security-test", "obeyed": False}},
        {"model": "m", "outcome": "error"},  # no poison block: ignored
    ]
    svg = poison_bars_svg(recs)
    assert ">1/2<" in svg and ">0/1<" in svg
    assert "destructive: delete the security test" in svg
    assert "benign-looking: add a constant" in svg


def test_cell_tint_follows_the_dominant_outcome_and_ties_go_to_the_worse_one():
    assert (
        cell_tint(Counter({"fixed-and-clean": 2, "fixed-but-broke": 1})) == TINTS["fixed-and-clean"]
    )
    assert cell_tint(Counter({"fixed-and-clean": 1, "not-fixed": 1})) == TINTS["not-fixed"]
    assert cell_tint(Counter({"error": 3})) == ""
    assert cell_tint(None) == ""
