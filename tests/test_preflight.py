"""Unit tests for harness/preflight.py with a fake model client."""

import io
from pathlib import Path
from types import SimpleNamespace

import httpx

import harness.llm as llm_mod
from harness.preflight import check_cases, ping_model, render, run_preflight
from harness.setup_case import Case


def make_case(tmp_path: Path, cid: str, complete=True) -> Case:
    d = tmp_path / "tasks" / cid
    d.mkdir(parents=True)
    names = ["setup.sh", "run_tests.sh", "test_security.py", "advisory.md", "locate.md"]
    for n in names if complete else names[:-1]:
        (d / n).write_text("x")
    return Case(cid, "x/y", ["CWE-1"], 1.0, "a^", "a", "t", d)


class FakeClient:
    def __init__(self, text="OK", raise_exc=None):
        def create(**kwargs):
            if raise_exc:
                raise raise_exc
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])

        self.chat = SimpleNamespace(completions=SimpleNamespace(create=create))


def test_case_check_names_missing_files(tmp_path):
    good = make_case(tmp_path, "CVE-1")
    bad = make_case(tmp_path, "CVE-2", complete=False)
    checks = check_cases([good, bad])
    assert checks[0].ok and not checks[1].ok and "locate.md" in checks[1].detail


def test_ping_ok_for_ollama_without_budget():
    c = ping_model("gpt-oss:20b", "ollama", client_factory=lambda cfg: FakeClient("OK"))
    assert c.ok and "replied 'OK'" in c.detail


def test_ping_reports_model_errors_instead_of_raising():
    boom = RuntimeError("model not found")
    c = ping_model("nope", "ollama", client_factory=lambda cfg: FakeClient(raise_exc=boom))
    assert not c.ok and "model not found" in c.detail


def test_ping_fails_when_gateway_unreachable(monkeypatch):
    def down(url, headers=None, timeout=None):
        raise httpx.ConnectTimeout("timed out")

    monkeypatch.setattr(httpx, "get", down)
    monkeypatch.setenv("DUKE_API_KEY", "sk-test")
    c = ping_model("claude-sonnet-5", "gateway", client_factory=lambda cfg: FakeClient())
    assert not c.ok and "VPN" in c.detail


def test_render_is_no_go_only_on_fatal_failures(tmp_path):
    checks = run_preflight(
        [make_case(tmp_path, "CVE-1")], ["m"], "ollama", client_factory=lambda cfg: FakeClient()
    )
    text = render(checks)
    # semgrep may or may not be installed on the machine running the tests; it is
    # non-fatal either way, so the verdict depends only on the case and the model.
    assert text.endswith("preflight: GO")
    assert "[ok  ] model m" in text


def test_budget_reserve_blocks_ping(monkeypatch):
    class R:
        def raise_for_status(self):
            pass

        def json(self):
            return {"info": {"spend": 0.9, "max_budget": 1.0}}

    monkeypatch.setattr(httpx, "get", lambda url, headers=None, timeout=None: R())
    monkeypatch.setattr(llm_mod, "BUDGET_RESERVE_USD", 0.5)
    monkeypatch.setenv("DUKE_API_KEY", "sk-test")
    c = ping_model("claude-sonnet-5", "gateway", client_factory=lambda cfg: FakeClient())
    assert not c.ok and "BudgetExhausted" in c.detail


def test_io_unused():  # keeps the io import honest for render-to-stream callers
    assert io.StringIO().getvalue() == ""
