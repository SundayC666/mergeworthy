"""
Small hardening checks found during the web-app security checklist review.

Each test was written before the fix (red), then the fix makes it pass (green).
"""

import pytest
from fastapi.testclient import TestClient

from main import app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.mark.parametrize("path", ["/api/health", "/api/os/detect"])
def test_public_endpoints_are_rate_limited(client, path, caplog):
    # These two routes had no @limiter.limit at all, while README claims
    # "rate limiting on all endpoints". 60/minute matches the other GET routes.
    for _ in range(60):
        assert client.get(path).status_code == 200
    with caplog.at_level("WARNING"):
        assert client.get(path).status_code == 429, f"{path} is not rate limited"
    # A 429 is a security signal, not just an HTTP status: it must reach the log
    # with the client address so it can be alerted on (log_security_event existed
    # since v1 but nothing ever called it).
    assert "SECURITY_EVENT: rate_limited" in caplog.text
    assert "testclient" in caplog.text  # the TestClient's client host


def test_blocked_input_is_logged_as_a_security_event(client, caplog):
    with caplog.at_level("WARNING"):
        response = client.post("/api/cve/analyze", json={"query": "<script>alert(1)</script>"})
    assert response.status_code == 422
    assert "SECURITY_EVENT: blocked_input" in caplog.text


def test_version_refresh_endpoint_is_gone(client):
    # POST /api/versions/refresh claimed to refresh from NVD but only re-read a local
    # JSON file; nobody called it. A public write endpoint with no purpose is removed,
    # not rate limited.
    assert client.post("/api/versions/refresh").status_code in (404, 405)


def test_version_status_does_not_leak_server_path(client):
    # get_status() returned the absolute path of the cache file on the server,
    # and /versions/buttons sends that to every browser on page load.
    body = client.get("/api/versions/buttons").json()
    cache_status = body.get("cache_status", {})
    assert "cache_file" not in cache_status, f"server path leaked: {cache_status.get('cache_file')}"


# --- XSS fix + CSP (2026-10-29, the item the 9/27 checklist scheduled for 11/19) ---------


@pytest.mark.parametrize("path", ["/", "/api/health"])
def test_every_response_carries_a_csp_without_inline_scripts(client, path):
    csp = client.get(path).headers["Content-Security-Policy"]
    directives = {d.strip().split(" ")[0]: d.strip() for d in csp.split(";") if d.strip()}
    assert directives["script-src"] == "script-src 'self'"  # no 'unsafe-inline', no CDNs
    assert directives["object-src"] == "object-src 'none'"
    assert directives["frame-ancestors"] == "frame-ancestors 'none'"
    assert directives["base-uri"] == "base-uri 'self'"


def test_front_end_has_no_inline_event_handlers():
    # The CSP above would silently break the page if any came back.
    from pathlib import Path

    for f in ("static/index.html", "static/js/app.js", "static/js/cve_analyzer.js"):
        code = [
            line
            for line in Path(f).read_text().splitlines()
            if not line.lstrip().startswith(("//", "*", "<!--"))
        ]
        assert not [ln for ln in code if 'onclick="' in ln or 'onkeypress="' in ln], f


def test_front_end_escapes_what_nvd_sends():
    from pathlib import Path

    js = Path("static/js/cve_analyzer.js").read_text()
    assert "function escapeHtml" in js
    for field in ("title", "description", "remediation_summary", "cve", "severity"):
        assert f"${{finding.{field}}}" not in js, f"finding.{field} rendered unescaped"
        assert f"escapeHtml(finding.{field}" in js
    assert "safeNvdLink(finding.nvd_link)" in js
