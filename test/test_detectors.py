"""
test_detectors.py
------------------
Lightweight unit tests that exercise the detection *logic* without
making real network calls, using unittest.mock to stand in for
requests.Session responses. Run with:

    python -m pytest test/ -v
"""

import sys
import os
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.detectors import sql_injection, xss, csrf, headers as headers_detector
from scanner.crawler import AttackSurface


def _mock_session(response_text, status_code=200, headers=None):
    session = MagicMock()
    resp = MagicMock()
    resp.text = response_text
    resp.status_code = status_code
    resp.headers = headers or {}
    session.get.return_value = resp
    session.post.return_value = resp
    return session, resp


class TestSqlInjection:
    def test_detects_mysql_error_signature(self):
        session, _ = _mock_session(
            "Warning: mysql_fetch_array() expects parameter 1 to be resource"
        )
        surface = AttackSurface("http://test/app", "GET", {"id": "1"}, "http://test/app")
        findings = sql_injection.check(session, surface)
        assert len(findings) == 1
        assert findings[0].vuln_type == "sql_injection"
        assert findings[0].confirmed is True

    def test_no_finding_on_clean_response(self):
        session, _ = _mock_session("<html><body>Welcome</body></html>")
        surface = AttackSurface("http://test/app", "GET", {"id": "1"}, "http://test/app")
        findings = sql_injection.check(session, surface)
        assert findings == []


class TestXss:
    def test_detects_unescaped_reflection(self):
        session = MagicMock()

        def fake_get(url, params=None, timeout=None):
            resp = MagicMock()
            resp.text = f"<html>You searched for: {params['q']}</html>"
            return resp

        session.get.side_effect = fake_get
        surface = AttackSurface("http://test/search", "GET", {"q": "test"}, "http://test/search")
        findings = xss.check(session, surface)
        assert len(findings) == 1
        assert findings[0].confirmed is True

    def test_no_finding_when_escaped(self):
        session = MagicMock()

        def fake_get(url, params=None, timeout=None):
            resp = MagicMock()
            resp.text = "<html>You searched for: &lt;script&gt;...&lt;/script&gt;</html>"
            return resp

        session.get.side_effect = fake_get
        surface = AttackSurface("http://test/search", "GET", {"q": "test"}, "http://test/search")
        findings = xss.check(session, surface)
        assert findings == []


class TestCsrf:
    def test_flags_post_form_without_token(self):
        _, resp = _mock_session(
            '<html><form method="post" action="/transfer">'
            '<input name="amount"><input type="submit"></form></html>'
        )
        findings = csrf.check_page("http://test/transfer", resp)
        assert len(findings) == 1
        assert findings[0].vuln_type == "csrf"

    def test_no_flag_when_token_present(self):
        _, resp = _mock_session(
            '<html><form method="post" action="/transfer">'
            '<input type="hidden" name="csrf_token" value="abc123">'
            '<input name="amount"></form></html>'
        )
        findings = csrf.check_page("http://test/transfer", resp)
        assert findings == []


class TestHeaders:
    def test_flags_missing_security_headers(self):
        _, resp = _mock_session("<html></html>", headers={"Content-Type": "text/html"})
        findings = headers_detector.check_page("http://test/", resp)
        found_headers = {f.parameter for f in findings}
        assert "X-Frame-Options" in found_headers
        assert "Content-Security-Policy" in found_headers

    def test_no_flags_when_all_headers_present(self):
        full_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=63072000",
            "Referrer-Policy": "no-referrer",
        }
        _, resp = _mock_session("<html></html>", headers=full_headers)
        findings = headers_detector.check_page("http://test/", resp)
        assert findings == []
