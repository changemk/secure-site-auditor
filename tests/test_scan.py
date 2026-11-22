import io
import json
import unittest
from contextlib import redirect_stdout
from email.message import Message
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.response import addinfourl

from secure_site_auditor.auditor import (
    HTML_LIMIT, Finding, _cookie_findings, _header_findings, _html_findings, audit,
)
from secure_site_auditor.cli import main
from secure_site_auditor.report import render_html, render_text


def response(body, url="https://site.test/", media="text/html", status=200):
    headers = Message()
    headers["Content-Type"] = media
    return addinfourl(io.BytesIO(body), headers, url, status)


class PageTests(unittest.TestCase):
    def findings(self, html, **kwargs):
        with response(html, **kwargs) as page:
            return {f.check: f for f in _html_findings(page, page.geturl())}

    def test_base_resources_form_overrides_and_redaction(self):
        html = b'''<base href="http://cdn.test/assets/"><script src="one.js?token=secret"></script>
        <link rel="stylesheet" href="style.css"><form action=""><input type=password>
        <button formaction="send?token=secret"></button></form>'''
        found = self.findings(html)
        self.assertIn("script http://cdn.test/assets/one.js", found["Mixed content"].message)
        self.assertIn("formaction http://cdn.test/assets/send", found["Form transport"].message)
        self.assertNotIn("secret", str(found))
        self.assertNotIn("form http://", found["Form transport"].message)

    def test_relative_https_and_inert_content(self):
        found = self.findings(b'''<template><script src="http://cdn.test"></script></template>
            <a href="http://site.test/">link</a><iframe src="//site.test/"></iframe>
            <form action="/submit"></form>''')
        self.assertEqual(found["Mixed content"].status, "pass")
        self.assertEqual(found["Form transport"].status, "pass")

    def test_http_password_field_even_with_https_action(self):
        found = self.findings(b'<form action="https://site.test"><input type=password></form>', url="http://site.test/")
        self.assertEqual(found["Form transport"].status, "fail")
        self.assertIn("password field on an HTTP page", found["Form transport"].message)

    def test_partial_scan_keeps_evidence_but_never_awards_pass(self):
        found = self.findings(b'<script src="http://cdn.test/a"></script><form></form>' + b" " * HTML_LIMIT)
        self.assertEqual(found["Mixed content"].status, "warn")
        self.assertIn("Partial", found["HTML inspection"].message)
        self.assertNotIn("Form transport", found)

    def test_encoded_response_is_unscored(self):
        with response(b"encoded") as page:
            page.headers["Content-Encoding"] = "br"
            finding, = _html_findings(page, page.geturl())
        self.assertEqual((finding.status, finding.max_points), ("info", 0))


class AccuracyTests(unittest.TestCase):
    def test_csp_directives_and_combined_policies(self):
        for value, expected in [
            ("report-uri /default-src", "warn"),
            ("default-src 'self'; script-src https:", "warn"),
            ("default-src 'self'; script-src 'unsafe-inline' 'nonce-YWJj'", "pass"),
            ("default-src *; script-src * 'unsafe-eval', default-src 'none'", "pass"),
        ]:
            with self.subTest(policy=value):
                findings = _header_findings({"content-security-policy": value}, True)
                csp = next(f for f in findings if f.check == "Content Security Policy")
                self.assertEqual(csp.status, expected)

    def test_referrer_fallback_and_frame_precedence(self):
        headers = {"referrer-policy": "same-origin, unsafe-url, unknown", "x-frame-options": "DENY",
                   "content-security-policy": "default-src 'self'; frame-ancestors *; frame-ancestors 'none'"}
        found = {f.check: f for f in _header_findings(headers, True)}
        self.assertEqual(found["Referrer Policy"].status, "warn")
        self.assertEqual(found["Clickjacking protection"].status, "warn")
        headers["content-security-policy"] += ", frame-ancestors 'self'"
        self.assertEqual(_header_findings(headers, True)[-1].status, "pass")

    def test_cookie_prefix_and_value_rules(self):
        cases = [
            ("__Host-a=x; HttpOnly; Secure; SameSite=Lax; Path=/", True, "pass"),
            ("__Host-a=x; HttpOnly; Secure; SameSite=Lax; Path=/a; Domain=site.test", True, "warn"),
            ("a=x; HttpOnly; SameSite=None", False, "warn"),
            ("a=x; HttpOnly; SameSite=Lax; Partitioned", False, "warn"),
            ("a=x; HttpOnly; Secure; SameSite=Other", True, "warn"),
        ]
        for cookie, https, expected in cases:
            with self.subTest(cookie=cookie):
                self.assertEqual(_cookie_findings([cookie], https)[0].status, expected)

    def test_error_response_through_cli_all_formats(self):
        url = "http://site.test/missing?token=private"
        for fmt in ("text", "json", "html"):
            with self.subTest(fmt=fmt):
                headers = Message()
                headers["Content-Type"] = "application/json"
                error = HTTPError(url, 404, "Not Found", headers, io.BytesIO(b"{}"))
                output = io.StringIO()
                with (patch("secure_site_auditor.auditor.build_opener") as opener,
                      patch("sys.argv", ["site-audit", url, "--format", fmt, "--fail-below", "100"]),
                      redirect_stdout(output)):
                    opener.return_value.open.side_effect = error
                    self.assertEqual(main(), 1)
                report = output.getvalue()
                self.assertIn("404", report)
                self.assertNotIn("private", report)
                self.assertNotIn("Clickjacking protection", report)
                self.assertTrue(error.closed)
                if fmt == "json":
                    self.assertEqual(json.loads(report)["http_status"], 404)
                if fmt == "text":
                    self.assertLess(report.index("Needs attention"), report.index("Coverage notes"))

    def test_downgrade_and_redaction_in_all_reports(self):
        url = "https://site.test:8443/?key=private"
        chain = [url, "http://site.test/?key=private", url]
        page = response(b'<form action="http://site.test/?key=private"></form>', url)
        with (patch("secure_site_auditor.auditor._open_url", return_value=(page, chain)) as fetch,
              patch("secure_site_auditor.auditor._tls_finding", return_value=Finding("TLS certificate", "pass", "OK"))):
            result = audit(url)
        self.assertEqual(fetch.call_count, 1)
        checks = {f.check: f for f in result.findings}
        self.assertEqual(checks["HTTPS"].status, "fail")
        self.assertEqual(checks["Form transport"].status, "warn")
        for report in (json.dumps(result.to_dict()), render_text(result), render_html(result)):
            self.assertNotIn("private", report)
