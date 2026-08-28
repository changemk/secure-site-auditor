import unittest
from unittest.mock import patch

from secure_site_auditor.auditor import (
    AuditResult,
    _cookie_findings,
    _header_findings,
    _https_redirect_finding,
    normalize_url,
)
from secure_site_auditor.cli import main


class UrlTests(unittest.TestCase):
    def test_adds_https(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com")

    def test_rejects_non_http_scheme(self):
        with self.assertRaises(ValueError):
            normalize_url("file:///tmp/test")


class FindingTests(unittest.TestCase):
    def test_complete_headers_pass(self):
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=()",
        }
        findings = _header_findings(headers, True)
        self.assertTrue(all(item.status == "pass" for item in findings))

    def test_weak_header_values_warn(self):
        headers = {
            "strict-transport-security": "max-age=300",
            "content-security-policy": "script-src * 'unsafe-inline'",
            "x-content-type-options": "off",
            "referrer-policy": "unsafe-url",
            "permissions-policy": "camera=*",
            "x-frame-options": "ALLOWALL",
        }
        findings = _header_findings(headers, True)
        self.assertTrue(all(item.status == "warn" for item in findings))

    def test_insecure_cookie_warns(self):
        finding = _cookie_findings(["session=abc; Path=/"], True)[0]
        self.assertEqual(finding.status, "warn")
        self.assertIn("Secure", finding.message)

    def test_cookie_value_cannot_impersonate_security_flags(self):
        finding = _cookie_findings(["session=secure-httponly-samesite; Path=/"], True)[0]
        self.assertEqual(finding.status, "warn")
        self.assertIn("Secure", finding.message)

    def test_secure_cookie_attributes_pass(self):
        finding = _cookie_findings(
            ["session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"], True
        )[0]
        self.assertEqual(finding.status, "pass")

    def test_http_redirect_to_https_passes(self):
        class Response:
            @staticmethod
            def geturl():
                return "https://example.com/"

        with patch(
            "secure_site_auditor.auditor._open_url",
            return_value=(Response(), ["http://example.com/", "https://example.com/"]),
        ):
            finding, chain = _https_redirect_finding("example.com", 1)

        self.assertEqual(finding.status, "pass")
        self.assertEqual(chain[-1], "https://example.com/")


class CliTests(unittest.TestCase):
    def test_fail_below_returns_one_for_low_score(self):
        result = AuditResult(
            "https://example.com",
            "https://example.com",
            "2026-01-01T00:00:00+00:00",
            70,
            [],
            ["https://example.com"],
        )
        with (
            patch("secure_site_auditor.cli.audit", return_value=result),
            patch("sys.argv", ["site-audit", "example.com", "--fail-below", "80"]),
        ):
            self.assertEqual(main(), 1)

    def test_invalid_fail_below_returns_two(self):
        with patch("sys.argv", ["site-audit", "example.com", "--fail-below", "101"]):
            self.assertEqual(main(), 2)


if __name__ == "__main__":
    unittest.main()
