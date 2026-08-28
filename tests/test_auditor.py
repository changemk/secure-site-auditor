import unittest

from secure_site_auditor.auditor import _cookie_findings, _header_findings, normalize_url


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


if __name__ == "__main__":
    unittest.main()
