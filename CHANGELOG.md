# Changelog

## 0.2.0

- Validate the strength of HSTS, CSP, MIME sniffing, referrer, permissions, and frame protections.
- Record the primary request's redirect chain and test HTTP-to-HTTPS enforcement explicitly.
- Report the negotiated TLS protocol, cipher, certificate issuer, and remaining validity.
- Add `--fail-below` with CI-friendly exit codes.
- Expand regression coverage for weak header values, redirects, and cookie attributes.

## 0.1.0

- Initial passive HTTPS, TLS, security-header, disclosure, and cookie checks.
- Text, JSON, and HTML reports.
