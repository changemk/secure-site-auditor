# Secure Site Auditor

A dependency-free, passive website security posture checker built by Change Muriuki. It reviews publicly returned HTTP and TLS information, then produces an actionable report without exploiting or attacking the target.

## What it checks

- HTTPS availability and redirect behavior
- Full redirect-chain recording and explicit HTTP-to-HTTPS enforcement
- TLS certificate validity, expiry, issuer, negotiated protocol, and cipher
- HSTS, CSP, clickjacking, MIME sniffing, referrer, and permissions policy strength
- Information exposed through the `Server` and `X-Powered-By` headers
- Security flags on response cookies
- A simple, explainable security score
- HTML and JSON report generation

## Ethical use

Only assess systems you own or have permission to review. This project performs passive requests only. It does not brute-force, crawl, inject payloads, bypass authentication, or exploit vulnerabilities.

## Install from source

Requires Python 3.10 or newer.

```bash
git clone https://github.com/changemk/secure-site-auditor.git
cd secure-site-auditor
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

On Windows PowerShell, activate the environment with:

```powershell
.\.venv\Scripts\Activate.ps1
```

## Usage

```bash
site-audit https://example.com
site-audit example.com --format json
site-audit example.com --format html --output reports/example.html
site-audit example.com --fail-below 75
site-audit --help
```

`--fail-below` is designed for CI pipelines. The command exits with status `1` when the score is below the chosen threshold, `2` for invalid input or an audit error, and `0` otherwise.

## Example

```text
Secure Site Auditor
Target: https://example.com
Score: 78/100

[PASS] HTTPS is enabled
[WARN] Content-Security-Policy is missing
[PASS] Cookies use the Secure flag
```

## Roadmap

- DNS security record checks
- Batch audits from CSV
- Historical score comparison
- Web dashboard
- Packaged releases on PyPI

## Development

Run the test suite with:

```bash
python -m unittest discover -s tests -v
```

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Released under the [MIT License](LICENSE).

## Portfolio notes

This repository demonstrates defensive security analysis, TLS handling, HTTP security headers, report generation, testable Python design, and clear remediation guidance.
