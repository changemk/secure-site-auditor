from __future__ import annotations

import codecs
import math
import socket
import ssl
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http.client import HTTPException
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .page import PageMarkup, report_url

HTML_LIMIT = 512 * 1024


@dataclass(frozen=True)
class Finding:
    check: str
    status: str
    message: str
    remediation: str = ""
    points: int = 0
    max_points: int = 0


@dataclass
class AuditResult:
    target: str
    final_url: str
    scanned_at: str
    score: int
    findings: list[Finding]
    redirect_chain: list[str]
    http_status: int | None = None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "final_url": self.final_url,
            "scanned_at": self.scanned_at,
            "score": self.score,
            "http_status": self.http_status,
            "redirect_chain": self.redirect_chain,
            "findings": [asdict(finding) for finding in self.findings],
        }


SECURITY_HEADERS = {
    "strict-transport-security": (
        "HTTP Strict Transport Security",
        15,
        "Add Strict-Transport-Security with an appropriate max-age after confirming HTTPS works everywhere.",
    ),
    "content-security-policy": (
        "Content Security Policy",
        15,
        "Define a restrictive Content-Security-Policy and refine it using report-only mode first.",
    ),
    "x-content-type-options": (
        "MIME sniffing protection",
        8,
        "Set X-Content-Type-Options to nosniff.",
    ),
    "referrer-policy": (
        "Referrer Policy",
        6,
        "Set a privacy-conscious Referrer-Policy such as strict-origin-when-cross-origin.",
    ),
    "permissions-policy": (
        "Permissions Policy",
        6,
        "Set Permissions-Policy to disable browser capabilities the application does not need.",
    ),
}

STRONG_REFERRER_POLICIES = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}


class _RedirectRecorder(HTTPRedirectHandler):
    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlparse(urljoin(req.full_url, newurl)).scheme not in {"http", "https"}:
            raise RuntimeError("Redirect points outside HTTP or HTTPS.")
        request = super().redirect_request(req, fp, code, msg, headers, newurl)
        if request is not None:
            self.urls.append(request.full_url)
        return request


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("A target URL is required.")
    if "://" not in value:
        value = f"https://{value}"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Use a valid HTTP or HTTPS URL.")
    return value


def _csp_policies(value: str) -> list[dict[str, list[str]]]:
    policies = []
    for policy in value.lower().split(","):
        directives = {}
        for directive in policy.split(";"):
            tokens = directive.split()
            if tokens:
                directives.setdefault(tokens[0], tokens[1:])
        policies.append(directives)
    return policies


def _broad_source(source: str) -> bool:
    authority = source.partition("://")[2] or source
    return source.endswith(":") or authority.split("/", 1)[0].split(":", 1)[0] == "*"


def _frame_protection(headers: dict[str, str]) -> bool:
    # Enforced policies apply together. Within one policy the first directive wins.
    has_frame_directive = False
    for policy in _csp_policies(headers.get("content-security-policy", "")):
        if "frame-ancestors" in policy:
            has_frame_directive = True
            if not any(_broad_source(source) for source in policy["frame-ancestors"]):
                return True
    return not has_frame_directive and headers.get("x-frame-options", "").strip().lower() in {"deny", "sameorigin"}


def _csp_weaknesses(value: str) -> list[str]:
    policies = _csp_policies(value)
    warnings = []
    defaults = [p["default-src"] for p in policies if "default-src" in p]
    if not defaults:
        warnings.append("default-src is missing")
    elif all(any(_broad_source(s) for s in sources) for sources in defaults):
        warnings.append("default-src has a broad source list")

    # Resolve script fallbacks within each policy before testing their combined restrictions.
    scripts = [p.get("script-src", p.get("default-src")) for p in policies]
    script_lists = [sources for sources in scripts if sources is not None]
    if script_lists and all("'unsafe-eval'" in sources for sources in script_lists):
        warnings.append("script policy includes unsafe-eval")
    for name in ("script-src-elem", "script-src-attr"):
        effective = [p.get(name, fallback) for p, fallback in zip(policies, scripts)]
        lists = [sources for sources in effective if sources is not None]
        if not lists:
            continue
        if name == "script-src-elem" and all(
            any(_broad_source(s) for s in sources) and "'strict-dynamic'" not in sources for sources in lists
        ):
            warnings.append("script element policy has a broad source list")
        if all("'unsafe-inline'" in sources and not any(
            s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in sources
        ) for sources in lists):
            warnings.append(f"{name} includes unsafe-inline without a nonce or hash")
    return warnings


def _header_findings(headers: dict[str, str], is_https: bool) -> list[Finding]:
    findings: list[Finding] = []
    for key, (label, points, remediation) in SECURITY_HEADERS.items():
        if key == "strict-transport-security" and not is_https:
            continue
        value = headers.get(key, "")
        valid = bool(value)
        message = f"Present: {value}" if value else "Header is missing."

        if key == "strict-transport-security" and value:
            directives = [part.strip().lower() for part in value.split(";")]
            ages = [part.partition("=")[2].strip().strip('"') for part in directives
                    if part.partition("=")[0].strip() == "max-age"]
            age = ages[0] if len(ages) == 1 else ""
            seconds = int(age) if age.isascii() and age.isdecimal() and len(age) <= 18 else -1
            valid = seconds >= 31_536_000
            extras = []
            if "includesubdomains" not in directives:
                extras.append("includeSubDomains is absent")
            if "preload" not in directives:
                extras.append("preload is absent")
            message = (
                f"max-age={seconds}; " + (", ".join(extras) or "includes subdomains and preload")
                if seconds >= 0
                else "The max-age directive is missing or invalid."
            )
        elif key == "content-security-policy" and value:
            weaknesses = _csp_weaknesses(value)
            valid = not weaknesses
            message = "Default source policy present; checked script rules passed." if valid else "; ".join(weaknesses) + "."
        elif key == "x-content-type-options" and value:
            valid = value.strip().lower() == "nosniff"
            message = "Set to nosniff." if valid else f"Unexpected value: {value}"
        elif key == "referrer-policy" and value:
            known = STRONG_REFERRER_POLICIES | {"origin", "origin-when-cross-origin", "unsafe-url", "no-referrer-when-downgrade"}
            tokens = [part.strip().lower() for part in value.split(",")]
            # A later recognized referrer policy overrides earlier fallback values.
            effective = next((p for p in reversed(tokens) if p in known), "")
            valid = effective in STRONG_REFERRER_POLICIES
            message = f"Effective policy: {effective}." if effective else "No recognized referrer policy."
        elif key == "permissions-policy" and value:
            valid = "*" not in value
            message = "No wildcard capability grants detected." if valid else "Wildcard capability access detected."

        findings.append(
            Finding(
                check=label,
                status="pass" if valid else "warn",
                message=message,
                remediation="" if valid else remediation,
                points=points if valid else 0,
                max_points=points,
            )
        )

    frame_protection = _frame_protection(headers)
    findings.append(
        Finding(
            "Clickjacking protection",
            "pass" if frame_protection else "warn",
            "Frame embedding is restricted." if frame_protection else "No host-restricted framing policy was detected.",
            "Set CSP frame-ancestors or X-Frame-Options.",
            8 if frame_protection else 0,
            8,
        )
    )
    return findings


def _disclosure_findings(headers: dict[str, str]) -> list[Finding]:
    disclosed = [name for name in ("server", "x-powered-by") if headers.get(name)]
    return [
        Finding(
            "Technology disclosure",
            "warn" if disclosed else "pass",
            f"Exposed headers: {', '.join(disclosed)}" if disclosed else "No common technology disclosure headers found.",
            "Remove unnecessary version and framework disclosure headers.",
            0 if disclosed else 8,
            8,
        )
    ]


def _cookie_findings(cookie_headers: Iterable[str], is_https: bool) -> list[Finding]:
    cookies = list(cookie_headers)
    if not cookies:
        return [Finding("Cookie flags", "info", "No response cookies were set.", max_points=0)]
    insecure = []
    for index, cookie in enumerate(cookies, start=1):
        pair, *parts = cookie.split(";")
        name = pair.partition("=")[0].strip().lower()
        attributes = {}
        for part in parts:
            key, _, value = part.partition("=")
            attributes[key.strip().lower()] = value.strip()
        issues = []
        same_site = attributes.get("samesite", "").lower()
        prefixed = name.startswith(("__host-", "__secure-"))
        requires_secure = is_https or prefixed or same_site == "none" or "partitioned" in attributes
        if requires_secure and "secure" not in attributes:
            issues.append("missing Secure")
        if not is_https and (prefixed or "secure" in attributes):
            issues.append("use HTTPS to set secure cookies")
        if "httponly" not in attributes:
            issues.append("missing HttpOnly")
        if "samesite" not in attributes:
            issues.append("missing SameSite")
        elif same_site not in {"lax", "strict", "none"}:
            issues.append("invalid SameSite value")
        if name.startswith("__host-"):
            if attributes.get("path") != "/":
                issues.append("__Host- requires Path=/")
            if "domain" in attributes:
                issues.append("__Host- forbids Domain")
        if issues:
            insecure.append(f"Cookie {index}: {', '.join(issues)}")
    passed = not insecure
    return [
        Finding(
            "Cookie flags",
            "pass" if passed else "warn",
            "Response cookies use the expected security flags." if passed else "; ".join(insecure) + ".",
            "Apply Secure, HttpOnly, and an appropriate SameSite policy to sensitive cookies.",
            10 if passed else 0,
            10,
        )
    ]


def _tls_finding(hostname: str, port: int = 443, timeout: float = 5.0) -> Finding:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as secure_socket:
                certificate = secure_socket.getpeercert()
                protocol = secure_socket.version() or "unknown"
                cipher = secure_socket.cipher()
        expires = datetime.strptime(certificate["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (expires - datetime.now(timezone.utc)).days
        issuer = dict(item[0] for item in certificate.get("issuer", ())).get("organizationName", "unknown issuer")
        cipher_name = cipher[0] if cipher else "unknown cipher"
        status = "pass" if days >= 14 else "warn"
        return Finding(
            "TLS certificate",
            status,
            f"{protocol} with {cipher_name}; issued by {issuer}; valid for approximately {days} more days.",
            "Renew the certificate and verify automated renewal." if status == "warn" else "",
            20 if status == "pass" else 8,
            20,
        )
    except (OSError, ssl.SSLError, KeyError, ValueError) as exc:
        return Finding("TLS certificate", "fail", f"TLS validation failed: {exc}", "Install a trusted, valid TLS certificate.", 0, 20)


def _open_url(url: str, timeout: float):
    recorder = _RedirectRecorder()
    request = Request(url, headers={"User-Agent": "SecureSiteAuditor/0.2 (+passive-security-check)"})
    try:
        response = build_opener(recorder).open(request, timeout=timeout)
    except HTTPError as exc:
        # Error pages carry headers and a body too. Keep the status so the report identifies the page.
        response = exc
    except URLError as exc:
        raise RuntimeError(f"Could not reach the target: {exc.reason}") from exc
    except (HTTPException, OSError) as exc:
        raise RuntimeError(f"Could not read the target response ({type(exc).__name__}).") from exc
    return response, [url, *recorder.urls]


def _redirect_downgrade(chain: list[str]) -> bool:
    schemes = [urlparse(url).scheme for url in chain]
    return any(before == "https" and after == "http" for before, after in zip(schemes, schemes[1:]))


def _redirect_result(chain: list[str]) -> Finding:
    passed = urlparse(chain[-1]).scheme == "https" and not _redirect_downgrade(chain)
    return Finding(
        "HTTP to HTTPS redirect", "pass" if passed else "fail",
        " -> ".join(report_url(url) for url in chain),
        "" if passed else "Redirect HTTP traffic to HTTPS and keep subsequent hops on HTTPS.",
        10 if passed else 0, 10,
    )


def _https_redirect_finding(hostname: str, timeout: float) -> tuple[Finding, list[str]]:
    host = f"[{hostname}]" if ":" in hostname else hostname
    http_url = f"http://{host}/"
    try:
        response, chain = _open_url(http_url, timeout)
    except (RuntimeError, OSError, HTTPException):
        return Finding(
            "HTTP to HTTPS redirect",
            "info",
            f"Could not verify the redirect from {http_url}.",
        ), [http_url]
    response.close()
    return _redirect_result(chain), chain


def _html_findings(response, url: str) -> list[Finding]:
    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
        return [Finding("HTML inspection", "info", "Skipped encoded response body.")]
    try:
        # The extra byte distinguishes an exactly-at-limit page from a truncated sample.
        body = response.read(HTML_LIMIT + 1)
        charset = response.headers.get_content_charset() or "utf-8-sig"
        if body.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
            charset = "utf-16"
        length = response.headers.get("Content-Length")
        if length and length.isascii() and length.isdecimal() and int(length) > len(body) and len(body) <= HTML_LIMIT:
            return [Finding("HTML inspection", "info", "Response ended before its declared length.")]
        markup = PageMarkup()
        markup.feed(body[:HTML_LIMIT].decode(charset, errors="replace"))
        complete = len(body) <= HTML_LIMIT
        if complete:
            markup.close()
        mixed = markup.http_references(markup.resources, url) if urlparse(url).scheme == "https" else []
        forms = markup.http_references(markup.actions, url)
    except (OSError, HTTPException, ValueError, LookupError, AssertionError):
        return [Finding("HTML inspection", "info", "Could not read or interpret the HTML body.")]

    findings = []
    if not complete:
        findings.append(Finding("HTML inspection", "info", "Partial coverage. Inspected the first 512 KiB of HTML."))
    http_password = bool(markup.password_fields) and urlparse(url).scheme == "http"
    if http_password:
        forms.insert(0, "password field on an HTTP page")
    for label, matches, applicable, fix in (
        ("Mixed content", mixed, urlparse(url).scheme == "https" and bool(markup.resources),
         "Use HTTPS URLs for scripts, stylesheets and frames."),
        ("Form transport", forms, bool(markup.actions),
         "Serve the form and its submission endpoint over HTTPS."),
    ):
        if matches:
            examples = "; ".join(dict.fromkeys(matches[:3]))
            status = "fail" if label == "Form transport" and http_password else "warn"
            findings.append(Finding(label, status, f"Observed in markup: {examples}.", fix, 0, 10))
        elif complete and applicable:
            # A partial sample can reveal an HTTP URL, but a clean sample cannot establish a pass.
            findings.append(Finding(label, "pass", "No HTTP reference found in the inspected markup.", "", 10, 10))
    if not findings:
        findings.append(Finding("HTML inspection", "info", "No applicable resource or form transport checks in this markup."))
    return findings


def audit(target: str, timeout: float = 10.0) -> AuditResult:
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Timeout must be a positive, finite number.")
    target = normalize_url(target)
    response, redirect_chain = _open_url(target, timeout)

    with response:
        final_url = response.geturl()
        status = response.getcode()
        headers = {key.lower(): value for key, value in response.headers.items()}
        # Repeated policy fields form ordered lists. Each Set-Cookie field describes a separate cookie.
        for name in ("content-security-policy", "referrer-policy"):
            if name in headers:
                headers[name] = ", ".join(response.headers.get_all(name))
        cookie_headers = response.headers.get_all("Set-Cookie", [])
        media_type = response.headers.get_content_type() if response.headers.get("Content-Type") else ""
        is_html = media_type == "text/html"
        page_findings = _html_findings(response, final_url) if is_html else [
            Finding("HTML inspection", "info", "Skipped because the response was not declared text/html.")
        ]
    parsed = urlparse(final_url)
    is_https = parsed.scheme == "https"
    downgrade = _redirect_downgrade(redirect_chain)
    secure_transport = is_https and not downgrade

    findings = [
        Finding(
            "HTTPS",
            "pass" if secure_transport else "fail",
            "The redirect chain downgraded from HTTPS to HTTP." if downgrade else
            ("The final response uses HTTPS." if is_https else "The final response is served over HTTP."),
            "Redirect all HTTP traffic to HTTPS.",
            20 if secure_transport else 0,
            20,
        )
    ]
    if is_https and parsed.hostname:
        findings.append(_tls_finding(parsed.hostname, parsed.port or 443, timeout=min(timeout, 5.0)))
    # Check the host the user entered even if the final page moved to another host.
    original = urlparse(target)
    if original.scheme == "http":
        findings.append(_redirect_result(redirect_chain))
    elif original.hostname and original.port in {None, 443}:
        redirect_finding, _ = _https_redirect_finding(original.hostname, timeout)
        findings.append(redirect_finding)
    else:
        findings.append(Finding("HTTP to HTTPS redirect", "info", "HTTP counterpart unknown for this custom port."))
    if not 200 <= status < 300:
        findings.append(Finding("HTTP response", "warn", f"HTTP {status}. Findings describe this response.",
                                "Verify that this is the intended page."))
    browser_checks = {"Content Security Policy", "Clickjacking protection", "Permissions Policy"}
    browser_document = media_type in {"text/html", "application/xhtml+xml", "image/svg+xml"}
    findings.extend(f for f in _header_findings(headers, is_https) if browser_document or f.check not in browser_checks)
    findings.extend(_disclosure_findings(headers))
    findings.extend(_cookie_findings(cookie_headers, is_https))
    findings.extend(page_findings)

    earned = sum(item.points for item in findings)
    # Coverage notes have zero weight, so a skipped check cannot raise or lower the score.
    possible = sum(item.max_points for item in findings)
    score = round((earned / possible) * 100) if possible else 0
    return AuditResult(report_url(target), report_url(final_url), datetime.now(timezone.utc).isoformat(),
                       score, findings, [report_url(url) for url in redirect_chain], status)
