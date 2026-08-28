from __future__ import annotations

import socket
import ssl
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


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

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "final_url": self.final_url,
            "scanned_at": self.scanned_at,
            "score": self.score,
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
        self.urls.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


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


def _header_findings(headers: dict[str, str], is_https: bool) -> list[Finding]:
    findings: list[Finding] = []
    for key, (label, points, remediation) in SECURITY_HEADERS.items():
        if key == "strict-transport-security" and not is_https:
            continue
        value = headers.get(key, "")
        valid = bool(value)
        message = f"Present: {value}" if value else "Header is missing."

        if key == "strict-transport-security" and value:
            directives = {part.strip().lower() for part in value.split(";")}
            max_age = next((part for part in directives if part.startswith("max-age=")), "")
            try:
                seconds = int(max_age.split("=", 1)[1])
            except (IndexError, ValueError):
                seconds = -1
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
            policy = value.lower()
            weaknesses = []
            if "default-src" not in policy:
                weaknesses.append("default-src is missing")
            if "'unsafe-inline'" in policy:
                weaknesses.append("unsafe-inline is allowed")
            if "'unsafe-eval'" in policy:
                weaknesses.append("unsafe-eval is allowed")
            if "default-src *" in policy:
                weaknesses.append("default-src allows every origin")
            valid = not weaknesses
            message = "Policy has a restrictive baseline." if valid else "; ".join(weaknesses) + "."
        elif key == "x-content-type-options" and value:
            valid = value.strip().lower() == "nosniff"
            message = "Set to nosniff." if valid else f"Unexpected value: {value}"
        elif key == "referrer-policy" and value:
            policies = {part.strip().lower() for part in value.split(",")}
            valid = bool(policies & STRONG_REFERRER_POLICIES)
            message = f"Policy: {value}" if valid else f"Potentially permissive policy: {value}"
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

    x_frame_options = headers.get("x-frame-options", "").strip().lower()
    csp = headers.get("content-security-policy", "").lower()
    frame_protection = x_frame_options in {"deny", "sameorigin"} or "frame-ancestors" in csp
    findings.append(
        Finding(
            "Clickjacking protection",
            "pass" if frame_protection else "warn",
            "Frame embedding is restricted." if frame_protection else "No frame restriction was detected.",
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
    for cookie in cookies:
        attributes = {
            part.strip().split("=", 1)[0].lower()
            for part in cookie.split(";")[1:]
            if part.strip()
        }
        missing = []
        if is_https and "secure" not in attributes:
            missing.append("Secure")
        if "httponly" not in attributes:
            missing.append("HttpOnly")
        if "samesite" not in attributes:
            missing.append("SameSite")
        if missing:
            insecure.append(", ".join(missing))
    passed = not insecure
    return [
        Finding(
            "Cookie flags",
            "pass" if passed else "warn",
            "Response cookies use the expected security flags." if passed else f"Cookies are missing: {'; '.join(insecure)}.",
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
        response = exc
    except URLError as exc:
        raise RuntimeError(f"Could not reach the target: {exc.reason}") from exc
    return response, [url, *recorder.urls]


def _https_redirect_finding(hostname: str, timeout: float) -> tuple[Finding, list[str]]:
    http_url = f"http://{hostname}/"
    try:
        response, chain = _open_url(http_url, timeout)
    except RuntimeError as exc:
        return Finding(
            "HTTP to HTTPS redirect",
            "warn",
            str(exc),
            "Redirect HTTP requests permanently to the HTTPS equivalent.",
            0,
            10,
        ), [http_url]
    final_is_https = urlparse(response.geturl()).scheme == "https"
    return Finding(
        "HTTP to HTTPS redirect",
        "pass" if final_is_https else "fail",
        " -> ".join(chain),
        "Redirect HTTP requests permanently to the HTTPS equivalent." if not final_is_https else "",
        10 if final_is_https else 0,
        10,
    ), chain


def audit(target: str, timeout: float = 10.0) -> AuditResult:
    target = normalize_url(target)
    response, redirect_chain = _open_url(target, timeout)

    final_url = response.geturl()
    parsed = urlparse(final_url)
    is_https = parsed.scheme == "https"
    headers = {key.lower(): value for key, value in response.headers.items()}
    cookie_headers = response.headers.get_all("Set-Cookie", [])

    findings = [
        Finding(
            "HTTPS",
            "pass" if is_https else "fail",
            "The final response uses HTTPS." if is_https else "The final response is served over HTTP.",
            "Redirect all HTTP traffic to HTTPS.",
            20 if is_https else 0,
            20,
        )
    ]
    if is_https and parsed.hostname:
        findings.append(_tls_finding(parsed.hostname, parsed.port or 443, timeout=min(timeout, 5.0)))
    if parsed.hostname:
        redirect_finding, _ = _https_redirect_finding(parsed.hostname, timeout)
        findings.append(redirect_finding)
    findings.extend(_header_findings(headers, is_https))
    findings.extend(_disclosure_findings(headers))
    findings.extend(_cookie_findings(cookie_headers, is_https))

    earned = sum(item.points for item in findings)
    possible = sum(item.max_points for item in findings)
    score = round((earned / possible) * 100) if possible else 0
    return AuditResult(target, final_url, datetime.now(timezone.utc).isoformat(), score, findings, redirect_chain)
