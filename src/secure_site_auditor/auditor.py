from __future__ import annotations

import socket
import ssl
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, build_opener


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

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "final_url": self.final_url,
            "scanned_at": self.scanned_at,
            "score": self.score,
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
        findings.append(
            Finding(
                check=label,
                status="pass" if value else "warn",
                message=f"Present: {value}" if value else "Header is missing.",
                remediation="" if value else remediation,
                points=points if value else 0,
                max_points=points,
            )
        )

    frame_protection = headers.get("x-frame-options") or "frame-ancestors" in headers.get(
        "content-security-policy", ""
    ).lower()
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
        expires = datetime.strptime(certificate["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (expires - datetime.now(timezone.utc)).days
        status = "pass" if days >= 14 else "warn"
        return Finding(
            "TLS certificate",
            status,
            f"Certificate is valid for approximately {days} more days.",
            "Renew the certificate and verify automated renewal." if status == "warn" else "",
            20 if status == "pass" else 8,
            20,
        )
    except (OSError, ssl.SSLError, KeyError, ValueError) as exc:
        return Finding("TLS certificate", "fail", f"TLS validation failed: {exc}", "Install a trusted, valid TLS certificate.", 0, 20)


def audit(target: str, timeout: float = 10.0) -> AuditResult:
    target = normalize_url(target)
    request = Request(target, headers={"User-Agent": "SecureSiteAuditor/0.1 (+passive-security-check)"})
    try:
        response = build_opener().open(request, timeout=timeout)
    except HTTPError as exc:
        response = exc
    except URLError as exc:
        raise RuntimeError(f"Could not reach the target: {exc.reason}") from exc

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
    findings.extend(_header_findings(headers, is_https))
    findings.extend(_disclosure_findings(headers))
    findings.extend(_cookie_findings(cookie_headers, is_https))

    earned = sum(item.points for item in findings)
    possible = sum(item.max_points for item in findings)
    score = round((earned / possible) * 100) if possible else 0
    return AuditResult(target, final_url, datetime.now(timezone.utc).isoformat(), score, findings)
