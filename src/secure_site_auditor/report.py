from __future__ import annotations

import html
import json
import textwrap
from collections import Counter
from pathlib import Path

from .auditor import AuditResult


def _terminal_text(value: str) -> str:
    return "".join(char if char.isprintable() else " " for char in value)


def render_text(result: AuditResult, width: int = 88) -> str:
    width = max(32, min(width, 120))
    counts = Counter(f.status for f in result.findings)
    earned = sum(f.points for f in result.findings)
    possible = sum(f.max_points for f in result.findings)
    lines = [
        "Secure Site Auditor",
        "=" * 19,
        f"Target       {_terminal_text(result.target)}",
    ]
    if len(result.redirect_chain) > 1:
        lines.extend(textwrap.wrap("Redirects    " + " -> ".join(map(_terminal_text, result.redirect_chain)),
                                   width, subsequent_indent="             "))
    if result.final_url != result.target:
        lines.append(f"Final URL    {_terminal_text(result.final_url)}")
    if result.http_status is not None:
        lines.append(f"Response     HTTP {result.http_status}")
    lines.extend([
        f"Score        {result.score}/100  ({earned}/{possible} applicable points)",
        f"Checks       {counts['fail']} failed, {counts['warn']} warnings, {counts['pass']} passed, {counts['info']} info",
    ])
    for title, statuses in (("Needs attention", ("fail", "warn")), ("Passed", ("pass",)), ("Coverage notes", ("info",))):
        group = [f for status in statuses for f in result.findings if f.status == status]
        if group:
            lines.extend(["", title, "-" * len(title)])
        for finding in group:
            lines.append(f"[{finding.status.upper()}] {_terminal_text(finding.check)}")
            lines.extend(textwrap.wrap(_terminal_text(finding.message), width, initial_indent="  ", subsequent_indent="  "))
            if finding.remediation and finding.status in {"warn", "fail"}:
                lines.extend(textwrap.wrap("Fix: " + _terminal_text(finding.remediation), width,
                                           initial_indent="  ", subsequent_indent="       "))
    return "\n".join(lines)


def render_html(result: AuditResult) -> str:
    rows = []
    status_line = f"HTTP {result.http_status}<br>" if result.http_status is not None else ""
    for finding in result.findings:
        remediation = html.escape(finding.remediation) if finding.status != "pass" else ""
        rows.append(
            f'<article class="finding {finding.status}"><div><span>{finding.status.upper()}</span>'
            f'<h2>{html.escape(finding.check)}</h2></div><p>{html.escape(finding.message)}</p>'
            f'<small>{remediation}</small></article>'
        )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Security audit for {html.escape(result.target)}</title><style>
body{{margin:0;background:#10110f;color:#f1f0e9;font:16px system-ui,sans-serif}}main{{width:min(900px,calc(100% - 32px));margin:60px auto}}
.score{{font-size:72px;font-weight:800;color:#c8ff32}}.meta{{color:#a8a99f}}.finding{{border-top:1px solid #3b3c37;padding:22px 0}}
.finding div{{display:flex;align-items:center;gap:14px}}.finding span{{font:700 11px monospace;letter-spacing:.1em;color:#c8ff32}}
.finding.warn span{{color:#ffcc66}}.finding.fail span{{color:#ff6b6b}}h1,h2{{margin:0}}h2{{font-size:20px}}p,small{{color:#b8b9b0;line-height:1.6}}small{{display:block}}
</style></head><body><main><p class="meta">PASSIVE WEBSITE SECURITY REVIEW</p><h1>{html.escape(result.target)}</h1>
<div class="score">{result.score}<small>/100</small></div><p class="meta">{status_line}Final URL: {html.escape(result.final_url)}<br>
Redirects: {html.escape(' -> '.join(result.redirect_chain))}<br>Scanned {html.escape(result.scanned_at)}</p>{''.join(rows)}</main></body></html>"""


def save_report(result: AuditResult, output: str, output_format: str) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    if output_format == "json":
        content = json.dumps(result.to_dict(), indent=2)
    elif output_format == "html":
        content = render_html(result)
    else:
        content = render_text(result)
    path.write_text(content, encoding="utf-8")
    return path
