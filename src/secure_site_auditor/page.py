from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit


def report_url(url: str) -> str:
    """Keep the location useful without copying credentials, queries or fragments."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc.rsplit("@", 1)[-1], parts.path, "", ""))


class PageMarkup(HTMLParser):
    """Collect static references without requesting them or running page code."""

    def __init__(self) -> None:
        super().__init__()
        self.base: str | None = None
        self.resources: list[tuple[str, str]] = []
        self.actions: list[tuple[str, str]] = []
        self.password_fields = 0
        self.inert: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in {"template", "noscript", "textarea", "title", "iframe"}:
            self.inert.append(tag)
            if len(self.inert) > 1 or tag != "iframe":
                return
        elif self.inert:
            return
        # HTML parsers retain the first occurrence of a duplicate attribute.
        values = dict(reversed([(key, value or "") for key, value in attrs]))
        if tag == "base" and "href" in values and self.base is None:
            self.base = values["href"]
        elif tag in {"script", "iframe"} and values.get("src") and not (tag == "iframe" and "srcdoc" in values):
            self.resources.append((tag, values["src"]))
        elif tag == "link" and "stylesheet" in values.get("rel", "").lower().split() and values.get("href"):
            self.resources.append(("stylesheet", values["href"]))
        elif tag == "form":
            self.actions.append(("form", values.get("action", "")))
        elif tag in {"input", "button"}:
            kind = values.get("type", "submit" if tag == "button" else "text").lower()
            if tag == "input" and kind == "password":
                self.password_fields += 1
            if kind in {"submit", "image"} and "formaction" in values:
                self.actions.append(("formaction", values["formaction"]))

    def handle_endtag(self, tag):
        if self.inert and self.inert[-1] == tag:
            self.inert.pop()

    def http_references(self, references: list[tuple[str, str]], document: str) -> list[str]:
        base = urljoin(document, self.base or "")
        evidence = []
        for label, value in references:
            destination = urljoin(base, value.strip()) if value.strip() else document
            if urlsplit(destination).scheme == "http":
                evidence.append(f"{label} {report_url(destination)}")
        return evidence
