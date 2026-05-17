"""Safe Web DAST crawler foundation."""

from __future__ import annotations

import posixpath
from collections import deque
from dataclasses import asdict, dataclass, field
from time import perf_counter
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup

from scanner.finding import Finding, create_finding


SOURCE = "web_crawler"
DEFAULT_USER_AGENT = "VulScan-WebDAST/13.0"
SKIPPED_SCHEMES = {"mailto", "tel", "javascript", "data", "file"}
STATIC_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".ico",
    ".pdf",
    ".zip",
    ".rar",
    ".7z",
    ".mp4",
    ".mp3",
    ".avi",
    ".css",
    ".js",
    ".woff",
    ".woff2",
    ".ttf",
}
LIMITATIONS = [
    "Version 13.0 is crawler foundation only.",
    "The crawler sends safe GET requests only, does not submit forms, does not authenticate, and does not test SQL injection or XSS.",
    "External domains are discovered but not crawled by default.",
]


@dataclass(frozen=True)
class WebFormResult:
    page_url: str
    method: str
    action: str
    input_names: list[str] = field(default_factory=list)
    input_types: list[str] = field(default_factory=list)
    has_password_field: bool = False
    has_file_upload: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class WebPageResult:
    url: str
    method: str
    status_code: int
    content_type: str
    title: str
    depth: int
    response_time_seconds: float
    links_found_count: int
    forms_found_count: int
    internal_links: list[str] = field(default_factory=list)
    external_links: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_url(url: str, base_url: str | None = None) -> str:
    """Normalize HTTP URLs for duplicate avoidance and same-host comparisons."""
    candidate = urljoin(base_url, url.strip()) if base_url else url.strip()
    parts = urlsplit(candidate)
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    if ":" in netloc:
        host, _, port = netloc.partition(":")
        if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
            netloc = host
    path = parts.path or "/"
    path = posixpath.normpath(path)
    if not path.startswith("/"):
        path = f"/{path}"
    if parts.path.endswith("/") and not path.endswith("/"):
        path = f"{path}/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def should_skip_url(url: str) -> bool:
    parts = urlsplit(url)
    if parts.scheme.lower() in SKIPPED_SCHEMES:
        return True
    path = parts.path.lower()
    return any(path.endswith(extension) for extension in STATIC_EXTENSIONS)


def crawl_web(
    *,
    start_url: str,
    crawl: bool = True,
    max_pages: int = 20,
    max_depth: int = 2,
    timeout: float = 10.0,
    user_agent: str = DEFAULT_USER_AGENT,
    session: Any | None = None,
) -> dict[str, Any]:
    """Run a safe same-host GET-only crawl."""
    started = perf_counter()
    normalized_start = normalize_url(start_url)
    parsed_start = urlsplit(normalized_start)
    if parsed_start.scheme not in {"http", "https"} or not parsed_start.netloc:
        raise ValueError("--url must be an absolute http or https URL.")

    allowed_host = parsed_start.netloc.lower()
    client = session or requests.Session()
    headers = {"User-Agent": user_agent}
    queue: deque[tuple[str, int]] = deque([(normalized_start, 0)])
    queued = {normalized_start}
    visited: set[str] = set()
    skipped: set[str] = set()
    pages: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    unique_internal_links: set[str] = set()
    unique_external_links: set[str] = set()

    while queue and len(pages) < max(1, int(max_pages)):
        current_url, depth = queue.popleft()
        if current_url in visited:
            continue
        visited.add(current_url)
        if depth > max_depth:
            skipped.add(current_url)
            continue

        try:
            response_started = perf_counter()
            response = client.get(
                current_url,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            )
            response_time = round(perf_counter() - response_started, 3)
        except Exception as exc:
            errors.append(
                {
                    "url": current_url,
                    "depth": depth,
                    "error": exc.__class__.__name__,
                    "message": str(exc)[:200],
                }
            )
            continue

        content_type = str(response.headers.get("Content-Type") or response.headers.get("content-type") or "")
        html = str(response.text or "") if _is_html(content_type) else ""
        parsed = _parse_html(current_url, html) if html else {"title": "", "internal_links": [], "external_links": [], "forms": []}
        page_forms = parsed["forms"]
        forms.extend(page_forms)
        internal_links = list(parsed["internal_links"])
        external_links = list(parsed["external_links"])
        unique_internal_links.update(internal_links)
        unique_external_links.update(external_links)

        pages.append(
            WebPageResult(
                url=current_url,
                method="GET",
                status_code=int(getattr(response, "status_code", 0) or 0),
                content_type=content_type,
                title=str(parsed["title"]),
                depth=depth,
                response_time_seconds=response_time,
                links_found_count=len(internal_links) + len(external_links),
                forms_found_count=len(page_forms),
                internal_links=internal_links,
                external_links=external_links,
                forms=page_forms,
            ).to_dict()
        )

        if not crawl or depth >= max_depth:
            continue
        for link in internal_links:
            if len(queued) >= max_pages:
                skipped.add(link)
                continue
            if link not in queued and link not in visited:
                queue.append((link, depth + 1))
                queued.add(link)

    summary = {
        "enabled": True,
        "start_url": start_url,
        "normalized_start_url": normalized_start,
        "allowed_host": allowed_host,
        "max_pages": int(max_pages),
        "max_depth": int(max_depth),
        "pages_crawled": len(pages),
        "pages_skipped": len(skipped),
        "unique_internal_links": len(unique_internal_links),
        "unique_external_links": len(unique_external_links),
        "forms_discovered": len(forms),
        "password_forms_discovered": sum(1 for form in forms if form.get("has_password_field")),
        "file_upload_forms_discovered": sum(1 for form in forms if form.get("has_file_upload")),
        "errors_count": len(errors),
        "duration_seconds": round(perf_counter() - started, 3),
        "limitations": list(LIMITATIONS),
    }
    findings = build_web_findings(summary=summary, forms=forms, pages=pages, errors=errors)
    return {
        "enabled": True,
        "source": SOURCE,
        "status": "success" if not errors else "partial",
        "web_scan_summary": summary,
        "crawled_pages": pages,
        "discovered_forms": forms,
        "errors": errors,
        "findings": findings,
    }


def build_web_findings(
    *,
    summary: dict[str, Any],
    forms: list[dict[str, Any]],
    pages: list[dict[str, Any]],
    errors: list[dict[str, Any]],
) -> list[Finding]:
    findings = [
        create_finding(
            title="Web Crawl Completed",
            severity="Informational",
            category="Web DAST",
            affected_url=str(summary.get("normalized_start_url") or summary.get("start_url") or ""),
            service="http",
            evidence=f"Crawler visited {summary.get('pages_crawled', 0)} pages and discovered {summary.get('forms_discovered', 0)} forms.",
            confidence="High",
            impact="Crawl results support review and future safe DAST testing.",
            recommendation="Review discovered pages and forms before deeper DAST testing.",
            verification="Review the Web DAST crawl report.",
            limitation="Version 13.0 does not submit forms or test injection vulnerabilities.",
            source=SOURCE,
        )
    ]
    for form in forms:
        if form.get("has_password_field"):
            findings.append(
                create_finding(
                    title="Password Form Discovered",
                    severity="Informational",
                    category="Web Form Discovery",
                    affected_url=str(form.get("page_url") or ""),
                    service="http",
                    evidence=f"Password input field discovered on {form.get('page_url')}.",
                    confidence="High",
                    impact="Login forms should use HTTPS and secure authentication controls.",
                    recommendation="Ensure login forms use HTTPS and secure authentication controls.",
                    verification="Review the discovered form manually.",
                    limitation="This finding does not test authentication security.",
                    source=SOURCE,
                )
            )
        if form.get("has_file_upload"):
            findings.append(
                create_finding(
                    title="File Upload Form Discovered",
                    severity="Low",
                    category="Web Form Discovery",
                    affected_url=str(form.get("page_url") or ""),
                    service="http",
                    evidence=f"File upload input discovered on {form.get('page_url')}.",
                    confidence="High",
                    impact="File upload features require careful validation and storage controls.",
                    recommendation="Review file upload validation, content-type restrictions, and storage controls.",
                    verification="Review the discovered form manually.",
                    limitation="This finding does not test upload bypass or exploitation.",
                    source=SOURCE,
                )
            )
    external_count = int(summary.get("unique_external_links") or 0)
    if external_count:
        findings.append(
            create_finding(
                title="External Links Discovered",
                severity="Informational",
                category="Web Discovery",
                affected_url=str(summary.get("normalized_start_url") or ""),
                service="http",
                evidence=f"{external_count} unique external links were found but not crawled.",
                confidence="High",
                impact="External dependencies and third-party links may affect application risk.",
                recommendation="Review external dependencies and third-party links.",
                verification="Review the external links in the crawl report.",
                limitation="External domains are not crawled by default.",
                source=SOURCE,
            )
        )
    if errors:
        findings.append(
            create_finding(
                title="Web Crawl Error",
                severity="Low",
                category="Web DAST",
                affected_url=str(summary.get("normalized_start_url") or ""),
                service="http",
                evidence=f"{len(errors)} page(s) could not be fetched during the crawl.",
                confidence="Medium",
                impact="Crawl coverage may be incomplete.",
                recommendation="Review errors and retry if needed.",
                verification="Review the crawl errors in the report.",
                limitation="Network errors, redirects, or access controls may affect crawl coverage.",
                source=SOURCE,
            )
        )
    return findings


def _parse_html(page_url: str, html: str) -> dict[str, Any]:
    soup = BeautifulSoup(html, "html.parser")
    title_node = soup.find("title")
    title = " ".join(title_node.get_text(" ", strip=True).split()) if title_node else ""
    internal_links: list[str] = []
    external_links: list[str] = []
    allowed_host = urlsplit(page_url).netloc.lower()
    for anchor in soup.find_all("a"):
        href = str(anchor.get("href") or "").strip()
        if not href:
            continue
        normalized = normalize_url(href, page_url)
        if should_skip_url(normalized):
            continue
        parts = urlsplit(normalized)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            continue
        if parts.netloc.lower() == allowed_host:
            if normalized not in internal_links:
                internal_links.append(normalized)
        elif normalized not in external_links:
            external_links.append(normalized)
    forms = [_parse_form(page_url, form).to_dict() for form in soup.find_all("form")]
    return {
        "title": title,
        "internal_links": internal_links,
        "external_links": external_links,
        "forms": forms,
    }


def _parse_form(page_url: str, form: Any) -> WebFormResult:
    method = str(form.get("method") or "GET").upper()
    action = normalize_url(str(form.get("action") or page_url), page_url)
    input_names: list[str] = []
    input_types: list[str] = []
    has_password = False
    has_file = False
    for input_node in form.find_all(["input", "textarea", "select"]):
        name = str(input_node.get("name") or "").strip()
        input_type = str(input_node.get("type") or input_node.name or "text").strip().lower()
        if name:
            input_names.append(name)
        input_types.append(input_type)
        if input_type == "password":
            has_password = True
        if input_type == "file":
            has_file = True
    return WebFormResult(
        page_url=page_url,
        method=method,
        action=action,
        input_names=input_names,
        input_types=input_types,
        has_password_field=has_password,
        has_file_upload=has_file,
    )


def _is_html(content_type: str) -> bool:
    lowered = content_type.lower()
    return "text/html" in lowered or "application/xhtml+xml" in lowered or not lowered
