"""Safe Web DAST crawler foundation."""

from __future__ import annotations

import posixpath
import hashlib
from collections import deque
from dataclasses import asdict, dataclass, field
from time import perf_counter
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup

from scanner.finding import Finding, create_finding
from scanner.web_cookie_audit import parse_set_cookie_headers


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
    form_id: str
    page_url: str
    method: str
    action: str
    page_title: str = ""
    resolved_action_url: str = ""
    action_host: str = ""
    is_internal_action: bool = True
    is_https_context: bool = False
    sends_to_http_from_https: bool = False
    enctype: str = ""
    autocomplete: str = ""
    input_count: int = 0
    hidden_input_count: int = 0
    password_input_count: int = 0
    file_input_count: int = 0
    textarea_count: int = 0
    select_count: int = 0
    submit_button_count: int = 0
    csrf_token_like_fields: list[str] = field(default_factory=list)
    input_fields: list[dict[str, Any]] = field(default_factory=list)
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
    response_headers: dict[str, str] = field(default_factory=dict)
    cookie_flags: list[dict[str, bool]] = field(default_factory=list)
    cookies: list[dict[str, Any]] = field(default_factory=list)

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
    scope: Any | None = None,
) -> dict[str, Any]:
    """Run a safe same-host GET-only crawl."""
    started = perf_counter()
    normalized_start = normalize_url(start_url)
    parsed_start = urlsplit(normalized_start)
    if parsed_start.scheme not in {"http", "https"} or not parsed_start.netloc:
        raise ValueError("--url must be an absolute http or https URL.")

    if scope is None:
        from scanner.web_scope import build_web_scope

        scope = build_web_scope(
            start_url=normalized_start,
            max_pages=max_pages,
            max_depth=max_depth,
        )
    start_allowed, start_reason, normalized_start = scope.decide_url(normalized_start)
    if not start_allowed:
        scope.record_skip(url=normalized_start, reason=start_reason, source_url="", depth=0)
        raise ValueError(f"Start URL is outside the configured Web DAST scope: {start_reason}.")

    allowed_host = parsed_start.netloc.lower()
    client = session or requests.Session()
    headers = {"User-Agent": user_agent}
    queue: deque[tuple[str, int]] = deque([(normalized_start, 0)])
    queued = {normalized_start}
    visited: set[str] = set()
    pages: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    unique_internal_links: set[str] = set()
    unique_external_links: set[str] = set()

    page_limit = max(1, int(max_pages))
    depth_limit = int(max_depth)
    while queue and len(pages) < page_limit:
        current_url, depth = queue.popleft()
        if current_url in visited:
            scope.record_skip(url=current_url, reason="skipped_duplicate", source_url=current_url, depth=depth)
            continue
        visited.add(current_url)
        if depth > depth_limit:
            scope.record_skip(url=current_url, reason="skipped_depth_limit", source_url=current_url, depth=depth)
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
        response_headers = _safe_response_headers(response.headers)
        cookies = parse_set_cookie_headers(_header_values(response.headers, "Set-Cookie"), current_url)
        cookie_flags = [
            {
                "secure": bool(cookie.get("secure")),
                "httponly": bool(cookie.get("httponly")),
                "samesite": bool(cookie.get("samesite")),
            }
            for cookie in cookies
        ]
        html = str(response.text or "") if _is_html(content_type) else ""
        parsed = _parse_html(current_url, html) if html else {"title": "", "links": [], "forms": []}
        page_forms = parsed["forms"]
        forms.extend(page_forms)
        internal_links: list[str] = []
        external_links: list[str] = []
        for link in parsed.get("links") or []:
            allowed, reason, normalized_link = scope.decide_url(str(link), current_url)
            if allowed:
                if normalized_link not in internal_links:
                    internal_links.append(normalized_link)
                unique_internal_links.add(normalized_link)
                continue
            scope.record_skip(
                url=normalized_link,
                reason=reason,
                source_url=current_url,
                depth=depth + 1,
            )
            if reason == "skipped_external_host" and normalized_link not in external_links:
                external_links.append(normalized_link)
                unique_external_links.add(normalized_link)

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
                response_headers=response_headers,
                cookie_flags=cookie_flags,
                cookies=cookies,
            ).to_dict()
        )

        if not crawl:
            continue
        if depth >= depth_limit:
            for link in internal_links:
                scope.record_skip(url=link, reason="skipped_depth_limit", source_url=current_url, depth=depth + 1)
            continue
        for link in internal_links:
            if len(queued) >= page_limit:
                scope.record_skip(url=link, reason="skipped_page_limit", source_url=current_url, depth=depth + 1)
                continue
            if link not in queued and link not in visited:
                queue.append((link, depth + 1))
                queued.add(link)
            else:
                scope.record_skip(url=link, reason="skipped_duplicate", source_url=current_url, depth=depth + 1)

    while queue:
        queued_url, queued_depth = queue.popleft()
        scope.record_skip(url=queued_url, reason="skipped_page_limit", source_url="", depth=queued_depth)

    scope_summary = scope.summary()
    summary = {
        "enabled": True,
        "start_url": start_url,
        "normalized_start_url": normalized_start,
        "allowed_host": allowed_host,
        "max_pages": int(max_pages),
        "max_depth": int(max_depth),
        "pages_crawled": len(pages),
        "pages_skipped": int(scope_summary.get("total_skipped_urls") or 0),
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
        "web_scope_summary": scope_summary,
        "skipped_url_samples": list(scope.skipped_url_samples),
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
    links: list[str] = []
    for anchor in soup.find_all("a"):
        href = str(anchor.get("href") or "").strip()
        if not href:
            continue
        normalized = normalize_url(href, page_url)
        if normalized not in links:
            links.append(normalized)
    forms = [
        _parse_form(page_url, form, page_title=title, index=index).to_dict()
        for index, form in enumerate(soup.find_all("form"), start=1)
    ]
    return {
        "title": title,
        "links": links,
        "forms": forms,
    }


def _parse_form(page_url: str, form: Any, *, page_title: str, index: int) -> WebFormResult:
    method = str(form.get("method") or "GET").upper()
    action = str(form.get("action") or page_url)
    resolved_action = normalize_url(action, page_url)
    page_host = urlsplit(page_url).netloc.lower()
    action_host = urlsplit(resolved_action).netloc.lower()
    is_https_context = urlsplit(page_url).scheme == "https"
    enctype = str(form.get("enctype") or "").strip().lower()
    autocomplete = str(form.get("autocomplete") or "").strip()
    input_names: list[str] = []
    input_types: list[str] = []
    input_fields: list[dict[str, Any]] = []
    csrf_like: list[str] = []
    has_password = False
    has_file = False
    hidden_count = 0
    password_count = 0
    file_count = 0
    textarea_count = 0
    select_count = 0
    submit_count = 0
    for input_node in form.find_all(["input", "textarea", "select"]):
        name = str(input_node.get("name") or "").strip()
        field_id = str(input_node.get("id") or "").strip()
        input_type = str(input_node.get("type") or input_node.name or "text").strip().lower()
        placeholder = str(input_node.get("placeholder") or "").strip()[:120]
        field_autocomplete = str(input_node.get("autocomplete") or "").strip()
        maxlength = str(input_node.get("maxlength") or "").strip()
        if name:
            input_names.append(name)
        input_types.append(input_type)
        field_label = name or field_id
        if _is_csrf_like(field_label):
            csrf_like.append(field_label)
        if input_type == "hidden":
            hidden_count += 1
        if input_type == "password":
            has_password = True
            password_count += 1
        if input_type == "file":
            has_file = True
            file_count += 1
        if input_type in {"submit", "button", "image"}:
            submit_count += 1
        if input_node.name == "textarea":
            textarea_count += 1
        if input_node.name == "select":
            select_count += 1
        input_fields.append(
            {
                "name": name,
                "type": input_type,
                "id": field_id,
                "placeholder": placeholder,
                "required": bool(input_node.get("required") is not None),
                "autocomplete": field_autocomplete,
                "maxlength": maxlength,
                "value_present": input_node.get("value") is not None,
                "looks_sensitive": _looks_sensitive(field_label),
            }
        )
    form_id = _form_id(page_url, method, resolved_action, input_names, input_types, index)
    return WebFormResult(
        form_id=form_id,
        page_url=page_url,
        page_title=page_title,
        method=method,
        action=action,
        resolved_action_url=resolved_action,
        action_host=action_host,
        is_internal_action=action_host == page_host,
        is_https_context=is_https_context,
        sends_to_http_from_https=is_https_context and urlsplit(resolved_action).scheme == "http",
        enctype=enctype,
        autocomplete=autocomplete,
        input_count=len(input_fields),
        hidden_input_count=hidden_count,
        password_input_count=password_count,
        file_input_count=file_count,
        textarea_count=textarea_count,
        select_count=select_count,
        submit_button_count=submit_count,
        csrf_token_like_fields=csrf_like,
        input_fields=input_fields,
        input_names=input_names,
        input_types=input_types,
        has_password_field=has_password,
        has_file_upload=has_file or enctype == "multipart/form-data",
    )


def _form_id(
    page_url: str,
    method: str,
    action: str,
    input_names: list[str],
    input_types: list[str],
    index: int,
) -> str:
    material = "|".join([page_url, method, action, ",".join(input_names), ",".join(input_types), str(index)])
    return f"FORM-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:12].upper()}"


def _is_csrf_like(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in ("csrf", "xsrf", "anti-forgery", "requestverificationtoken"))


def _looks_sensitive(value: str) -> bool:
    lowered = value.lower()
    indicators = (
        "password",
        "passwd",
        "pwd",
        "token",
        "csrf",
        "secret",
        "api_key",
        "auth",
        "session",
        "otp",
        "mfa",
        "credit",
        "card",
        "ssn",
        "national",
        "ni_number",
    )
    return any(indicator in lowered for indicator in indicators)


def _is_html(content_type: str) -> bool:
    lowered = content_type.lower()
    return "text/html" in lowered or "application/xhtml+xml" in lowered or not lowered


def _safe_response_headers(headers: Any) -> dict[str, str]:
    safe_headers: dict[str, str] = {}
    for key, value in dict(headers or {}).items():
        name = str(key)
        if name.lower() == "set-cookie":
            safe_headers[name] = "[set-cookie present]"
            continue
        safe_headers[name] = str(value)[:300]
    return safe_headers


def _header_values(headers: Any, header_name: str) -> list[str]:
    if headers is None:
        return []
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        return [str(value) for value in get_all(header_name) or []]
    getlist = getattr(headers, "getlist", None)
    if callable(getlist):
        return [str(value) for value in getlist(header_name) or []]
    values: list[str] = []
    for key, value in dict(headers or {}).items():
        if str(key).lower() == header_name.lower():
            values.append(str(value))
    return values
