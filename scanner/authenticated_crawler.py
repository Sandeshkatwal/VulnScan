"""GET-only Authenticated Crawl with Session Boundary Controls."""

from __future__ import annotations

import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit
from uuid import uuid4

import requests
from bs4 import BeautifulSoup

from scanner.auth_context import build_auth_context
from scanner.auth_redaction import redact_secret_text, safe_profile_summary
from scanner.authenticated_evidence import build_redacted_evidence_summary, redact_request_for_logs, redact_response_for_storage
from scanner.authenticated_scope import classify_auth_required_endpoints
from scanner.session_boundary import boundary_event_from_decision, classify_session_boundary
from scanner.session_profiles import ensure_auth_profile_dirs, validate_session_profile
from scanner.web_crawler import normalize_url, should_skip_url


AUTHENTICATED_CRAWL_REPORTS_DIR = Path("reports") / "authenticated" / "crawls"
DEFAULT_USER_AGENT = "VulScan-AuthenticatedCrawl/21.1"


def build_authenticated_request_context(session_profile: dict[str, Any]) -> dict[str, Any]:
    summary = safe_profile_summary(session_profile)
    validation = validate_session_profile(session_profile)
    headers = dict(session_profile.get("headers") or {})
    cookies = dict(session_profile.get("cookies") or {})
    placeholder_only = _placeholder_only(headers) and _placeholder_only(cookies)
    return {
        "enabled": True,
        "profile_summary": summary,
        "headers": headers,
        "cookies": cookies,
        "auth_type": summary.get("auth_type") or "manual",
        "cookie_names": summary.get("cookie_names", []),
        "header_names": summary.get("header_names", []),
        "role_label": summary.get("role_label") or "",
        "redaction_status": "redacted",
        "placeholder_only": placeholder_only,
        "warnings": validation.get("warnings", []) + (["Profile contains redacted placeholders only; crawl may behave like an unauthenticated request."] if placeholder_only else []),
    }


def apply_auth_context_to_request(request: dict[str, Any], auth_context: dict[str, Any]) -> dict[str, Any]:
    headers = dict(request.get("headers") or {})
    cookies = dict(request.get("cookies") or {})
    headers.update(dict(auth_context.get("headers") or {}))
    cookies.update(dict(auth_context.get("cookies") or {}))
    request["headers"] = headers
    request["cookies"] = cookies
    return request


def authenticated_crawl(
    start_url: str,
    session_profile: dict[str, Any],
    options: dict[str, Any] | None = None,
    *,
    session: Any | None = None,
) -> dict[str, Any]:
    options = dict(options or {})
    ensure_auth_profile_dirs()
    AUTHENTICATED_CRAWL_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    crawl_id = f"authcrawl_{uuid4().hex[:12]}"
    started_at = datetime.now(timezone.utc)
    max_pages = max(1, int(options.get("max_pages", 30)))
    max_depth = max(0, int(options.get("max_depth", 2)))
    request_delay = max(0.0, float(options.get("request_delay_seconds", options.get("request_delay", 1.0))))
    timeout = max(1.0, float(options.get("timeout", 5)))
    max_redirects = max(0, int(options.get("max_redirects", 5)))
    same_origin_only = bool(options.get("same_origin_only", True))
    dry_run = bool(options.get("dry_run", False))
    profile_summary = safe_profile_summary(session_profile)
    auth_context = build_auth_context(session_profile)
    request_context = build_authenticated_request_context(session_profile)
    normalized_start = normalize_url(start_url)
    start_decision = classify_session_boundary(normalized_start, session_profile, start_url=normalized_start, same_origin_only=same_origin_only)

    results: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    boundary_events: list[dict[str, Any]] = []
    endpoint_rows: list[dict[str, Any]] = []
    requests_attempted = 0
    requests_completed = 0
    links_discovered = 0

    if not start_decision.get("allowed"):
        skipped.append(_skipped(normalized_start, start_decision, "start_url"))
        boundary_events.append(boundary_event_from_decision(start_decision))
        return _result(crawl_id, normalized_start, profile_summary, auth_context, started_at, results, skipped, boundary_events, endpoint_rows, options, requests_attempted, requests_completed, links_discovered)

    client = session or requests.Session()
    queue: deque[tuple[str, int, str]] = deque([(normalized_start, 0, "start_url")])
    queued = {normalized_start}
    visited: set[str] = set()

    while queue and len(results) < max_pages:
        current_url, depth, source = queue.popleft()
        if current_url in visited:
            continue
        if depth > max_depth:
            decision = {**start_decision, "url": current_url, "reason": "Max depth reached.", "matched_rule": "max_depth", "event_type": "out_of_scope_skipped", "severity": "low", "action_taken": "skipped", "allowed": False}
            skipped.append(_skipped(current_url, decision, source))
            boundary_events.append(boundary_event_from_decision(decision))
            continue
        decision = classify_session_boundary(current_url, session_profile, start_url=normalized_start, same_origin_only=same_origin_only)
        if not decision.get("allowed"):
            skipped.append(_skipped(current_url, decision, source))
            boundary_events.append(boundary_event_from_decision(decision))
            continue
        visited.add(current_url)
        if dry_run:
            row = _dry_run_row(current_url, depth, decision, request_context)
            results.append(row)
            endpoint_rows.append(row)
            continue
        requests_attempted += 1
        request = apply_auth_context_to_request({"method": "GET", "url": current_url, "headers": {"User-Agent": DEFAULT_USER_AGENT}, "cookies": {}}, request_context)
        redacted_request = redact_request_for_logs(request)
        try:
            started = time.perf_counter()
            response = client.get(current_url, headers=request["headers"], cookies=request["cookies"], timeout=timeout, allow_redirects=False)
            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
            requests_completed += 1
        except Exception as exc:
            event = {"url": current_url, "event_type": "request_error", "reason": exc.__class__.__name__, "matched_rule": "request", "severity": "low", "action_taken": "recorded"}
            boundary_events.append(event)
            skipped.append({"url": current_url, "reason": exc.__class__.__name__, "matched_rule": "request", "source": source})
            continue
        text = _limited_text(response)
        soup = BeautifulSoup(text, "html.parser") if _is_html(response) else BeautifulSoup("", "html.parser")
        title = _title(soup)
        final_url = normalize_url(str(getattr(response, "url", current_url) or current_url), current_url)
        redirect_chain = _redirect_chain(response)
        expiry = detect_session_expiry(response, final_url, title, text[:2000])
        if expiry.get("session_expiry_indicator"):
            boundary_events.append({"url": current_url, "event_type": "session_expiry_detected", "reason": expiry.get("reason"), "matched_rule": "session_expiry_indicator", "severity": "medium", "action_taken": "recorded"})
        links = _safe_links(soup, current_url)
        links_discovered += len(links)
        forms = _form_metadata(soup, current_url)
        for link in links:
            normalized_link = normalize_url(link, current_url)
            if should_skip_url(normalized_link):
                continue
            link_decision = classify_session_boundary(normalized_link, session_profile, start_url=normalized_start, same_origin_only=same_origin_only)
            if not link_decision.get("allowed"):
                skipped.append(_skipped(normalized_link, link_decision, current_url))
                boundary_events.append(boundary_event_from_decision(link_decision))
                continue
            if normalized_link not in queued and normalized_link not in visited and len(queued) + len(results) < max_pages:
                queued.add(normalized_link)
                queue.append((normalized_link, depth + 1, current_url))
        status_code = int(getattr(response, "status_code", 0) or 0)
        endpoint_category = _endpoint_category(current_url, expiry)
        evidence_summary = build_redacted_evidence_summary(status_code=status_code, title=title, content_type=_content_type(response), indicators=[expiry.get("reason") or ""] if expiry.get("session_expiry_indicator") else [])
        row = {
            "url": current_url,
            "normalised_url": current_url,
            "method": "GET",
            "status_code": status_code,
            "content_type": _content_type(response),
            "page_title": title,
            "title": title,
            "final_url": final_url,
            "redirect_chain": redirect_chain[:max_redirects],
            "response_time_ms": elapsed_ms,
            "auth_context_used": bool(request_context.get("headers") or request_context.get("cookies")),
            "auth_required_likely": bool(expiry.get("session_expiry_indicator") or status_code in {401, 403}),
            "session_expiry_indicator": bool(expiry.get("session_expiry_indicator")),
            "session_expiry_reason": expiry.get("reason") or "",
            "session_expiry_confidence": expiry.get("confidence") or "Low",
            "boundary_status": decision.get("boundary_status") or "allowed",
            "boundary_reason": decision.get("reason") or "",
            "endpoint_category": endpoint_category,
            "discovered_links_count": len(links),
            "forms": forms,
            "redacted_evidence_summary": evidence_summary,
            "redacted_request_summary": redacted_request,
            "redacted_response_summary": redact_response_for_storage({"url": current_url, "status_code": status_code, "content_type": _content_type(response), "headers": getattr(response, "headers", {}) or {}, "snippet": ""}),
            "source": "authenticated_crawl",
            "role_label": profile_summary.get("role_label") or "",
        }
        results.append(row)
        endpoint_rows.append(row)
        if request_delay > 0 and queue:
            time.sleep(request_delay)

    return _result(crawl_id, normalized_start, profile_summary, auth_context, started_at, results, skipped, boundary_events, endpoint_rows, options, requests_attempted, requests_completed, links_discovered)


def detect_session_expiry(response: Any, final_url: str, title: str, snippet: str) -> dict[str, Any]:
    status_code = int(getattr(response, "status_code", 0) or 0)
    final = str(final_url or "").lower()
    title_text = str(title or "").lower()
    body = str(snippet or "").lower()
    headers = getattr(response, "headers", {}) or {}
    if status_code in {401, 403}:
        return {"session_expiry_indicator": True, "reason": f"HTTP {status_code} indicates authentication is required.", "confidence": "High"}
    if any(token in final for token in ("/login", "/signin", "/auth")):
        return {"session_expiry_indicator": True, "reason": "Redirect or final URL indicates login is required.", "confidence": "High"}
    if any(token in title_text for token in ("login", "sign in", "signin")):
        return {"session_expiry_indicator": True, "reason": "Page title indicates login is required.", "confidence": "Medium"}
    for token in ("session expired", "please log in", "sign in to continue", "authentication required", "unauthorized", "forbidden"):
        if token in body:
            return {"session_expiry_indicator": True, "reason": f"Body snippet contains '{token}'.", "confidence": "Medium"}
    set_cookie = " ".join(str(value) for key, value in dict(headers).items() if str(key).lower() == "set-cookie").lower()
    if "expires=thu, 01 jan 1970" in set_cookie or "max-age=0" in set_cookie:
        return {"session_expiry_indicator": True, "reason": "Set-Cookie appears to clear a session cookie.", "confidence": "Medium"}
    return {"session_expiry_indicator": False, "reason": "", "confidence": "Low"}


def _result(crawl_id: str, target_base_url: str, profile_summary: dict[str, Any], auth_context: dict[str, Any], started_at: datetime, results: list[dict[str, Any]], skipped: list[dict[str, Any]], events: list[dict[str, Any]], endpoint_rows: list[dict[str, Any]], options: dict[str, Any], requests_attempted: int, requests_completed: int, links_discovered: int) -> dict[str, Any]:
    completed_at = datetime.now(timezone.utc)
    classification = classify_auth_required_endpoints(endpoint_rows, profile_summary)
    classified = classification["classified_endpoints"]
    summary = {
        "enabled": True,
        "crawl_id": crawl_id,
        "target_base_url": target_base_url,
        "profile_id": profile_summary.get("profile_id") or "",
        "profile_name": profile_summary.get("profile_name") or "",
        "role_label": profile_summary.get("role_label") or "",
        "started_at": started_at.isoformat(timespec="seconds"),
        "completed_at": completed_at.isoformat(timespec="seconds"),
        "max_pages": int(options.get("max_pages", 30)),
        "max_depth": int(options.get("max_depth", 2)),
        "request_delay_seconds": float(options.get("request_delay_seconds", options.get("request_delay", 1.0))),
        "requests_attempted": requests_attempted,
        "requests_completed": requests_completed,
        "pages_crawled": len(results),
        "links_discovered": links_discovered,
        "endpoints_discovered": len(classified),
        "auth_required_endpoints_count": sum(1 for item in classified if item.get("auth_required_likely")),
        "blocked_by_boundary_count": sum(1 for item in events if item.get("event_type") == "blocked_path"),
        "skipped_destructive_count": sum(1 for item in events if item.get("event_type") in {"destructive_path_skipped", "logout_path_skipped"}),
        "skipped_out_of_scope_count": sum(1 for item in events if item.get("event_type") in {"out_of_scope_skipped", "cross_host_skipped"}),
        "session_expiry_indicators_count": sum(1 for item in results if item.get("session_expiry_indicator")),
        "redaction_applied": True,
        "limitations": [
            "Authenticated Crawl uses GET-only requests and does not submit forms.",
            "Session Expiry Indicator evidence is classification only. Manual Validation Required.",
            "Auth material is used in memory only and redacted from stored evidence.",
        ],
    }
    return {
        "auth_context_summary": auth_context,
        "authenticated_crawl_summary": summary,
        "authenticated_crawl_results": classified,
        "authenticated_crawl_skipped": skipped,
        "authenticated_boundary_events": events,
        "auth_required_endpoint_classification": classification["auth_required_endpoint_classification"],
        "redaction_status": "redacted",
    }


def _placeholder_only(values: dict[str, Any]) -> bool:
    if not values:
        return True
    return all("[REDACTED" in str(value) for value in values.values())


def _skipped(url: str, decision: dict[str, Any], source: str) -> dict[str, Any]:
    return {"url": url, "reason": decision.get("reason") or "", "matched_rule": decision.get("matched_rule") or "", "source": source}


def _dry_run_row(url: str, depth: int, decision: dict[str, Any], request_context: dict[str, Any]) -> dict[str, Any]:
    return {
        "url": url,
        "normalised_url": url,
        "method": "GET",
        "status_code": 0,
        "content_type": "",
        "page_title": "",
        "title": "",
        "final_url": url,
        "redirect_chain": [],
        "response_time_ms": 0,
        "auth_context_used": bool(request_context.get("headers") or request_context.get("cookies")),
        "auth_required_likely": False,
        "session_expiry_indicator": False,
        "session_expiry_reason": "",
        "session_expiry_confidence": "Low",
        "boundary_status": decision.get("boundary_status") or "allowed",
        "boundary_reason": decision.get("reason") or "",
        "endpoint_category": "dry_run",
        "discovered_links_count": 0,
        "redacted_evidence_summary": "dry_run=True; no request sent",
        "source": "authenticated_crawl",
        "role_label": request_context.get("role_label") or "",
        "depth": depth,
    }


def _limited_text(response: Any, limit: int = 512 * 1024) -> str:
    text = str(getattr(response, "text", "") or "")
    return redact_secret_text(text[:limit])


def _is_html(response: Any) -> bool:
    return "html" in _content_type(response).lower()


def _content_type(response: Any) -> str:
    headers = getattr(response, "headers", {}) or {}
    return str(headers.get("Content-Type") or headers.get("content-type") or "")


def _title(soup: BeautifulSoup) -> str:
    title = soup.find("title")
    return redact_secret_text(" ".join(title.get_text(" ", strip=True).split()) if title else "")


def _safe_links(soup: BeautifulSoup, base_url: str) -> list[str]:
    links = []
    for anchor in soup.find_all("a"):
        href = str(anchor.get("href") or "").strip()
        if not href or href.lower().startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            continue
        links.append(urljoin(base_url, href))
    return links


def _form_metadata(soup: BeautifulSoup, page_url: str) -> list[dict[str, Any]]:
    forms = []
    for form in soup.find_all("form"):
        method = str(form.get("method") or "GET").upper()
        action = urljoin(page_url, str(form.get("action") or page_url))
        input_names = [redact_secret_text(str(item.get("name") or "")) for item in form.find_all(["input", "textarea", "select"]) if str(item.get("name") or "")]
        input_types = [str(item.get("type") or item.name or "").lower() for item in form.find_all(["input", "textarea", "select"])]
        category = "search_form_get_safe_candidate" if method == "GET" else "state_changing_form_skipped"
        if any(kind == "file" for kind in input_types):
            category = "upload_form_metadata_only"
        if any(kind == "password" for kind in input_types):
            category = "auth_form"
        forms.append({"action": action, "method": method, "input_names": input_names, "input_types": input_types, "form_category": category, "submitted": False})
    return forms


def _redirect_chain(response: Any) -> list[str]:
    history = list(getattr(response, "history", []) or [])
    urls = [str(getattr(item, "url", "") or "") for item in history if getattr(item, "url", "")]
    if getattr(response, "url", ""):
        urls.append(str(response.url))
    return [urlunsplit(urlsplit(url)) for url in urls if url]


def _endpoint_category(url: str, expiry: dict[str, Any]) -> str:
    path = (urlsplit(url).path or "").lower()
    if expiry.get("session_expiry_indicator"):
        return "auth_required_likely"
    if any(token in path for token in ("dashboard", "account", "profile", "settings", "orders", "billing")):
        return "authenticated_likely"
    return "unknown"
