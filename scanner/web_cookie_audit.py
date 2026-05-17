"""Passive Web DAST cookie attribute audit."""

from __future__ import annotations

from collections import defaultdict
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import urlsplit

from scanner.evidence import safe_truncate
from scanner.finding import Finding, create_finding


SOURCE = "web_cookie_audit"
LIMITATIONS = [
    "Cookie audit checks attributes only and never stores cookie values.",
    "Version 13.2 does not log in, submit forms, test authenticated session handling, fuzz, test SQL injection, or test XSS.",
    "Cookie findings are indicators and should be reviewed in application context.",
]


def parse_set_cookie_headers(cookie_headers: list[str], source_url: str) -> list[dict[str, Any]]:
    """Parse Set-Cookie headers into value-free cookie attribute records."""
    cookies: list[dict[str, Any]] = []
    is_https = urlsplit(source_url).scheme == "https"
    for header in cookie_headers:
        parsed = SimpleCookie()
        try:
            parsed.load(str(header))
        except Exception:
            continue
        for name, morsel in parsed.items():
            expires = str(morsel["expires"] or "")
            max_age = str(morsel["max-age"] or "")
            cookie = {
                "name": safe_truncate(name, max_chars=80),
                "domain": safe_truncate(morsel["domain"] or "", max_chars=120),
                "path": safe_truncate(morsel["path"] or "", max_chars=120),
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": safe_truncate(morsel["samesite"] or "", max_chars=40),
                "expires": safe_truncate(expires, max_chars=120),
                "max_age": safe_truncate(max_age, max_chars=40),
                "expires_present": bool(expires),
                "max_age_present": bool(max_age),
                "is_session_cookie": not bool(expires or max_age),
                "source_url": source_url,
                "is_https_context": is_https,
            }
            cookie["issues"] = _cookie_issues(cookie)
            cookies.append(cookie)
    return cookies


def audit_web_cookies(pages: list[dict[str, Any]]) -> dict[str, Any]:
    """Audit parsed cookie attributes without storing or printing cookie values."""
    cookies: list[dict[str, Any]] = []
    pages_with_cookies: set[str] = set()
    for page in pages:
        source_url = str(page.get("url") or "")
        page_cookies = list(page.get("cookies") or [])
        if page_cookies:
            pages_with_cookies.add(source_url)
        for cookie in page_cookies:
            sanitized = _result_cookie(cookie)
            sanitized["issues"] = _cookie_issues(sanitized)
            cookies.append(sanitized)

    issue_groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for cookie in cookies:
        parsed_url = urlsplit(str(cookie.get("source_url") or ""))
        host = parsed_url.netloc.lower()
        scheme = parsed_url.scheme.lower()
        for issue in cookie.get("issues") or []:
            issue_groups[(str(cookie.get("name") or ""), str(issue), host, scheme)].append(cookie)

    findings = _build_cookie_findings(issue_groups=issue_groups)
    findings.append(
        create_finding(
            title="Cookie Audit Completed",
            severity="Informational",
            category="Cookie Security",
            evidence=f"Cookie audit reviewed {len(cookies)} cookies across {len(pages_with_cookies)} pages.",
            confidence="High",
            impact="Cookie attribute review supports session management hardening.",
            recommendation="Review cookie flags in context of application authentication and session management.",
            verification="Review the Web Cookie Audit report.",
            limitation="VulScan does not log in or test authenticated session handling in Version 13.2.",
            source=SOURCE,
        )
    )
    summary = {
        "enabled": True,
        "pages_checked": len(pages),
        "cookies_observed": len(cookies),
        "unique_cookie_names": len({str(cookie.get("name") or "") for cookie in cookies}),
        "cookies_missing_secure": _issue_count(cookies, "Cookie Missing Secure Flag"),
        "cookies_missing_httponly": _issue_count(cookies, "Cookie Missing HttpOnly Flag"),
        "cookies_missing_samesite": _issue_count(cookies, "Cookie Missing SameSite Attribute"),
        "samesite_none_without_secure": _issue_count(cookies, "Cookie SameSite=None Without Secure"),
        "persistent_cookie_issues": _issue_count(cookies, "Persistent Cookie Without Security Flags"),
        "findings_count": len(findings),
        "limitations": list(LIMITATIONS),
    }
    return {
        "enabled": True,
        "source": SOURCE,
        "status": "success",
        "web_cookie_summary": summary,
        "web_cookie_results": cookies,
        "findings": findings,
    }


def _cookie_issues(cookie: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    secure = bool(cookie.get("secure"))
    httponly = bool(cookie.get("httponly"))
    samesite = str(cookie.get("samesite") or "")
    persistent = bool(cookie.get("expires_present") or cookie.get("max_age_present"))
    if not secure:
        issues.append("Cookie Missing Secure Flag")
    if not httponly:
        issues.append("Cookie Missing HttpOnly Flag")
    if not samesite:
        issues.append("Cookie Missing SameSite Attribute")
    if samesite.lower() == "none" and not secure:
        issues.append("Cookie SameSite=None Without Secure")
    if persistent and (not secure or not httponly or not samesite):
        issues.append("Persistent Cookie Without Security Flags")
    return issues


def _build_cookie_findings(
    *,
    issue_groups: dict[tuple[str, str, str, str], list[dict[str, Any]]],
) -> list[Finding]:
    findings: list[Finding] = []
    for (cookie_name, issue, _host, scheme), affected in issue_groups.items():
        sample_url = str(affected[0].get("source_url") or "")
        affected_count = len({str(cookie.get("source_url") or "") for cookie in affected})
        findings.append(
            _cookie_issue_finding(
                issue=issue,
                cookie_name=cookie_name,
                scheme=scheme,
                affected_count=affected_count,
                sample_url=sample_url,
            )
        )
    return findings


def _cookie_issue_finding(
    *,
    issue: str,
    cookie_name: str,
    scheme: str,
    affected_count: int,
    sample_url: str,
) -> Finding:
    definitions = {
        "Cookie Missing Secure Flag": {
            "severity": "Medium" if scheme == "https" else "Low",
            "evidence": f"Cookie {cookie_name} missing Secure on {affected_count} pages. Sample URL: {sample_url}.",
            "recommendation": "Add Secure flag to cookies used over HTTPS.",
            "limitation": "Some non-sensitive cookies may not require Secure, but session cookies should use it.",
        },
        "Cookie Missing HttpOnly Flag": {
            "severity": "Medium",
            "evidence": f"Cookie {cookie_name} missing HttpOnly on {affected_count} pages. Sample URL: {sample_url}.",
            "recommendation": "Add HttpOnly to session or sensitive cookies.",
            "limitation": "Some cookies intentionally require JavaScript access.",
        },
        "Cookie Missing SameSite Attribute": {
            "severity": "Low",
            "evidence": f"Cookie {cookie_name} missing SameSite on {affected_count} pages. Sample URL: {sample_url}.",
            "recommendation": "Add SameSite=Lax or SameSite=Strict where appropriate.",
            "limitation": "SameSite=None may be needed for cross-site flows and must be paired with Secure.",
        },
        "Cookie SameSite=None Without Secure": {
            "severity": "Medium",
            "evidence": f"Cookie {cookie_name} uses SameSite=None without Secure on {affected_count} pages. Sample URL: {sample_url}.",
            "recommendation": "Add Secure flag when SameSite=None is used.",
            "limitation": "Browser behaviour may vary, but modern browsers require Secure for SameSite=None.",
        },
        "Persistent Cookie Without Security Flags": {
            "severity": "Medium",
            "evidence": f"Persistent cookie {cookie_name} has Expires or Max-Age but lacks one or more recommended security flags. Affected pages: {affected_count}. Sample URL: {sample_url}.",
            "recommendation": "Review whether the persistent cookie is sensitive and apply Secure, HttpOnly, and SameSite as appropriate.",
            "limitation": "Persistence alone is not a vulnerability.",
        },
    }
    definition = definitions[issue]
    return create_finding(
        title=issue,
        severity=definition["severity"],  # type: ignore[arg-type]
        category="Cookie Security",
        affected_url=sample_url,
        service="http",
        evidence=str(definition["evidence"]),
        confidence="High",
        impact="Cookie attributes help reduce transport, script access, cross-site request, and persistence risks.",
        recommendation=str(definition["recommendation"]),
        verification="Review Set-Cookie attributes for the affected response.",
        limitation=str(definition["limitation"]),
        source=SOURCE,
        evidence_details={"affected_urls_count": affected_count, "sample_affected_url": sample_url},
    )


def _result_cookie(cookie: dict[str, Any]) -> dict[str, Any]:
    return {
        "cookie_name": safe_truncate(cookie.get("cookie_name") or cookie.get("name") or "", max_chars=80),
        "name": safe_truncate(cookie.get("name") or cookie.get("cookie_name") or "", max_chars=80),
        "source_url": str(cookie.get("source_url") or ""),
        "secure": bool(cookie.get("secure")),
        "httponly": bool(cookie.get("httponly")),
        "samesite": safe_truncate(cookie.get("samesite") or "", max_chars=40),
        "path": safe_truncate(cookie.get("path") or "", max_chars=120),
        "domain": safe_truncate(cookie.get("domain") or "", max_chars=120),
        "expires": safe_truncate(cookie.get("expires") or "", max_chars=120),
        "max_age": safe_truncate(cookie.get("max_age") or "", max_chars=40),
        "expires_present": bool(cookie.get("expires_present")),
        "max_age_present": bool(cookie.get("max_age_present")),
        "is_session_cookie": bool(cookie.get("is_session_cookie")),
        "is_https_context": bool(cookie.get("is_https_context")),
    }


def _issue_count(cookies: list[dict[str, Any]], issue: str) -> int:
    return sum(1 for cookie in cookies if issue in (cookie.get("issues") or []))
