"""Passive Web DAST security header checks."""

from __future__ import annotations

from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit

from scanner.finding import Finding, create_finding


SOURCE = "web_header_audit"
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]
LIMITATIONS = [
    "Header checks are passive configuration indicators.",
    "Version 13.1 does not submit forms, authenticate, test SQL injection, test XSS, fuzz, or send attack payloads.",
    "Missing headers should be reviewed in application context and do not prove exploitability.",
]


def audit_web_headers(pages: list[dict[str, Any]]) -> dict[str, Any]:
    """Check crawled page response headers without sending additional requests."""
    missing_header_urls: dict[str, list[str]] = defaultdict(list)
    disclosure_header_urls: dict[str, list[str]] = defaultdict(list)
    cookie_issue_urls: dict[str, list[str]] = defaultdict(list)
    page_results: list[dict[str, Any]] = []

    for page in pages:
        url = str(page.get("url") or "")
        headers = _normalize_headers(page.get("response_headers") or {})
        missing_headers = _missing_headers(url=url, headers=headers)
        disclosure_headers = [
            header for header in ("Server", "X-Powered-By") if header.lower() in headers
        ]
        cookie_issues = _cookie_issues(url=url, cookie_flags=page.get("cookie_flags") or [])

        for header in missing_headers:
            missing_header_urls[header].append(url)
        for header in disclosure_headers:
            disclosure_header_urls[header].append(url)
        for issue in cookie_issues:
            cookie_issue_urls[issue].append(url)

        page_results.append(
            {
                "url": url,
                "status_code": page.get("status_code"),
                "headers_checked": list(SECURITY_HEADERS),
                "missing_headers": missing_headers,
                "disclosure_headers": disclosure_headers,
                "cookie_issues": cookie_issues,
            }
        )

    findings = _build_header_findings(
        pages_checked=len(pages),
        missing_header_urls=missing_header_urls,
        disclosure_header_urls=disclosure_header_urls,
        cookie_issue_urls=cookie_issue_urls,
    )
    summary = {
        "enabled": True,
        "pages_checked": len(pages),
        "headers_checked": list(SECURITY_HEADERS),
        "missing_header_counts": {header: len(urls) for header, urls in missing_header_urls.items()},
        "disclosure_header_counts": {header: len(urls) for header, urls in disclosure_header_urls.items()},
        "cookie_issue_counts": {issue: len(urls) for issue, urls in cookie_issue_urls.items()},
        "cookie_issues_count": sum(len(urls) for urls in cookie_issue_urls.values()),
        "findings_count": len(findings),
        "limitations": list(LIMITATIONS),
    }
    return {
        "enabled": True,
        "source": SOURCE,
        "status": "success",
        "web_header_summary": summary,
        "web_header_results": page_results,
        "findings": findings,
    }


def _missing_headers(url: str, headers: dict[str, str]) -> list[str]:
    missing: list[str] = []
    if urlsplit(url).scheme == "https" and "strict-transport-security" not in headers:
        missing.append("Strict-Transport-Security")
    for header in SECURITY_HEADERS:
        if header == "Strict-Transport-Security":
            continue
        if header.lower() not in headers:
            missing.append(header)
    return missing


def _cookie_issues(url: str, cookie_flags: list[dict[str, bool]]) -> list[str]:
    issues: list[str] = []
    if not cookie_flags:
        return issues
    https = urlsplit(url).scheme == "https"
    if https and any(not cookie.get("secure") for cookie in cookie_flags):
        issues.append("Cookie Missing Secure Flag")
    if any(not cookie.get("httponly") for cookie in cookie_flags):
        issues.append("Cookie Missing HttpOnly Flag")
    if any(not cookie.get("samesite") for cookie in cookie_flags):
        issues.append("Cookie Missing SameSite Flag")
    return issues


def _build_header_findings(
    *,
    pages_checked: int,
    missing_header_urls: dict[str, list[str]],
    disclosure_header_urls: dict[str, list[str]],
    cookie_issue_urls: dict[str, list[str]],
) -> list[Finding]:
    findings: list[Finding] = []
    for header, urls in missing_header_urls.items():
        findings.append(_missing_header_finding(header=header, urls=urls, pages_checked=pages_checked))
    for header, urls in disclosure_header_urls.items():
        findings.append(_disclosure_finding(header=header, urls=urls, pages_checked=pages_checked))
    for issue, urls in cookie_issue_urls.items():
        findings.append(_cookie_finding(issue=issue, urls=urls, pages_checked=pages_checked))
    return findings


def _missing_header_finding(header: str, urls: list[str], pages_checked: int) -> Finding:
    sample_url = urls[0] if urls else ""
    affected_count = len(urls)
    definitions = {
        "Strict-Transport-Security": {
            "title": "Missing Strict-Transport-Security",
            "severity": "Medium",
            "evidence": "Strict-Transport-Security header was not present on HTTPS response.",
            "recommendation": "Add HSTS after confirming HTTPS is correctly configured.",
            "limitation": "HSTS should be deployed carefully to avoid availability issues.",
        },
        "Content-Security-Policy": {
            "title": "Missing Content-Security-Policy",
            "severity": "Medium",
            "evidence": "Content-Security-Policy header was not present.",
            "recommendation": "Add a CSP appropriate for the application.",
            "limitation": "Presence of CSP does not guarantee complete XSS protection.",
        },
        "X-Frame-Options": {
            "title": "Missing X-Frame-Options",
            "severity": "Low",
            "evidence": "X-Frame-Options header was not present.",
            "recommendation": "Add X-Frame-Options DENY or SAMEORIGIN, or use CSP frame-ancestors.",
            "limitation": "Some modern apps use CSP frame-ancestors instead.",
        },
        "X-Content-Type-Options": {
            "title": "Missing X-Content-Type-Options",
            "severity": "Low",
            "evidence": "X-Content-Type-Options header was not present.",
            "recommendation": "Add X-Content-Type-Options: nosniff.",
            "limitation": "Header presence should be verified across relevant responses.",
        },
        "Referrer-Policy": {
            "title": "Missing Referrer-Policy",
            "severity": "Low",
            "evidence": "Referrer-Policy header was not present.",
            "recommendation": "Add a suitable Referrer-Policy such as strict-origin-when-cross-origin.",
            "limitation": "Policy choice depends on application requirements.",
        },
        "Permissions-Policy": {
            "title": "Missing Permissions-Policy",
            "severity": "Informational",
            "evidence": "Permissions-Policy header was not present.",
            "recommendation": "Add Permissions-Policy to limit browser features where appropriate.",
            "limitation": "Policy should be tailored to required features.",
        },
    }
    definition = definitions[header]
    evidence = f"{definition['evidence']} Affected pages: {affected_count} of {pages_checked}. Sample URL: {sample_url}."
    return create_finding(
        title=str(definition["title"]),
        severity=definition["severity"],  # type: ignore[arg-type]
        category="Web Security Headers",
        affected_url=sample_url,
        service="http",
        evidence=evidence,
        confidence="High",
        impact="Missing browser security headers can reduce client-side protection in supported browsers.",
        recommendation=str(definition["recommendation"]),
        verification=f"Review response headers for {header}.",
        limitation=str(definition["limitation"]),
        source=SOURCE,
        evidence_details={"affected_urls_count": affected_count, "sample_affected_url": sample_url},
    )


def _disclosure_finding(header: str, urls: list[str], pages_checked: int) -> Finding:
    sample_url = urls[0] if urls else ""
    affected_count = len(urls)
    title = "Server Header Disclosure" if header == "Server" else "X-Powered-By Header Disclosure"
    severity = "Informational" if header == "Server" else "Low"
    recommendation = (
        "Minimise verbose server banners where possible."
        if header == "Server"
        else "Remove or minimise framework disclosure headers."
    )
    evidence = f"{header} header was present. Affected pages: {affected_count} of {pages_checked}. Sample URL: {sample_url}."
    return create_finding(
        title=title,
        severity=severity,  # type: ignore[arg-type]
        category="Information Disclosure",
        affected_url=sample_url,
        service="http",
        evidence=evidence,
        confidence="High",
        impact="Technology disclosure can help attackers fingerprint the application stack.",
        recommendation=recommendation,
        verification=f"Review response headers for {header}.",
        limitation="Header removal alone does not secure the server."
        if header == "Server"
        else "Header removal alone does not remove underlying vulnerabilities.",
        source=SOURCE,
        evidence_details={"affected_urls_count": affected_count, "sample_affected_url": sample_url},
    )


def _cookie_finding(issue: str, urls: list[str], pages_checked: int) -> Finding:
    sample_url = urls[0] if urls else ""
    affected_count = len(urls)
    definitions = {
        "Cookie Missing Secure Flag": {
            "severity": "Medium",
            "evidence": "Set-Cookie header lacked Secure flag.",
            "recommendation": "Add Secure flag to cookies sent over HTTPS.",
            "limitation": "Cookie security should be reviewed per cookie purpose.",
        },
        "Cookie Missing HttpOnly Flag": {
            "severity": "Medium",
            "evidence": "Set-Cookie header lacked HttpOnly flag.",
            "recommendation": "Add HttpOnly to session or sensitive cookies.",
            "limitation": "Some cookies may need JavaScript access.",
        },
        "Cookie Missing SameSite Flag": {
            "severity": "Low",
            "evidence": "Set-Cookie header lacked SameSite flag.",
            "recommendation": "Add SameSite=Lax or SameSite=Strict where appropriate.",
            "limitation": "SameSite=None may be required for cross-site flows and must use Secure.",
        },
    }
    definition = definitions[issue]
    evidence = f"{definition['evidence']} Affected pages: {affected_count} of {pages_checked}. Sample URL: {sample_url}."
    return create_finding(
        title=issue,
        severity=definition["severity"],  # type: ignore[arg-type]
        category="Cookie Security",
        affected_url=sample_url,
        service="http",
        evidence=evidence,
        confidence="High",
        impact="Cookie flags help reduce transport, script access, and cross-site request risks.",
        recommendation=str(definition["recommendation"]),
        verification="Review Set-Cookie attributes for the affected response.",
        limitation=str(definition["limitation"]),
        source=SOURCE,
        evidence_details={"affected_urls_count": affected_count, "sample_affected_url": sample_url},
    )


def _normalize_headers(headers: dict[str, Any]) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in headers.items()}
