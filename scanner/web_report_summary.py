"""Consolidated passive Web DAST reporting helpers."""

from __future__ import annotations

from typing import Any

from scanner.finding import Finding, create_finding, finding_to_dict
from scanner.risk_score import apply_risk_scores
from scanner.web_passive_summary import build_passive_risk_rating


SOURCE = "web_passive_summary"
WEB_SOURCES = {
    "web_scope",
    "web_rate_limit",
    "web_robots",
    "web_sitemap",
    "web_crawler",
    "web_header_audit",
    "web_cookie_audit",
    "web_form_audit",
    "web_passive_summary",
}
LIMITATIONS = [
    "Passive Web DAST does not prove exploitability.",
    "Passive Web DAST does not submit forms, authenticate, send payloads, fuzz, test SQL injection, or test XSS.",
    "Written authorisation and configured scope remain the source of truth for any further testing.",
]


def get_web_findings(findings: list[Finding | dict[str, Any]]) -> list[dict[str, Any]]:
    """Return only web-related findings."""
    web_findings: list[dict[str, Any]] = []
    for finding in findings or []:
        item = finding_to_dict(finding)
        if str(item.get("source") or "") in WEB_SOURCES:
            web_findings.append(item)
    return web_findings


def group_web_findings_by_source(findings: list[Finding | dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group web findings by source."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for finding in get_web_findings(findings):
        grouped.setdefault(str(finding.get("source") or "unknown"), []).append(finding)
    return grouped


def group_web_findings_by_category(findings: list[Finding | dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group web findings by category."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for finding in get_web_findings(findings):
        grouped.setdefault(str(finding.get("category") or "Uncategorised"), []).append(finding)
    return grouped


def count_web_findings_by_severity(findings: list[Finding | dict[str, Any]]) -> dict[str, int]:
    """Count web findings by severity."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for finding in get_web_findings(findings):
        severity = str(finding.get("severity") or "Informational")
        if severity in counts:
            counts[severity] += 1
    return counts


def get_highest_web_risk(findings: list[Finding | dict[str, Any]]) -> dict[str, Any]:
    """Return highest scored web finding metadata."""
    scored = get_web_findings(apply_risk_scores(get_web_findings(findings)))
    highest = max(scored, key=lambda item: int(item.get("risk_score") or 0), default={})
    return {
        "score": int(highest.get("risk_score") or 0),
        "label": str(highest.get("risk_label") or "Informational"),
        "title": str(highest.get("title") or ""),
    }


def build_web_dast_sections(
    *,
    web_scope_summary: dict[str, Any] | None = None,
    web_politeness_summary: dict[str, Any] | None = None,
    web_robots_summary: dict[str, Any] | None = None,
    web_sitemap_summary: dict[str, Any] | None = None,
    web_scan_summary: dict[str, Any] | None = None,
    web_header_summary: dict[str, Any] | None = None,
    web_cookie_summary: dict[str, Any] | None = None,
    web_form_summary: dict[str, Any] | None = None,
    web_passive_summary: dict[str, Any] | None = None,
    findings: list[Finding | dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Build section status rows for passive Web DAST modules."""
    findings = findings or []
    return [
        _section(
            section_id="web_scope",
            section_name="Web DAST Scope",
            source="web_scope",
            summary=web_scope_summary,
            key_metrics={
                "same_host_only": _get(web_scope_summary, "same_host_only"),
                "allowed_hosts": _get(web_scope_summary, "allowed_hosts", []),
                "denied_hosts": _get(web_scope_summary, "denied_hosts", []),
                "total_skipped_urls": _int(web_scope_summary, "total_skipped_urls"),
            },
            findings=findings,
        ),
        _section(
            section_id="web_politeness",
            section_name="Web DAST Politeness",
            source="web_rate_limit",
            summary=web_politeness_summary,
            key_metrics={
                "request_delay_seconds": _get(web_politeness_summary, "request_delay_seconds"),
                "max_requests_per_minute": _get(web_politeness_summary, "max_requests_per_minute"),
                "total_requests": _int(web_politeness_summary, "total_requests"),
                "request_errors": _int(web_politeness_summary, "request_errors"),
            },
            findings=findings,
        ),
        _section(
            section_id="web_robots",
            section_name="Robots.txt Awareness",
            source="web_robots",
            summary=web_robots_summary,
            key_metrics={
                "robots_found": _unknown_bool(web_robots_summary, "robots_found"),
                "respect_robots": _get(web_robots_summary, "respect_robots"),
                "disallow_rules": _int(web_robots_summary, "disallow_rules_count"),
                "skipped_by_robots": _int(web_robots_summary, "urls_skipped_by_robots"),
            },
            findings=findings,
        ),
        _section(
            section_id="web_sitemap",
            section_name="Web Sitemap Discovery",
            source="web_sitemap",
            summary=web_sitemap_summary,
            key_metrics={
                "sitemaps_fetched": _int(web_sitemap_summary, "sitemap_urls_fetched"),
                "url_entries_found": _int(web_sitemap_summary, "url_entries_found"),
                "in_scope_urls": _int(web_sitemap_summary, "in_scope_urls"),
                "urls_added_to_crawl": _int(web_sitemap_summary, "urls_added_to_crawl"),
            },
            findings=findings,
        ),
        _section(
            section_id="web_crawler",
            section_name="Web Crawler",
            source="web_crawler",
            summary=web_scan_summary,
            key_metrics={
                "pages_crawled": _int(web_scan_summary, "pages_crawled"),
                "errors": _int(web_scan_summary, "errors_count"),
                "forms_found": _int(web_scan_summary, "forms_discovered"),
                "external_links": _int(web_scan_summary, "unique_external_links"),
            },
            findings=findings,
            duration_key="duration_seconds",
        ),
        _section(
            section_id="web_headers",
            section_name="Web Header Audit",
            source="web_header_audit",
            summary=web_header_summary,
            key_metrics={
                "pages_checked": _int(web_header_summary, "pages_checked"),
                "missing_headers": _sum_mapping(web_header_summary, "missing_header_counts"),
                "disclosure_headers": _sum_mapping(web_header_summary, "disclosure_header_counts"),
                "cookie_issues": _int(web_header_summary, "cookie_issues_count"),
            },
            findings=findings,
        ),
        _section(
            section_id="web_cookies",
            section_name="Web Cookie Audit",
            source="web_cookie_audit",
            summary=web_cookie_summary,
            key_metrics={
                "cookies_observed": _int(web_cookie_summary, "cookies_observed"),
                "unique_cookie_names": _int(web_cookie_summary, "unique_cookie_names"),
                "missing_secure": _int(web_cookie_summary, "cookies_missing_secure"),
                "missing_samesite": _int(web_cookie_summary, "cookies_missing_samesite"),
            },
            findings=findings,
        ),
        _section(
            section_id="web_forms",
            section_name="Web Form Discovery",
            source="web_form_audit",
            summary=web_form_summary,
            key_metrics={
                "forms_discovered": _int(web_form_summary, "forms_discovered"),
                "login_forms": _int(web_form_summary, "login_forms"),
                "upload_forms": _int(web_form_summary, "upload_forms"),
                "http_submission_risk": _int(web_form_summary, "http_submission_risk"),
            },
            findings=findings,
        ),
        _section(
            section_id="web_passive_summary",
            section_name="Web Passive Risk Summary",
            source="web_passive_summary",
            summary=web_passive_summary,
            key_metrics={
                "passive_risk_rating": _get(web_passive_summary, "passive_risk_rating", "None"),
                "total_web_findings": _int(web_passive_summary, "total_web_findings"),
                "highest_web_risk_score": _int(web_passive_summary, "highest_web_risk_score"),
            },
            findings=findings,
        ),
    ]


def build_web_dast_summary(
    *,
    start_url: str,
    web_dast_sections: list[dict[str, Any]],
    web_scope_summary: dict[str, Any] | None = None,
    web_politeness_summary: dict[str, Any] | None = None,
    web_robots_summary: dict[str, Any] | None = None,
    web_sitemap_summary: dict[str, Any] | None = None,
    web_scan_summary: dict[str, Any] | None = None,
    web_header_summary: dict[str, Any] | None = None,
    web_cookie_summary: dict[str, Any] | None = None,
    web_form_summary: dict[str, Any] | None = None,
    web_passive_summary: dict[str, Any] | None = None,
    findings: list[Finding | dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the consolidated passive Web DAST report summary."""
    findings = findings or []
    web_findings = get_web_findings(findings)
    highest = get_highest_web_risk(findings)
    enabled_sections = [section["section_id"] for section in web_dast_sections if section["enabled"]]
    completed_sections = [section["section_id"] for section in web_dast_sections if section["status"] == "success"]
    partial_sections = [section["section_id"] for section in web_dast_sections if section["status"] == "partial"]
    failed_sections = [section["section_id"] for section in web_dast_sections if section["status"] == "failed"]
    summary = {
        "enabled": True,
        "mode": "passive",
        "start_url": start_url,
        "normalized_start_url": str(_get(web_scan_summary, "normalized_start_url", start_url)),
        "allowed_host": str(_get(web_scan_summary, "allowed_host", _get(web_scope_summary, "start_host", ""))),
        "scan_profile": "passive",
        "sections_enabled": enabled_sections,
        "sections_completed": completed_sections,
        "sections_partial": partial_sections,
        "sections_failed": failed_sections,
        "total_duration_seconds": _float(web_scan_summary, "duration_seconds"),
        "total_requests": _int(web_politeness_summary, "total_requests"),
        "pages_crawled": _int(web_scan_summary, "pages_crawled"),
        "forms_discovered": _int(web_scan_summary, "forms_discovered") or _int(web_form_summary, "forms_discovered"),
        "cookies_observed": _int(web_cookie_summary, "cookies_observed"),
        "sitemap_urls_found": _int(web_sitemap_summary, "url_entries_found"),
        "robots_found": _unknown_bool(web_robots_summary, "robots_found"),
        "total_web_findings": len(web_findings),
        "highest_web_risk_score": highest["score"],
        "highest_web_risk_label": highest["label"],
        "passive_risk_rating": str(
            _get(web_passive_summary, "passive_risk_rating", build_passive_risk_rating(findings))
        ),
        "recommended_next_steps": [],
        "limitations": list(LIMITATIONS),
    }
    summary["recommended_next_steps"] = build_web_recommended_next_steps(
        summary=summary,
        web_scope_summary=web_scope_summary,
        web_politeness_summary=web_politeness_summary,
        web_robots_summary=web_robots_summary,
        web_sitemap_summary=web_sitemap_summary,
        web_header_summary=web_header_summary,
        web_cookie_summary=web_cookie_summary,
        web_form_summary=web_form_summary,
    )
    return summary


def build_web_recommended_next_steps(
    *,
    summary: dict[str, Any] | None = None,
    web_scope_summary: dict[str, Any] | None = None,
    web_politeness_summary: dict[str, Any] | None = None,
    web_robots_summary: dict[str, Any] | None = None,
    web_sitemap_summary: dict[str, Any] | None = None,
    web_header_summary: dict[str, Any] | None = None,
    web_cookie_summary: dict[str, Any] | None = None,
    web_form_summary: dict[str, Any] | None = None,
) -> list[str]:
    """Build concise next steps from passive web summaries."""
    steps: list[str] = []
    if _sum_mapping(web_header_summary, "missing_header_counts"):
        steps.append("Review and implement missing security headers.")
    if _cookie_issue_count(web_cookie_summary):
        steps.append("Review cookie flags for sensitive/session cookies.")
    if _int(web_form_summary, "login_forms"):
        steps.append("Verify HTTPS, CSRF protections, and anti-automation controls for login forms.")
    if _int(web_form_summary, "upload_forms"):
        steps.append("Review upload validation and storage controls.")
    if _int(web_robots_summary, "urls_skipped_by_robots") or _int(web_scope_summary, "skipped_by_robots_count"):
        steps.append("Confirm written authorisation before testing robots-disallowed areas.")
    if _int(web_sitemap_summary, "out_of_scope_urls"):
        steps.append("Review scope before including additional sitemap hosts or paths.")
    if _int(web_politeness_summary, "request_errors") or _get(web_politeness_summary, "max_errors_reached"):
        steps.append("Review target availability and reduce scan speed if needed.")
    if str((summary or {}).get("passive_risk_rating") or "") == "High":
        steps.append("Manually review high-priority web findings before active testing.")
    if not steps:
        steps.append("Continue with authorised deeper testing if in scope.")
    return list(dict.fromkeys(steps))[:8]


def build_web_report_consolidation_finding(
    existing_findings: list[Finding | dict[str, Any]] | None = None,
) -> list[Finding]:
    """Create one duplicate-safe finding for report consolidation."""
    existing_titles = {
        str(finding_to_dict(finding).get("title") or "")
        for finding in existing_findings or []
        if str(finding_to_dict(finding).get("source") or "") == SOURCE
    }
    if "Web DAST Passive Report Consolidated" in existing_titles:
        return []
    return [
        create_finding(
            title="Web DAST Passive Report Consolidated",
            severity="Informational",
            category="Web DAST",
            evidence=(
                "Passive Web DAST report consolidated crawler, scope, robots, sitemap, "
                "headers, cookies, forms, and risk summary."
            ),
            confidence="High",
            impact="The consolidated report helps review passive web coverage and prioritise next steps.",
            recommendation=(
                "Use the consolidated report to review scope and prioritise authorised next testing steps."
            ),
            verification="Review the Web DAST Passive Report section.",
            limitation="Passive Web DAST does not prove exploitability and does not submit forms or payloads.",
            source=SOURCE,
            service="http",
        )
    ]


def _section(
    *,
    section_id: str,
    section_name: str,
    source: str,
    summary: dict[str, Any] | None,
    key_metrics: dict[str, Any],
    findings: list[Finding | dict[str, Any]],
    duration_key: str = "duration_seconds",
) -> dict[str, Any]:
    enabled = bool((summary or {}).get("enabled"))
    status = _status(summary)
    return {
        "section_id": section_id,
        "section_name": section_name,
        "source": source,
        "status": status,
        "enabled": enabled,
        "key_metrics": key_metrics,
        "findings_count": len([finding for finding in get_web_findings(findings) if finding.get("source") == source]),
        "duration_seconds": _float(summary, duration_key),
        "limitations": list((summary or {}).get("limitations") or (summary or {}).get("robots_limitations") or []),
    }


def _status(summary: dict[str, Any] | None) -> str:
    if not (summary or {}).get("enabled"):
        return "skipped"
    raw_status = str((summary or {}).get("status") or "").lower()
    if raw_status in {"success", "partial", "failed", "skipped"}:
        return raw_status
    if _int(summary, "errors_count") or _int(summary, "sitemap_urls_failed") or _get(summary, "max_errors_reached"):
        return "partial"
    return "success"


def _get(summary: dict[str, Any] | None, key: str, default: Any = None) -> Any:
    return (summary or {}).get(key, default)


def _int(summary: dict[str, Any] | None, key: str) -> int:
    try:
        return int((summary or {}).get(key) or 0)
    except (TypeError, ValueError):
        return 0


def _float(summary: dict[str, Any] | None, key: str) -> float:
    try:
        return round(float((summary or {}).get(key) or 0.0), 3)
    except (TypeError, ValueError):
        return 0.0


def _sum_mapping(summary: dict[str, Any] | None, key: str) -> int:
    value = (summary or {}).get(key) or {}
    if not isinstance(value, dict):
        return 0
    return sum(int(item or 0) for item in value.values())


def _cookie_issue_count(summary: dict[str, Any] | None) -> int:
    return (
        _int(summary, "cookies_missing_secure")
        + _int(summary, "cookies_missing_httponly")
        + _int(summary, "cookies_missing_samesite")
        + _int(summary, "samesite_none_without_secure")
        + _int(summary, "persistent_cookie_issues")
    )


def _unknown_bool(summary: dict[str, Any] | None, key: str) -> bool | str:
    if not (summary or {}).get("enabled"):
        return "unknown"
    return bool((summary or {}).get(key))
