"""Consolidated passive Web DAST risk summary."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from scanner.finding import Finding, create_finding, finding_to_dict
from scanner.risk_score import apply_risk_scores


SOURCE = "web_passive_summary"
WEB_SOURCES = {
    "web_crawler",
    "web_header_audit",
    "web_cookie_audit",
    "web_form_audit",
    SOURCE,
}
SUMMARY_LIMITATIONS = [
    "Passive summary does not test exploitability or submit forms.",
    "Passive summary does not authenticate, fuzz, send payloads, test SQL injection, or test XSS.",
    "Results are indicators for authorised manual review and deeper testing where in scope.",
]


def get_web_findings(findings: list[Finding | dict[str, Any]]) -> list[dict[str, Any]]:
    """Return findings from web-related sources."""
    return [
        finding_to_dict(finding)
        for finding in findings
        if str(finding_to_dict(finding).get("source") or "") in WEB_SOURCES
    ]


def count_web_findings_by_severity(findings: list[Finding | dict[str, Any]]) -> dict[str, int]:
    """Count web findings by standard severity."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for finding in get_web_findings(findings):
        severity = str(finding.get("severity") or "Informational")
        if severity in counts:
            counts[severity] += 1
    return counts


def get_highest_web_risk(findings: list[Finding | dict[str, Any]]) -> dict[str, Any]:
    """Return highest scored web finding metadata."""
    web_findings = get_web_findings(apply_risk_scores(get_web_findings(findings)))
    highest = max(web_findings, key=lambda item: int(item.get("risk_score") or 0), default={})
    return {
        "score": int(highest.get("risk_score") or 0),
        "label": str(highest.get("risk_label") or "Informational"),
        "severity": str(highest.get("severity") or "Informational") if highest else "None",
        "title": str(highest.get("title") or ""),
    }


def build_passive_risk_rating(findings: list[Finding | dict[str, Any]]) -> str:
    """Build the passive web risk rating from web finding severities."""
    counts = count_web_findings_by_severity(findings)
    if counts["Critical"] or counts["High"]:
        return "High"
    if counts["Medium"]:
        return "Medium"
    if counts["Low"]:
        return "Low"
    if counts["Informational"]:
        return "Informational"
    return "None"


def build_recommended_next_steps(summary: dict[str, Any]) -> list[str]:
    """Build concise de-duplicated next steps from passive summary indicators."""
    steps: list[str] = []
    if int(summary.get("missing_security_headers") or 0):
        steps.append("Review and implement missing security headers.")
    if int(summary.get("cookie_issues") or 0):
        steps.append("Review cookie flags for session and sensitive cookies.")
    if int(summary.get("login_forms") or 0):
        steps.append("Verify login forms use HTTPS and anti-automation controls.")
    if int(summary.get("upload_forms") or 0):
        steps.append("Review file upload validation and storage controls.")
    if int(summary.get("external_form_actions") or 0):
        steps.append("Review third-party form submission destinations.")
    if not steps:
        steps.append("Continue with authorised deeper testing if in scope.")
    return list(dict.fromkeys(steps))


def build_web_passive_summary(
    *,
    start_url: str,
    web_scan_summary: dict[str, Any] | None = None,
    web_header_summary: dict[str, Any] | None = None,
    web_cookie_summary: dict[str, Any] | None = None,
    web_form_summary: dict[str, Any] | None = None,
    findings: list[Finding | dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a consolidated passive summary from available web module output."""
    web_scan_summary = web_scan_summary or {}
    web_header_summary = web_header_summary or {}
    web_cookie_summary = web_cookie_summary or {}
    web_form_summary = web_form_summary or {}
    findings = findings or []
    highest = get_highest_web_risk(findings)

    missing_headers = sum(int(value or 0) for value in (web_header_summary.get("missing_header_counts") or {}).values())
    disclosure_headers = sum(int(value or 0) for value in (web_header_summary.get("disclosure_header_counts") or {}).values())
    cookie_issues = (
        int(web_cookie_summary.get("cookies_missing_secure") or 0)
        + int(web_cookie_summary.get("cookies_missing_httponly") or 0)
        + int(web_cookie_summary.get("cookies_missing_samesite") or 0)
        + int(web_cookie_summary.get("samesite_none_without_secure") or 0)
        + int(web_cookie_summary.get("persistent_cookie_issues") or 0)
    )
    allowed_host = str(web_scan_summary.get("allowed_host") or urlsplit(start_url).netloc.lower())
    severity_counts = count_web_findings_by_severity(findings)
    summary = {
        "enabled": True,
        "start_url": start_url,
        "allowed_host": allowed_host,
        "pages_crawled": int(web_scan_summary.get("pages_crawled") or 0),
        "pages_with_errors": int(web_scan_summary.get("errors_count") or 0),
        "forms_discovered": int(web_form_summary.get("forms_discovered") or web_scan_summary.get("forms_discovered") or 0),
        "login_forms": int(web_form_summary.get("login_forms") or web_scan_summary.get("password_forms_discovered") or 0),
        "upload_forms": int(web_form_summary.get("upload_forms") or web_scan_summary.get("file_upload_forms_discovered") or 0),
        "cookies_observed": int(web_cookie_summary.get("cookies_observed") or 0),
        "cookie_issues": cookie_issues,
        "missing_security_headers": missing_headers,
        "disclosure_headers": disclosure_headers,
        "external_links": int(web_scan_summary.get("unique_external_links") or 0),
        "external_form_actions": int(web_form_summary.get("external_form_actions") or 0),
        "high_risk_indicators": _indicator_titles(findings, {"Critical", "High"}),
        "medium_risk_indicators": _indicator_titles(findings, {"Medium"}),
        "low_risk_indicators": _indicator_titles(findings, {"Low"}),
        "informational_indicators": _indicator_titles(findings, {"Informational"}),
        "severity_counts": severity_counts,
        "total_web_findings": len(get_web_findings(findings)),
        "highest_web_risk_score": highest["score"],
        "highest_web_risk_label": highest["label"],
        "passive_risk_rating": build_passive_risk_rating(findings),
        "recommended_next_steps": [],
        "limitations": list(SUMMARY_LIMITATIONS),
        "source_references": ["web_crawler", "web_header_audit", "web_cookie_audit", "web_form_audit"],
    }
    summary["recommended_next_steps"] = build_recommended_next_steps(summary)
    return summary


def build_web_passive_summary_findings(
    summary: dict[str, Any],
    existing_findings: list[Finding | dict[str, Any]] | None = None,
) -> list[Finding]:
    """Create duplicate-safe standard findings for the passive summary."""
    existing_titles = {
        str(finding_to_dict(finding).get("title") or "")
        for finding in existing_findings or []
        if str(finding_to_dict(finding).get("source") or "") == SOURCE
    }
    findings: list[Finding] = []
    if "Web Passive Risk Summary Completed" not in existing_titles:
        findings.append(
            create_finding(
                title="Web Passive Risk Summary Completed",
                severity="Informational",
                category="Web DAST",
                affected_url=str(summary.get("start_url") or ""),
                service="http",
                evidence="Passive summary generated from crawler, header, cookie, and form indicators.",
                confidence="High",
                impact="The summary supports prioritisation and planning for authorised deeper testing.",
                recommendation="Use the passive summary to plan authorised deeper testing.",
                verification="Review the Web Passive Risk Summary report section.",
                limitation="Passive summary does not test exploitability or submit forms.",
                source=SOURCE,
            )
        )
    priority_count = len(summary.get("high_risk_indicators") or []) + len(summary.get("medium_risk_indicators") or [])
    if priority_count and "Passive Web Review Recommended" not in existing_titles:
        findings.append(
            create_finding(
                title="Passive Web Review Recommended",
                severity="Medium" if summary.get("passive_risk_rating") == "High" else "Low",
                category="Web DAST",
                affected_url=str(summary.get("start_url") or ""),
                service="http",
                evidence=f"Passive checks identified {priority_count} medium/high indicators.",
                confidence="Medium",
                impact="Priority passive indicators may require remediation or scoped active validation.",
                recommendation="Review priority web findings before active testing.",
                verification="Review web findings and passive summary indicators.",
                limitation="Passive indicators require manual validation.",
                source=SOURCE,
            )
        )
    return findings


def _indicator_titles(findings: list[Finding | dict[str, Any]], severities: set[str]) -> list[str]:
    titles: list[str] = []
    for finding in get_web_findings(findings):
        if str(finding.get("source") or "") == SOURCE:
            continue
        if str(finding.get("severity") or "") in severities:
            title = str(finding.get("title") or "")
            if title and title not in titles:
                titles.append(title)
    return titles
