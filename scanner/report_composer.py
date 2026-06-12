"""Compose Professional Finding Builder outputs into complete reports."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from scanner.evidence_redaction import redact_mapping_values
from scanner.finding_builder import calculate_finding_risk_score
from scanner.finding_models import now_iso
from scanner.report_sections import (
    build_evidence_summary_section,
    build_executive_summary,
    build_findings_summary,
    build_owasp_mapping_section,
)
from scanner.retest_summary import build_retest_summary
from scanner.risk_acceptance import build_risk_acceptance_summary


ASSESSMENT_TYPES = {
    "web_application_assessment",
    "owasp_assessment",
    "authenticated_assessment",
    "vulnerability_management",
    "bug_intelligence",
    "retest_report",
    "custom",
}
REPORT_STATUSES = {"draft", "ready_for_review", "final", "archived"}


def new_report_id() -> str:
    return f"report-{uuid4().hex[:10]}"


def compose_report(
    *,
    title: str,
    target: str,
    findings: list[dict[str, Any]],
    client_or_project_name: str = "",
    assessment_type: str = "owasp_assessment",
    report_status: str = "draft",
    generated_by: str = "VulScan",
    date_range: dict[str, Any] | None = None,
    scope_summary: str = "",
    methodology_summary: str = "",
    owasp_summary: dict[str, Any] | None = None,
    appendices: dict[str, Any] | None = None,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    assessment_type = assessment_type if assessment_type in ASSESSMENT_TYPES else "custom"
    report_status = report_status if report_status in REPORT_STATUSES else "draft"
    safe_findings = []
    for finding in findings:
        item = redact_mapping_values(dict(finding))
        if not item.get("risk_rating"):
            item["risk_rating"] = calculate_finding_risk_score(item)
            item["risk_score"] = item["risk_rating"]["risk_score"]
        safe_findings.append(item)
    evidence_summary = build_evidence_summary_section(safe_findings)
    executive_summary = build_executive_summary(safe_findings, owasp_summary=owasp_summary, evidence_summary=evidence_summary)
    retest_summary = build_retest_summary(safe_findings)
    risk_acceptance_summary = build_risk_acceptance_summary(safe_findings)
    findings_summary = build_findings_summary(safe_findings)
    owasp_mapping = build_owasp_mapping_section(safe_findings, owasp_summary)
    remediation_roadmap = _build_remediation_roadmap(safe_findings)
    export_blocked = evidence_summary["export_safety_status"] == "blocked"
    return {
        "report_id": new_report_id(),
        "title": title,
        "target": target,
        "client_or_project_name": client_or_project_name,
        "assessment_type": assessment_type,
        "report_status": report_status,
        "generated_at": now_iso(),
        "generated_by": generated_by,
        "date_range": date_range or {},
        "scope_summary": scope_summary or "Assessment scope was defined by the supplied target and available local assessment records.",
        "methodology_summary": methodology_summary or "VulScan composed this report from safe findings, redacted evidence references, OWASP assessment data, manual observations, retest records, and local scan outputs. No scan is executed by the Report Composer.",
        "executive_summary": executive_summary,
        "risk_overview": findings_summary,
        "findings": safe_findings,
        "evidence_summary": evidence_summary,
        "owasp_summary": owasp_mapping,
        "retest_summary": retest_summary,
        "risk_acceptance_summary": risk_acceptance_summary,
        "remediation_roadmap": remediation_roadmap,
        "limitations": limitations or ["Candidate findings require manual validation before being described as manually verified issues."],
        "safe_testing_statement": "This report is for authorised testing only. It includes Redacted Evidence references and excludes raw secrets, passwords, cookies, bearer tokens, private keys, full sensitive response bodies, exploit payloads, and unsafe reproduction steps.",
        "appendices": appendices or {"tool_version": "VulScan 21.8", "glossary": ["Technical Finding", "Executive Summary", "Business Impact", "Developer Remediation", "Retest Status"]},
        "export_paths": {},
        "export_safety_status": "blocked" if export_blocked else "allowed",
    }


def _build_remediation_roadmap(findings: list[dict[str, Any]]) -> dict[str, Any]:
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    active = [finding for finding in findings if finding.get("status") not in {"false_positive", "closed"} and finding.get("retest_status") != "retest_passed"]
    active.sort(key=lambda finding: (order.get(str(finding.get("severity")), 4), -int(finding.get("risk_score") or 0)))
    return {
        "priority_findings": [{"finding_id": finding.get("finding_id"), "title": finding.get("title"), "severity": finding.get("severity"), "risk_score": finding.get("risk_score")} for finding in active[:10]],
        "themes": sorted({cat.split(":")[0] for finding in active for cat in finding.get("owasp_categories") or [] if cat}),
    }
