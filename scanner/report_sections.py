"""Section builders for composed professional assessment reports."""

from __future__ import annotations

from collections import Counter
from typing import Any

from scanner.risk_acceptance import build_risk_acceptance_summary
from scanner.retest_summary import build_retest_summary


SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
OWASP_IDS = ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]


def build_executive_summary(findings: list[dict[str, Any]], owasp_summary: dict[str, Any] | None = None, evidence_summary: dict[str, Any] | None = None) -> dict[str, Any]:
    total = len(findings)
    high_critical = sum(1 for finding in findings if finding.get("severity") in {"High", "Critical"})
    manually_verified = sum(1 for finding in findings if finding.get("validation_status") == "manually_verified_issue")
    requiring_validation = sum(1 for finding in findings if finding.get("validation_status") in {"candidate", "indicator_only", "manual_validation_required"})
    remediated = sum(1 for finding in findings if finding.get("retest_status") == "retest_passed" or finding.get("status") == "remediated")
    category_counts = Counter(cat.split(":")[0] for finding in findings for cat in finding.get("owasp_categories") or [] if cat)
    strongest = [category for category, _count in category_counts.most_common(3)]
    priorities = []
    if high_critical:
        priorities.append("prioritise High and Critical Technical Findings")
    if requiring_validation:
        priorities.append("complete manual validation for candidate indicators")
    if manually_verified:
        priorities.append("remediate and retest manually verified issues")
    summary_text = (
        f"The assessment produced {total} Technical Findings, including {high_critical} High or Critical items. "
        f"Manual validation confirmed {manually_verified} issue(s), while {requiring_validation} item(s) require further validation. "
        f"{remediated} item(s) are marked remediated or retest passed. Assessment coverage and limitations are reflected in the Scope and Methodology section."
    )
    return {
        "total_findings": total,
        "high_critical_count": high_critical,
        "strongest_risk_themes": strongest,
        "manually_verified_count": manually_verified,
        "manual_validation_required_count": requiring_validation,
        "remediated_or_retest_passed_count": remediated,
        "key_remediation_priorities": priorities,
        "scope_limitations": (owasp_summary or {}).get("limitations") or [],
        "evidence_summary": evidence_summary or {},
        "summary": summary_text,
    }


def build_findings_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    severity_counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = finding.get("severity") or "Informational"
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    return {
        "total": len(findings),
        "severity_counts": severity_counts,
        "status_counts": dict(Counter(str(finding.get("status") or "draft") for finding in findings)),
        "owasp_category_counts": dict(Counter(cat.split(":")[0] for finding in findings for cat in finding.get("owasp_categories") or [] if cat)),
        "retest_status_counts": dict(Counter(str(finding.get("retest_status") or "not_retested") for finding in findings)),
    }


def build_owasp_mapping_section(findings: list[dict[str, Any]], owasp_summary: dict[str, Any] | None = None) -> dict[str, Any]:
    counts = Counter(cat.split(":")[0] for finding in findings for cat in finding.get("owasp_categories") or [] if cat)
    matrix = []
    for owasp_id in OWASP_IDS:
        related = [finding for finding in findings if any(str(cat).startswith(owasp_id) for cat in finding.get("owasp_categories") or [])]
        matrix.append(
            {
                "category": owasp_id,
                "finding_count": counts.get(owasp_id, 0),
                "manual_validation_required": sum(1 for finding in related if finding.get("validation_status") in {"candidate", "indicator_only", "manual_validation_required"}),
                "manually_verified": sum(1 for finding in related if finding.get("validation_status") == "manually_verified_issue"),
            }
        )
    return {"matrix": matrix, "source_summary": owasp_summary or {}}


def build_evidence_summary_section(findings: list[dict[str, Any]]) -> dict[str, Any]:
    refs = sorted({ref for finding in findings for ref in finding.get("evidence_references") or [] if ref})
    blocked = []
    scores = []
    for finding in findings:
        quality = finding.get("evidence_quality_summary") or {}
        if isinstance(quality, dict) and quality.get("score") is not None:
            scores.append(int(quality.get("score") or 0))
        safety = finding.get("export_safety_status") or {}
        blocked.extend(safety.get("blocked_evidence") or [])
    return {
        "evidence_reference_count": len(refs),
        "evidence_references": refs,
        "average_evidence_quality_score": round(sum(scores) / len(scores), 2) if scores else 0,
        "redaction_status": "blocked" if blocked else "redacted",
        "export_safety_status": "blocked" if blocked else "allowed",
        "blocked_evidence": blocked,
    }


def build_report_sections(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings = list(report.get("findings") or [])
    return [
        {"section_id": "cover_page", "title": "Cover Page", "content": {"title": report.get("title"), "target": report.get("target"), "assessment_type": report.get("assessment_type"), "generated_at": report.get("generated_at"), "report_status": report.get("report_status")}},
        {"section_id": "safe_testing_statement", "title": "Safe Testing Statement", "content": report.get("safe_testing_statement")},
        {"section_id": "executive_summary", "title": "Executive Summary", "content": report.get("executive_summary")},
        {"section_id": "scope_methodology", "title": "Scope and Methodology", "content": {"scope_summary": report.get("scope_summary"), "methodology_summary": report.get("methodology_summary"), "limitations": report.get("limitations")}},
        {"section_id": "findings_summary", "title": "Findings Summary", "content": build_findings_summary(findings)},
        {"section_id": "technical_findings", "title": "Technical Findings", "content": findings},
        {"section_id": "owasp_mapping", "title": "OWASP Mapping", "content": report.get("owasp_summary") or build_owasp_mapping_section(findings)},
        {"section_id": "evidence_summary", "title": "Evidence Summary", "content": report.get("evidence_summary") or build_evidence_summary_section(findings)},
        {"section_id": "retest_summary", "title": "Retest Summary", "content": report.get("retest_summary") or build_retest_summary(findings)},
        {"section_id": "risk_acceptance", "title": "Risk Acceptance", "content": report.get("risk_acceptance_summary") or build_risk_acceptance_summary(findings)},
        {"section_id": "appendices", "title": "Appendices", "content": report.get("appendices") or {}},
    ]

