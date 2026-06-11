"""Professional Finding Builder data model helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


FINDING_STATUSES = {
    "draft",
    "ready_for_review",
    "reviewed",
    "accepted",
    "false_positive",
    "risk_accepted",
    "remediated",
    "retest_required",
    "closed",
}
FINDING_TYPES = {
    "owasp_indicator",
    "manually_verified_issue",
    "vulnerability_intelligence_match",
    "access_control_issue",
    "business_logic_issue",
    "authentication_issue",
    "misconfiguration",
    "cryptographic_issue",
    "supply_chain_issue",
    "evidence_note",
    "custom",
}
SEVERITIES = {"Informational", "Low", "Medium", "High", "Critical"}
CONFIDENCES = {"Low", "Medium", "High", "Confirmed"}
VALIDATION_STATUSES = {
    "candidate",
    "indicator_only",
    "manual_validation_required",
    "manually_verified_issue",
    "manually_verified_secure",
    "false_positive",
    "retest_required",
    "retest_passed",
    "retest_failed",
}
RETEST_STATUSES = {
    "not_retested",
    "retest_required",
    "retest_scheduled",
    "retest_passed",
    "retest_failed",
    "not_applicable",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_finding_id() -> str:
    return f"finding-{uuid4().hex[:8]}"


def normalise_severity(severity: str | None) -> str:
    value = str(severity or "Informational").strip().title()
    if value == "Info":
        value = "Informational"
    return value if value in SEVERITIES else "Informational"


def normalise_confidence(confidence: str | None) -> str:
    value = str(confidence or "Low").strip().title()
    return value if value in CONFIDENCES else "Low"


def normalise_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if str(item)]
    return [str(value)]


def build_professional_finding(**kwargs: Any) -> dict[str, Any]:
    created = kwargs.get("created_at") or now_iso()
    validation_status = str(kwargs.get("validation_status") or "candidate")
    if validation_status not in VALIDATION_STATUSES:
        validation_status = "candidate"
    evidence_strength = str(kwargs.get("evidence_strength") or "informational")
    confidence = normalise_confidence(kwargs.get("confidence"))
    if validation_status == "manually_verified_issue" or evidence_strength == "confirmed_finding":
        confidence = "Confirmed"
    elif confidence == "Confirmed":
        confidence = "High"
    status = str(kwargs.get("status") or "draft")
    if status not in FINDING_STATUSES:
        status = "draft"
    finding_type = str(kwargs.get("finding_type") or "custom")
    if finding_type not in FINDING_TYPES:
        finding_type = "custom"
    return {
        "finding_id": kwargs.get("finding_id") or new_finding_id(),
        "title": kwargs.get("title") or "Professional Finding Draft",
        "status": status,
        "finding_type": finding_type,
        "owasp_categories": normalise_list(kwargs.get("owasp_categories") or kwargs.get("owasp")),
        "affected_targets": normalise_list(kwargs.get("affected_targets") or kwargs.get("target")),
        "affected_urls": normalise_list(kwargs.get("affected_urls") or kwargs.get("url")),
        "affected_components": normalise_list(kwargs.get("affected_components") or kwargs.get("component")),
        "affected_parameters": normalise_list(kwargs.get("affected_parameters") or kwargs.get("parameter")),
        "severity": normalise_severity(kwargs.get("severity")),
        "risk_score": int(kwargs.get("risk_score") or 0),
        "confidence": confidence,
        "evidence_strength": evidence_strength,
        "validation_status": validation_status,
        "executive_summary": kwargs.get("executive_summary") or "",
        "technical_summary": kwargs.get("technical_summary") or kwargs.get("summary") or "",
        "business_impact": kwargs.get("business_impact") or "",
        "technical_impact": kwargs.get("technical_impact") or "",
        "affected_roles": normalise_list(kwargs.get("affected_roles")),
        "affected_workflows": normalise_list(kwargs.get("affected_workflows")),
        "prerequisites": normalise_list(kwargs.get("prerequisites")),
        "reproduction_steps": normalise_list(kwargs.get("reproduction_steps")),
        "safe_reproduction_notes": kwargs.get("safe_reproduction_notes") or "",
        "evidence_references": normalise_list(kwargs.get("evidence_references") or kwargs.get("evidence_ids")),
        "evidence_quality_summary": kwargs.get("evidence_quality_summary") or {},
        "remediation": kwargs.get("remediation") or "",
        "developer_guidance": kwargs.get("developer_guidance") or "",
        "validation_guidance": kwargs.get("validation_guidance") or "",
        "retest_status": kwargs.get("retest_status") if kwargs.get("retest_status") in RETEST_STATUSES else "not_retested",
        "retest_notes": kwargs.get("retest_notes") or "",
        "risk_acceptance": kwargs.get("risk_acceptance") or None,
        "limitations": normalise_list(kwargs.get("limitations")) or ["Finding draft uses safe summaries and linked evidence references only."],
        "safe_testing_statement": kwargs.get("safe_testing_statement") or "Authorised testing only. Redacted Evidence references are used; raw secrets and unsafe evidence are excluded.",
        "created_at": created,
        "updated_at": kwargs.get("updated_at") or created,
        "source_modules": normalise_list(kwargs.get("source_modules") or kwargs.get("source_module")),
        "tags": normalise_list(kwargs.get("tags")),
        "warnings": normalise_list(kwargs.get("warnings")),
    }

