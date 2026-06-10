"""Evidence Vault data model helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


EVIDENCE_TYPES = {
    "request_response_summary",
    "screenshot_reference",
    "manual_observation",
    "scan_output_summary",
    "owasp_indicator",
    "vulnerability_intelligence",
    "authenticated_crawl_result",
    "access_control_test_observation",
    "parameter_replay_observation",
    "business_logic_observation",
    "retest_observation",
    "report_attachment_reference",
    "custom",
}

EVIDENCE_STRENGTHS = {"informational", "weak_indicator", "strong_indicator", "manually_verified_issue", "manually_verified_secure", "confirmed_finding"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_evidence_id() -> str:
    return f"evidence_{uuid4().hex[:12]}"


def build_evidence_item(**kwargs: Any) -> dict[str, Any]:
    created = kwargs.get("created_at") or now_iso()
    evidence_type = kwargs.get("evidence_type") or kwargs.get("type") or "custom"
    if evidence_type not in EVIDENCE_TYPES:
        evidence_type = "custom"
    item = {
        "evidence_id": kwargs.get("evidence_id") or new_evidence_id(),
        "title": kwargs.get("title") or "Evidence Item",
        "evidence_type": evidence_type,
        "source_module": kwargs.get("source_module") or "manual",
        "related_target": kwargs.get("related_target") or kwargs.get("target") or "",
        "related_url": kwargs.get("related_url") or kwargs.get("url") or "",
        "related_host": kwargs.get("related_host") or kwargs.get("host") or "",
        "related_owasp_categories": list(kwargs.get("related_owasp_categories") or kwargs.get("owasp") or []),
        "linked_finding_ids": list(kwargs.get("linked_finding_ids") or []),
        "linked_test_plan_ids": list(kwargs.get("linked_test_plan_ids") or []),
        "linked_replay_plan_ids": list(kwargs.get("linked_replay_plan_ids") or []),
        "linked_business_logic_plan_ids": list(kwargs.get("linked_business_logic_plan_ids") or []),
        "linked_submission_ids": list(kwargs.get("linked_submission_ids") or []),
        "severity_context": kwargs.get("severity_context") or "",
        "confidence": kwargs.get("confidence") or "medium",
        "evidence_strength": kwargs.get("evidence_strength") or "informational",
        "redaction_status": kwargs.get("redaction_status") or "pending_redaction",
        "redaction_checks": list(kwargs.get("redaction_checks") or []),
        "secret_detection_status": kwargs.get("secret_detection_status") or "not_checked",
        "evidence_quality_score": kwargs.get("evidence_quality_score") or 0,
        "safe_summary": kwargs.get("safe_summary") or kwargs.get("summary") or "",
        "redacted_request_summary": kwargs.get("redacted_request_summary") or "",
        "redacted_response_summary": kwargs.get("redacted_response_summary") or "",
        "safe_observed_value": kwargs.get("safe_observed_value") or "",
        "attachment_metadata": list(kwargs.get("attachment_metadata") or []),
        "timeline_events": list(kwargs.get("timeline_events") or []),
        "created_at": created,
        "updated_at": kwargs.get("updated_at") or created,
        "created_by": kwargs.get("created_by") or "system",
        "notes": kwargs.get("notes") or "",
        "limitations": list(kwargs.get("limitations") or ["Evidence Vault stores Redacted Evidence summaries only."]),
    }
    return item
