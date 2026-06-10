"""Evidence templates for manual Role and Permission Mapping validation."""

from __future__ import annotations

from typing import Any

from scanner.evidence import redact_nested


def build_role_permission_evidence_template(
    *,
    role_label: str = "",
    expected_permission: str = "unknown",
    observed_manual_result: str = "",
    affected_endpoint: str = "",
    action_type: str = "",
    risk_if_failed: str = "",
    recommendation: str = "",
) -> dict[str, Any]:
    """Build a redacted evidence template for manual A01 validation."""
    return redact_nested(
        {
            "evidence_type": "role_permission_mapping_manual_validation",
            "role_label": role_label,
            "expected_permission": expected_permission,
            "observed_manual_result": observed_manual_result,
            "affected_endpoint": affected_endpoint,
            "action_type": action_type,
            "risk_if_failed": risk_if_failed,
            "recommendation": recommendation or "Validate server-side access control using authorised test accounts and redacted evidence.",
            "safety_notes": [
                "Authorised Test Accounts Only.",
                "Do not include usernames, passwords, session cookies, bearer tokens, Authorization headers, or real user data.",
                "Do not perform destructive actions.",
            ],
        }
    )


def build_a01_manual_test_evidence_template(plan: dict[str, Any], observation: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build redacted evidence context for an A01 Manual Validation Plan."""
    observation = observation or plan.get("observed_behaviour") or {}
    return redact_nested(
        {
            "evidence_type": "a01_manual_validation_plan",
            "test_plan_id": plan.get("test_plan_id") or "",
            "role_label": plan.get("role_label") or "",
            "affected_endpoint": plan.get("affected_url") or plan.get("normalised_url") or "",
            "expected_permission": plan.get("expected_permission") or "unknown",
            "expected_behaviour": plan.get("expected_secure_behaviour") or "",
            "observed_behaviour": observation.get("observed_message_summary") or "",
            "observed_access_result": observation.get("observed_access_result") or "not_tested",
            "evidence_summary": observation.get("evidence_summary") or "",
            "redaction_status": observation.get("redaction_status") or "redacted",
            "safety_notes": [
                "Authorised Test Accounts Only.",
                "Do not include secret authentication material or real user data.",
                "Manual Validation Required.",
            ],
        }
    )
