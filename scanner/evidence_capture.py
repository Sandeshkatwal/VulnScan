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
