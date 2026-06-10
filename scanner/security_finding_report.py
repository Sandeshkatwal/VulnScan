"""Security Finding Report templates for manual A01 role context."""

from __future__ import annotations

from typing import Any

from scanner.evidence import redact_nested


def build_a01_role_permission_report_template(evidence: dict[str, Any]) -> dict[str, Any]:
    """Return a safe report template for manually confirmed A01 findings."""
    return redact_nested(
        {
            "report_type": "A01 Access-Control Planning",
            "title": "Manual Role and Permission Mapping Finding Template",
            "authorised_test_account_note": "Authorised Test Accounts Only. Use safe labels, not real credentials.",
            "role_permission_context": {
                "role_label": evidence.get("role_label") or "",
                "expected_permission": evidence.get("expected_permission") or "unknown",
                "inferred_action": evidence.get("inferred_action") or evidence.get("action_type") or "",
                "validation_status": evidence.get("validation_status") or "not_tested",
            },
            "expected_vs_observed_behaviour": {
                "expected": evidence.get("expected_secure_result") or "",
                "observed_manual_result": evidence.get("observed_manual_result") or "",
            },
            "redacted_evidence": evidence.get("redacted_evidence") or evidence.get("safe_evidence_summary") or "",
            "manual_validation_steps": evidence.get("safe_manual_steps") or [],
            "recommendation": evidence.get("recommendation") or "Enforce server-side authorization for the documented role and action.",
            "limitations": [
                "Use only after manual validation confirms behaviour.",
                "Do not include secret authentication material or real user data.",
            ],
        }
    )


def build_a01_manual_test_report_template(plan: dict[str, Any], observation: dict[str, Any] | None = None, retest: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build report-ready A01 text from an Access Control Manual Test Planner record."""
    from scanner.access_control_test_planner import build_report_ready_a01_template

    return build_report_ready_a01_template(plan, observation, retest)
