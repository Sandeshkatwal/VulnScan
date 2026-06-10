"""API handlers for Access Control Manual Test Planner."""

from __future__ import annotations

from typing import Any

from scanner.a01_manual_tests import build_a01_observation
from scanner.access_control_retest import build_a01_retest_record
from scanner.access_control_test_planner import (
    build_a01_manual_validation_summary,
    build_report_ready_a01_template,
    build_test_plan_from_endpoint,
    build_test_plans_from_a01_candidates,
    find_test_plan,
    load_access_test_plans,
    record_observation_for_plan,
)
from scanner.evidence import redact_nested
from scanner.role_profiles import validate_no_credential_fields


def api_generate_access_tests(
    a01_evidence_items: list[dict[str, Any]],
    role_profiles: list[dict[str, Any]] | None = None,
    permission_matrix: dict[str, Any] | None = None,
) -> dict[str, Any]:
    validate_no_credential_fields({"a01_evidence_items": a01_evidence_items, "role_profiles": role_profiles or [], "permission_matrix": permission_matrix or {}})
    plans = build_test_plans_from_a01_candidates(a01_evidence_items, role_profiles or [{}], permission_matrix or {})
    return redact_nested(
        {
            "access_control_test_plans": plans,
            "access_control_observations": [],
            "access_control_retests": [],
            "a01_manual_validation_summary": build_a01_manual_validation_summary(plans, [], []),
        }
    )


def api_create_access_test(
    role: dict[str, Any] | None,
    endpoint: dict[str, Any] | str,
    expected_permission: str,
    test_type: str,
) -> dict[str, Any]:
    validate_no_credential_fields({"role": role or {}, "endpoint": endpoint})
    endpoint_payload = {"url": endpoint, "method": "GET"} if isinstance(endpoint, str) else dict(endpoint or {})
    plan = build_test_plan_from_endpoint(endpoint_payload, None, expected_permission, role or {}, test_type)
    return {"access_control_test_plan": plan}


def api_record_observation(
    test_plan_id: str,
    observed_access_result: str,
    observed_status_code: int | None = None,
    observed_message_summary: str = "",
    evidence_summary: str = "",
    evidence_file_path: str = "",
    tester_notes: str = "",
) -> dict[str, Any]:
    observation = build_a01_observation(
        test_plan_id=test_plan_id,
        observed_access_result=observed_access_result,
        observed_status_code=observed_status_code,
        observed_message_summary=observed_message_summary,
        evidence_summary=evidence_summary,
        evidence_file_path=evidence_file_path,
        tester_notes=tester_notes,
    )
    return {"access_control_observation": observation}


def api_record_retest(
    test_plan_id: str,
    retest_status: str,
    original_observed_result: str = "",
    remediation_summary: str = "",
    retest_steps: list[str] | None = None,
    retest_observed_result: str = "",
    retest_notes: str = "",
) -> dict[str, Any]:
    record = build_a01_retest_record(
        test_plan_id=test_plan_id,
        retest_status=retest_status,
        original_observed_result=original_observed_result,
        remediation_summary=remediation_summary,
        retest_steps=retest_steps,
        retest_observed_result=retest_observed_result,
        retest_notes=retest_notes,
    )
    return {"access_control_retest": record}


def api_get_access_test(plan_id: str) -> dict[str, Any]:
    package = load_access_test_plans()
    return {"access_control_test_plan": find_test_plan(package["access_control_test_plans"], plan_id)}


def api_report_template(plan: dict[str, Any], observation: dict[str, Any] | None = None, retest: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"a01_report_template": build_report_ready_a01_template(plan, observation, retest)}
