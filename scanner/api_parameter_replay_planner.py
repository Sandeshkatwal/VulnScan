"""API-safe handlers for Safe Authenticated Parameter Replay Planner."""

from __future__ import annotations

from typing import Any

from scanner.evidence import redact_nested
from scanner.parameter_replay_planner import build_parameter_replay_summary, build_report_ready_replay_template, build_replay_plan_from_parameter, build_replay_plans_from_candidates, find_replay_plan, load_replay_plans, package_from_plans
from scanner.parameter_review_workflow import build_parameter_replay_observation, build_parameter_replay_retest
from scanner.role_profiles import validate_no_credential_fields


def _reject_raw_credential_values(payload: Any) -> None:
    validate_no_credential_fields(payload)


def api_create_replay_plan(endpoint: dict[str, Any] | str, parameter: str | dict[str, Any], intent: str = "", role: dict[str, Any] | str | None = None) -> dict[str, Any]:
    endpoint_payload = {"url": endpoint, "method": "GET"} if isinstance(endpoint, str) else dict(endpoint or {})
    parameter_payload = {"parameter_name": parameter} if isinstance(parameter, str) else dict(parameter or {})
    if intent:
        parameter_payload["replay_intent"] = intent
    role_payload = {"role_label": role} if isinstance(role, str) else dict(role or {})
    _reject_raw_credential_values({"endpoint": endpoint_payload, "role": role_payload})
    plan = build_replay_plan_from_parameter(parameter_payload, endpoint_payload, role_payload)
    package = package_from_plans([plan])
    return {"parameter_replay_plan": package["parameter_replay_plans"][0], "redacted_request_template": package["redacted_request_templates"][0], "parameter_replay_summary": package["parameter_replay_summary"]}


def api_generate_replay_plans(
    parameter_results: list[dict[str, Any]],
    endpoint_results: list[dict[str, Any]] | None = None,
    a01_evidence: list[dict[str, Any]] | None = None,
    a05_evidence: list[dict[str, Any]] | None = None,
    a07_evidence: list[dict[str, Any]] | None = None,
    roles: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    _reject_raw_credential_values({"endpoint_results": endpoint_results or [], "roles": roles or []})
    plans = build_replay_plans_from_candidates(parameter_results, endpoint_results or [], a01_evidence or [], a05_evidence or [], a07_evidence or [], roles or [{}])
    return package_from_plans(plans)


def api_get_replay_plan(plan_id: str) -> dict[str, Any]:
    package = load_replay_plans()
    return {"parameter_replay_plan": find_replay_plan(package["parameter_replay_plans"], plan_id)}


def api_record_replay_observation(
    replay_plan_id: str,
    observed_access_result: str,
    observed_status_code: int | None = None,
    observed_message_summary: str = "",
    observed_parameter_effect: str = "",
    evidence_summary: str = "",
    evidence_file_path: str = "",
    tester_notes: str = "",
) -> dict[str, Any]:
    observation = build_parameter_replay_observation(
        replay_plan_id=replay_plan_id,
        observed_access_result=observed_access_result,
        observed_status_code=observed_status_code,
        observed_message_summary=observed_message_summary,
        observed_parameter_effect=observed_parameter_effect,
        evidence_summary=evidence_summary,
        evidence_file_path=evidence_file_path,
        tester_notes=tester_notes,
    )
    return {"parameter_replay_observation": observation}


def api_record_replay_retest(
    replay_plan_id: str,
    retest_status: str,
    original_observed_result: str = "",
    remediation_summary: str = "",
    retest_steps: list[str] | None = None,
    retest_observed_result: str = "",
    retest_notes: str = "",
) -> dict[str, Any]:
    retest = build_parameter_replay_retest(
        replay_plan_id=replay_plan_id,
        retest_status=retest_status,
        original_observed_result=original_observed_result,
        remediation_summary=remediation_summary,
        retest_steps=retest_steps,
        retest_observed_result=retest_observed_result,
        retest_notes=retest_notes,
    )
    return {"parameter_replay_retest": retest}


def api_replay_report_template(plan: dict[str, Any], observation: dict[str, Any] | None = None, retest: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"parameter_replay_report_template": redact_nested(build_report_ready_replay_template(plan, observation, retest))}
