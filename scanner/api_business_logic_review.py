"""API handlers for Business Logic Review Workflow Assistant."""

from __future__ import annotations

from typing import Any

from scanner.business_logic_checklists import build_abuse_case_checklist
from scanner.business_logic_retest import build_business_logic_observation, build_business_logic_retest
from scanner.business_logic_review import build_business_logic_review_plan, build_report_ready_business_logic_template, build_review_plans_from_candidates, package_business_logic
from scanner.role_profiles import validate_no_credential_fields
from scanner.workflow_candidates import assess_business_logic_workflow_candidates
from scanner.workflow_state_map import build_state_transition_map


def api_detect_business_logic(endpoint_results: list[dict[str, Any]], parameter_results: list[dict[str, Any]] | None = None, role_matrix: list[dict[str, Any]] | dict[str, Any] | None = None, replay_plans: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    validate_no_credential_fields({"role_matrix": role_matrix or {}})
    candidates = assess_business_logic_workflow_candidates(endpoint_results, parameter_results or [], role_matrix, replay_plans or [])
    return package_business_logic(candidates, [], [], [])


def api_create_business_logic_plan(workflow: str, endpoint: str | dict[str, Any], role: str | dict[str, Any] | None = None) -> dict[str, Any]:
    role_payload = {"role_label": role} if isinstance(role, str) else dict(role or {})
    validate_no_credential_fields({"role": role_payload})
    endpoint_payload = {"url": endpoint} if isinstance(endpoint, str) else dict(endpoint or {})
    candidate = {
        "workflow_candidate_id": "api-created",
        "workflow_type": workflow,
        "affected_url": endpoint_payload.get("url") or endpoint_payload.get("endpoint") or "",
        "target": endpoint_payload.get("target") or "",
        "related_roles": [role_payload.get("role_label") or role_payload.get("role_id") or ""],
        "related_owasp_categories": ["A06"],
    }
    plan = build_business_logic_review_plan(candidate, [role_payload] if role_payload else [])
    return {"business_logic_review_plan": plan}


def api_generate_business_logic_plans(candidates: list[dict[str, Any]], roles: list[dict[str, Any]] | None = None, replay_plans: list[dict[str, Any]] | None = None, access_test_plans: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    validate_no_credential_fields({"roles": roles or []})
    plans = build_review_plans_from_candidates(candidates, roles or [], replay_plans or [], access_test_plans or [])
    return package_business_logic(candidates, plans, [], [])


def api_state_map(workflow: str, endpoints: list[Any] | None = None, roles: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    validate_no_credential_fields({"roles": roles or []})
    return {"business_logic_state_transition_map": build_state_transition_map(workflow, endpoints or [], roles or [])}


def api_checklist(workflow: str, review_plan_id: str = "") -> dict[str, Any]:
    return {"business_logic_abuse_case_checklist": build_abuse_case_checklist(workflow, review_plan_id)}


def api_observe_business_logic(**kwargs: Any) -> dict[str, Any]:
    return {"business_logic_observation": build_business_logic_observation(**kwargs)}


def api_retest_business_logic(**kwargs: Any) -> dict[str, Any]:
    return {"business_logic_retest": build_business_logic_retest(**kwargs)}


def api_business_logic_report_template(plan: dict[str, Any], observation: dict[str, Any] | None = None, retest: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"business_logic_report_template": build_report_ready_business_logic_template(plan, observation, retest)}
