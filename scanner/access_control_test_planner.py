"""Access Control Manual Test Planner for authorised A01 workflows."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from scanner.a01_manual_tests import ACCESS_TEST_REPORTS_DIR, build_a01_observation, observation_to_validation_status
from scanner.access_control_evidence_checklist import build_evidence_checklist
from scanner.access_control_matrix import infer_action_from_endpoint
from scanner.access_control_retest import build_a01_retest_record, retest_summary
from scanner.evidence import redact_nested
from scanner.permission_matrix import EXPECTED_PERMISSIONS, load_permission_matrix
from scanner.role_profiles import ROLES_DIR, RoleProfileError, find_role, load_role_profiles, validate_no_credential_fields


ACCESS_TESTS_DIR = Path("data") / "access_control_tests"
ACCESS_TEST_REPORTS_DIR = Path("reports") / "access_control_tests"
TEST_TYPES = {
    "object_ownership_review",
    "horizontal_access_control_review",
    "vertical_access_control_review",
    "tenant_boundary_review",
    "function_level_authorization_review",
    "sensitive_export_review",
    "admin_surface_review",
    "role_permission_review",
    "file_download_authorization_review",
    "custom",
}
VALIDATION_STATUSES = {
    "planned",
    "in_progress",
    "manually_verified_secure",
    "manually_verified_issue",
    "needs_more_evidence",
    "not_applicable",
    "retest_required",
    "retest_passed",
    "retest_failed",
}
SAFE_TESTING_STATEMENT = (
    "Manual Validation Required. Use Authorised Test Accounts Only. "
    "VulScan creates local planning records and does not perform live access-control requests."
)


class AccessControlTestPlannerError(ValueError):
    """Raised when Access Control Manual Test Planner data is invalid."""


@dataclass
class A01ManualTestPlan:
    test_plan_id: str
    title: str
    category: str
    test_type: str
    target: str
    affected_url: str
    normalised_url: str
    endpoint_category: str
    role_label: str = ""
    role_id: str = ""
    tenant_label: str = ""
    expected_permission: str = "unknown"
    expected_secure_behaviour: str = ""
    test_preconditions: list[str] = field(default_factory=list)
    manual_steps: list[str] = field(default_factory=list)
    evidence_checklist: dict[str, Any] = field(default_factory=dict)
    observed_behaviour: dict[str, Any] = field(default_factory=dict)
    validation_status: str = "planned"
    risk_if_failed: str = ""
    recommendation: str = ""
    safety_notes: list[str] = field(default_factory=list)
    linked_a01_evidence_id: str = ""
    linked_endpoint_id: str = ""
    linked_role_matrix_id: str = ""
    linked_session_profile_id: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def ensure_access_test_dirs() -> None:
    ACCESS_TESTS_DIR.mkdir(parents=True, exist_ok=True)
    ACCESS_TEST_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (ACCESS_TEST_REPORTS_DIR / "evidence").mkdir(parents=True, exist_ok=True)


def build_a01_test_plan_from_candidate(
    a01_evidence_item: dict[str, Any],
    role_profile: dict[str, Any] | None = None,
    permission_rule: dict[str, Any] | None = None,
) -> dict[str, Any]:
    validate_no_credential_fields({"a01_evidence_item": a01_evidence_item, "role_profile": role_profile or {}, "permission_rule": permission_rule or {}})
    test_type = _test_type_from_candidate(a01_evidence_item)
    expected_permission = str((permission_rule or {}).get("expected_permission") or a01_evidence_item.get("expected_permission") or "unknown")
    if expected_permission not in EXPECTED_PERMISSIONS:
        expected_permission = "unknown"
    role = role_profile or {}
    affected_url = str(a01_evidence_item.get("affected_url") or a01_evidence_item.get("url") or "")
    plan_id = str(a01_evidence_item.get("manual_test_plan_id") or a01_evidence_item.get("manual_plan_id") or f"a01_plan_{uuid4().hex[:12]}")
    plan = _build_plan(
        test_plan_id=plan_id,
        title=str(a01_evidence_item.get("title") or _title_for_type(test_type)),
        category=str(a01_evidence_item.get("rule_group") or "A01 Access-Control Planning"),
        test_type=test_type,
        affected_url=affected_url,
        endpoint_category=str(a01_evidence_item.get("endpoint_category") or a01_evidence_item.get("access_control_candidate_type") or ""),
        role_profile=role,
        expected_permission=expected_permission,
        linked_a01_evidence_id=str(a01_evidence_item.get("evidence_id") or ""),
        linked_endpoint_id=str(a01_evidence_item.get("endpoint_id") or ""),
        linked_role_matrix_id=str((permission_rule or {}).get("rule_id") or ""),
        linked_session_profile_id=str(role.get("linked_session_profile_id") or a01_evidence_item.get("linked_session_profile_id") or ""),
    )
    return redact_nested(plan)


def build_test_plan_from_endpoint(
    endpoint_result: dict[str, Any],
    inferred_action: dict[str, Any] | str | None = None,
    expected_permission: str = "unknown",
    role_profile: dict[str, Any] | None = None,
    test_type: str | None = None,
) -> dict[str, Any]:
    validate_no_credential_fields({"endpoint_result": endpoint_result, "role_profile": role_profile or {}, "inferred_action": inferred_action or {}})
    inferred = infer_action_from_endpoint(endpoint_result) if not isinstance(inferred_action, dict) else inferred_action
    if isinstance(inferred_action, str):
        inferred["inferred_action"] = inferred_action
    selected_type = test_type or _test_type_from_action(str(inferred.get("inferred_action") or ""), endpoint_result)
    role = role_profile or {}
    plan = _build_plan(
        test_plan_id=f"a01_plan_{uuid4().hex[:12]}",
        title=_title_for_type(selected_type),
        category="A01 Access-Control Planning",
        test_type=selected_type,
        affected_url=str(inferred.get("endpoint") or endpoint_result.get("url") or endpoint_result.get("normalised_url") or ""),
        endpoint_category=str(endpoint_result.get("endpoint_category") or inferred.get("endpoint_category") or ""),
        role_profile=role,
        expected_permission=expected_permission if expected_permission in EXPECTED_PERMISSIONS else "unknown",
        linked_endpoint_id=str(endpoint_result.get("endpoint_id") or ""),
        linked_role_matrix_id=str(endpoint_result.get("role_matrix_id") or endpoint_result.get("manual_plan_id") or ""),
        linked_session_profile_id=str(role.get("linked_session_profile_id") or endpoint_result.get("linked_session_profile_id") or ""),
    )
    return redact_nested(plan)


def build_test_plans_from_a01_candidates(
    a01_evidence_items: list[dict[str, Any]],
    role_profiles: list[dict[str, Any]] | None = None,
    permission_matrix: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    validate_no_credential_fields({"a01_evidence_items": a01_evidence_items, "role_profiles": role_profiles or [], "permission_matrix": permission_matrix or {}})
    roles = role_profiles or [{}]
    plans: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in a01_evidence_items or []:
        matched_roles = _matching_roles(item, roles)
        for role in matched_roles:
            rule = _permission_rule_for(role, item, permission_matrix or {})
            plan = build_a01_test_plan_from_candidate(item, role, rule)
            fp = plan_fingerprint(plan)
            if fp in seen:
                continue
            seen.add(fp)
            plans.append(plan)
    return plans


def build_test_plans_from_role_mapping(role_mapping: dict[str, Any]) -> list[dict[str, Any]]:
    rows = role_mapping.get("role_endpoint_matrix") or []
    roles = {str(role.get("role_id") or role.get("role_label") or ""): role for role in role_mapping.get("role_profiles") or [] if isinstance(role, dict)}
    plans: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        action = str(row.get("inferred_action") or "")
        expected = str(row.get("expected_permission") or "unknown")
        url = str(row.get("endpoint") or "")
        if not _role_mapping_row_needs_plan(row):
            continue
        role = roles.get(str(row.get("role_id") or "")) or {
            "role_id": row.get("role_id") or "",
            "role_label": row.get("role_label") or "",
            "tenant_label": row.get("tenant_label") or "",
        }
        plan = build_test_plan_from_endpoint(
            {"url": url, "method": row.get("method") or "GET", "endpoint_category": row.get("endpoint_category") or ""},
            {"endpoint": url, "inferred_action": action, "action_id": row.get("action_id") or action},
            expected,
            role,
        )
        fp = plan_fingerprint(plan)
        if fp not in seen:
            seen.add(fp)
            plans.append(plan)
    return plans


def build_a01_manual_validation_summary(
    plans: list[dict[str, Any]] | None = None,
    observations: list[dict[str, Any]] | None = None,
    retests: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    plan_rows = plans or []
    observed_statuses = {str(item.get("test_plan_id")): observation_to_validation_status(item) for item in observations or []}
    statuses = [observed_statuses.get(str(plan.get("test_plan_id")), str(plan.get("validation_status") or "planned")) for plan in plan_rows]
    retest_counts = retest_summary(retests or [])
    return {
        "enabled": True,
        "manual_test_plans_count": len(plan_rows),
        "planned_count": statuses.count("planned"),
        "in_progress_count": statuses.count("in_progress"),
        "manually_verified_issue_count": statuses.count("manually_verified_issue"),
        "manually_verified_secure_count": statuses.count("manually_verified_secure"),
        "needs_more_evidence_count": statuses.count("needs_more_evidence"),
        "retest_required_count": statuses.count("retest_required") + retest_counts.get("retest_required_count", 0),
        "retest_passed_count": statuses.count("retest_passed") + retest_counts.get("retest_passed_count", 0),
        "retest_failed_count": statuses.count("retest_failed") + retest_counts.get("retest_failed_count", 0),
        "safety_notes": [SAFE_TESTING_STATEMENT],
    }


def record_observation_for_plan(plan: dict[str, Any], observation: dict[str, Any]) -> dict[str, Any]:
    updated = dict(plan)
    updated["observed_behaviour"] = observation
    updated["validation_status"] = observation_to_validation_status(observation)
    updated["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return redact_nested(updated)


def build_report_ready_a01_template(plan: dict[str, Any], observation: dict[str, Any] | None = None, retest: dict[str, Any] | None = None) -> dict[str, Any]:
    observation = observation or plan.get("observed_behaviour") or {}
    observed_result = str(observation.get("observed_access_result") or "not_tested")
    validation_status = observation_to_validation_status(observation) if observation else str(plan.get("validation_status") or "planned")
    is_issue = validation_status == "manually_verified_issue" and observed_result in {"unexpectedly_allowed", "unexpectedly_denied"}
    title_prefix = "Manually Verified A01 Issue" if is_issue else "A01 Manual Validation Plan"
    return redact_nested(
        {
            "Title": f"{title_prefix}: {plan.get('title') or 'Access Control Review'}",
            "Summary": _summary_text(plan, is_issue),
            "Affected Endpoint": plan.get("affected_url") or plan.get("normalised_url") or "",
            "Affected Role": plan.get("role_label") or "",
            "Expected Behaviour": plan.get("expected_secure_behaviour") or "",
            "Observed Behaviour": observation.get("observed_message_summary") or "Manual validation has not confirmed an issue.",
            "Impact if Confirmed": plan.get("risk_if_failed") or "",
            "Evidence": observation.get("evidence_summary") or "Evidence Checklist pending.",
            "Steps to Reproduce Manually": plan.get("manual_steps") or [],
            "Recommendation": plan.get("recommendation") or "",
            "Retest Notes": (retest or {}).get("retest_notes") or "",
            "Limitations": [
                "Manual validation required before reporting confirmed impact." if not is_issue else "Finding wording is based on manually recorded observation.",
                "Use Authorised Test Accounts Only.",
                "Evidence must be redacted before sharing.",
            ],
            "Safe Testing Statement": SAFE_TESTING_STATEMENT,
            "validation_status": validation_status,
            "observed_access_result": observed_result,
        }
    )


def save_access_test_package(package: dict[str, Any], *, json_report: bool = False, html_report: bool = False) -> tuple[Path | None, Path | None]:
    ensure_access_test_dirs()
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    json_path: Path | None = None
    html_path: Path | None = None
    if json_report:
        json_path = ACCESS_TEST_REPORTS_DIR / f"a01_test_plans_{stamp}.json"
        json_path.write_text(json.dumps(redact_nested(package), indent=2), encoding="utf-8")
    if html_report:
        html_path = ACCESS_TEST_REPORTS_DIR / f"a01_test_plans_{stamp}.html"
        html_path.write_text(render_access_test_html(package), encoding="utf-8")
    return json_path, html_path


def save_report_template_markdown(template: dict[str, Any], plan_id: str) -> Path:
    ensure_access_test_dirs()
    safe_id = "".join(ch for ch in str(plan_id) if ch.isalnum() or ch in {"-", "_"}) or "plan"
    path = ACCESS_TEST_REPORTS_DIR / f"a01_test_plan_{safe_id}.md"
    path.write_text(render_report_template_markdown(template), encoding="utf-8")
    return path


def load_access_test_plans(path: str | Path = ACCESS_TESTS_DIR / "sample_a01_test_plan.json") -> dict[str, Any]:
    plan_path = _resolve_access_test_path(path)
    try:
        payload = json.loads(plan_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AccessControlTestPlannerError(f"Access Control Manual Test Planner file was not found: {plan_path}") from exc
    except json.JSONDecodeError as exc:
        raise AccessControlTestPlannerError(f"Access Control Manual Test Planner file is not valid JSON: {plan_path}") from exc
    validate_no_credential_fields(payload)
    plans = payload.get("access_control_test_plans") or payload.get("test_plans") or []
    observations = payload.get("access_control_observations") or []
    retests = payload.get("access_control_retests") or []
    return redact_nested(
        {
            "access_control_test_plans": plans,
            "access_control_observations": observations,
            "access_control_retests": retests,
            "a01_manual_validation_summary": build_a01_manual_validation_summary(plans, observations, retests),
        }
    )


def find_test_plan(plans: list[dict[str, Any]], plan_id: str) -> dict[str, Any]:
    for plan in plans or []:
        if str(plan.get("test_plan_id") or "") == str(plan_id):
            return plan
    raise AccessControlTestPlannerError(f"Access Control Manual Test Planner plan was not found: {plan_id}")


def plan_fingerprint(plan: dict[str, Any]) -> str:
    raw = "|".join(
        [
            _normalise_url(str(plan.get("normalised_url") or plan.get("affected_url") or "")),
            str(plan.get("role_label") or "").lower(),
            str(plan.get("expected_permission") or "unknown"),
            str(plan.get("test_type") or "custom"),
            str(plan.get("category") or "A01").lower(),
        ]
    )
    return str(abs(hash(raw)))


def render_report_template_markdown(template: dict[str, Any]) -> str:
    steps = "\n".join(f"{index + 1}. {step}" for index, step in enumerate(template.get("Steps to Reproduce Manually") or []))
    limitations = "\n".join(f"- {item}" for item in template.get("Limitations") or [])
    return f"""# {template.get('Title')}

## Summary
{template.get('Summary')}

## Affected Endpoint
{template.get('Affected Endpoint')}

## Affected Role
{template.get('Affected Role')}

## Expected Behaviour
{template.get('Expected Behaviour')}

## Observed Behaviour
{template.get('Observed Behaviour')}

## Impact if Confirmed
{template.get('Impact if Confirmed')}

## Evidence
{template.get('Evidence')}

## Steps to Reproduce Manually
{steps}

## Recommendation
{template.get('Recommendation')}

## Retest Notes
{template.get('Retest Notes')}

## Limitations
{limitations}

## Safe Testing Statement
{template.get('Safe Testing Statement')}
"""


def render_access_test_html(package: dict[str, Any]) -> str:
    summary = package.get("a01_manual_validation_summary") or {}
    plans = package.get("access_control_test_plans") or []
    observations = package.get("access_control_observations") or []
    retests = package.get("access_control_retests") or []
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Access Control Manual Test Planner</title>
<style>body{{font-family:Arial,sans-serif;margin:24px;color:#172033}}table{{border-collapse:collapse;width:100%;margin:12px 0}}td,th{{border:1px solid #d7dce5;padding:8px;text-align:left}}th{{background:#eef2f7}}.note{{background:#f6f8fb;border:1px solid #d7dce5;padding:12px}}</style></head>
<body><h1>Access Control Manual Test Planner</h1>
<p class="note">{SAFE_TESTING_STATEMENT}</p>
<h2>Test Plan Summary</h2><p>Plans: {summary.get('manual_test_plans_count', 0)}. Manually Verified Secure: {summary.get('manually_verified_secure_count', 0)}. Manually Verified Issue: {summary.get('manually_verified_issue_count', 0)}. Retest Passed: {summary.get('retest_passed_count', 0)}. Retest Failed: {summary.get('retest_failed_count', 0)}.</p>
<h2>Planned Tests</h2><table><tr><th>Plan</th><th>Title</th><th>Role</th><th>Endpoint</th><th>Type</th><th>Expected</th><th>Status</th></tr>{''.join(f"<tr><td>{p.get('test_plan_id','')}</td><td>{p.get('title','')}</td><td>{p.get('role_label','')}</td><td>{p.get('affected_url','')}</td><td>{p.get('test_type','')}</td><td>{p.get('expected_permission','')}</td><td>{p.get('validation_status','')}</td></tr>" for p in plans)}</table>
<h2>Expected vs Observed Behaviour</h2><table><tr><th>Plan</th><th>Observed Result</th><th>Status Code</th><th>Summary</th></tr>{''.join(f"<tr><td>{o.get('test_plan_id','')}</td><td>{o.get('observed_access_result','')}</td><td>{o.get('observed_status_code','')}</td><td>{o.get('observed_message_summary','')}</td></tr>" for o in observations)}</table>
<h2>Retest Workflow</h2><table><tr><th>Plan</th><th>Status</th><th>Observed Result</th><th>Notes</th></tr>{''.join(f"<tr><td>{r.get('test_plan_id','')}</td><td>{r.get('retest_status','')}</td><td>{r.get('retest_observed_result','')}</td><td>{r.get('retest_notes','')}</td></tr>" for r in retests)}</table>
</body></html>"""


def _build_plan(
    *,
    test_plan_id: str,
    title: str,
    category: str,
    test_type: str,
    affected_url: str,
    endpoint_category: str,
    role_profile: dict[str, Any],
    expected_permission: str,
    linked_a01_evidence_id: str = "",
    linked_endpoint_id: str = "",
    linked_role_matrix_id: str = "",
    linked_session_profile_id: str = "",
) -> dict[str, Any]:
    if test_type not in TEST_TYPES:
        test_type = "custom"
    normalised = _normalise_url(affected_url)
    plan = A01ManualTestPlan(
        test_plan_id=test_plan_id,
        title=title,
        category=category,
        test_type=test_type,
        target=_target(normalised),
        affected_url=affected_url,
        normalised_url=normalised,
        endpoint_category=endpoint_category,
        role_label=str(role_profile.get("role_label") or role_profile.get("role_name") or ""),
        role_id=str(role_profile.get("role_id") or ""),
        tenant_label=str(role_profile.get("tenant_label") or ""),
        expected_permission=expected_permission,
        expected_secure_behaviour=_expected_behaviour(test_type),
        test_preconditions=_preconditions(test_type),
        manual_steps=manual_steps_for_test_type(test_type),
        evidence_checklist=build_evidence_checklist(test_plan_id),
        observed_behaviour={},
        validation_status="planned",
        risk_if_failed=_risk_if_failed(test_type, role_profile),
        recommendation=_recommendation(test_type),
        safety_notes=_safety_notes(test_type),
        linked_a01_evidence_id=linked_a01_evidence_id,
        linked_endpoint_id=linked_endpoint_id,
        linked_role_matrix_id=linked_role_matrix_id,
        linked_session_profile_id=linked_session_profile_id,
    )
    return redact_nested(plan.to_dict())


def manual_steps_for_test_type(test_type: str) -> list[str]:
    if test_type in {"object_ownership_review", "horizontal_access_control_review"}:
        return [
            "Use authorised test accounts only.",
            "Identify two approved test-owned objects.",
            "Confirm the expected allowed object access works.",
            "Manually verify denied access behaviour for non-owned object using programme-approved test data only.",
            "Record status code, user-facing message, and redacted screenshot/response summary.",
            "Do not access real third-party user data.",
        ]
    if test_type == "tenant_boundary_review":
        return [
            "Use approved test tenants only.",
            "Verify tenant-scoped resource isolation.",
            "Confirm tenant identifiers cannot be used to access another authorised test tenant's data without permission.",
            "Record expected vs observed behaviour.",
            "Avoid production sensitive data.",
        ]
    if test_type in {"vertical_access_control_review", "function_level_authorization_review", "admin_surface_review"}:
        return [
            "Use a lower-privileged authorised test role.",
            "Confirm admin/management function is denied.",
            "Avoid state-changing actions.",
            "Prefer GET/view-only checks where possible.",
            "For destructive actions, document review need instead of executing.",
        ]
    if test_type in {"sensitive_export_review", "file_download_authorization_review"}:
        return [
            "Use test reports/files only.",
            "Verify export/download is limited to authorised records.",
            "Do not download real sensitive customer/user files.",
            "Record filename/path safely if allowed, otherwise use redacted label.",
        ]
    if test_type == "role_permission_review":
        return [
            "Compare expected permission from permission matrix with manual observation.",
            "Use safe labels for accounts and roles.",
            "Do not store credentials.",
        ]
    return ["Use Authorised Test Accounts Only.", "Record Expected Behaviour and Observed Behaviour.", "Capture redacted evidence only."]


def _test_type_from_candidate(item: dict[str, Any]) -> str:
    text = " ".join(str(item.get(key) or "") for key in ("rule_group", "access_control_candidate_type", "title", "affected_url", "affected_parameter")).lower()
    if any(token in text for token in ("object", "idor", "identifier", "id parameter")):
        return "object_ownership_review"
    if any(token in text for token in ("tenant", "workspace", "organisation", "organization", "org")):
        return "tenant_boundary_review"
    if any(token in text for token in ("role", "permission")):
        return "role_permission_review"
    if any(token in text for token in ("admin", "management", "function")):
        return "function_level_authorization_review"
    if any(token in text for token in ("export", "download", "file")):
        return "sensitive_export_review" if "export" in text else "file_download_authorization_review"
    return "custom"


def _test_type_from_action(action: str, endpoint: dict[str, Any]) -> str:
    path = str(endpoint.get("url") or endpoint.get("normalised_url") or "").lower()
    if action in {"manage_users", "manage_roles", "admin"} or "admin" in path:
        return "vertical_access_control_review"
    if action == "export":
        return "sensitive_export_review"
    if action == "download":
        return "file_download_authorization_review"
    if "tenant" in path or "workspace" in path or "/org" in path:
        return "tenant_boundary_review"
    if action in {"delete", "edit", "create", "approve", "reject"}:
        return "function_level_authorization_review"
    return "role_permission_review"


def _role_mapping_row_needs_plan(row: dict[str, Any]) -> bool:
    action = str(row.get("inferred_action") or "")
    endpoint = str(row.get("endpoint") or "").lower()
    return (
        row.get("expected_permission") == "denied"
        or action in {"admin", "manage_users", "manage_roles", "export", "download"}
        or "tenant" in endpoint
        or "id=" in endpoint
    )


def _matching_roles(item: dict[str, Any], roles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    role_label = str(item.get("role_label") or "").lower()
    if role_label:
        matches = [role for role in roles if role_label in {str(role.get("role_label") or "").lower(), str(role.get("role_id") or "").lower()}]
        if matches:
            return matches
    return roles or [{}]


def _permission_rule_for(role: dict[str, Any], item: dict[str, Any], matrix: dict[str, Any]) -> dict[str, Any]:
    role_id = str(role.get("role_id") or "")
    expected_action = str(item.get("action_id") or item.get("inferred_action") or "")
    for rule in matrix.get("role_action_rules") or []:
        if str(rule.get("role_id") or "") == role_id and (not expected_action or str(rule.get("action_id") or "") == expected_action):
            return rule
    return {}


def _expected_behaviour(test_type: str) -> str:
    mapping = {
        "object_ownership_review": "User can access only objects they own or are explicitly authorised to access.",
        "horizontal_access_control_review": "User can access only objects they own or are explicitly authorised to access.",
        "vertical_access_control_review": "Only roles with explicit authorization can access this function.",
        "function_level_authorization_review": "Only roles with explicit authorization can access this function.",
        "admin_surface_review": "Only roles with explicit authorization can access this function.",
        "tenant_boundary_review": "Users cannot access resources outside their assigned tenant/workspace.",
        "sensitive_export_review": "User can export/download only authorised data.",
        "file_download_authorization_review": "User can export/download only authorised data.",
        "role_permission_review": "Client-controlled role or permission parameters must not override server-side authorization.",
    }
    return mapping.get(test_type, "Expected Behaviour must be documented before manual validation.")


def _preconditions(test_type: str) -> list[str]:
    return ["Authorised Test Accounts Only.", "Assessment scope has been approved.", f"Manual Validation Required for {test_type.replace('_', ' ')}."]


def _risk_if_failed(test_type: str, role: dict[str, Any]) -> str:
    tenant = str(role.get("tenant_label") or "")
    if test_type == "tenant_boundary_review" and tenant:
        return f"Potential Tenant Boundary Review issue if the {tenant} role can reach resources outside its assigned tenant/workspace."
    if test_type in {"vertical_access_control_review", "function_level_authorization_review", "admin_surface_review"}:
        return "Potential Function-Level Authorization Review issue if roles without explicit authorization can use the function."
    if test_type in {"object_ownership_review", "horizontal_access_control_review"}:
        return "Potential Object Ownership Review issue if users can access objects they do not own or are not authorised to access."
    if test_type in {"sensitive_export_review", "file_download_authorization_review"}:
        return "Potential sensitive data exposure if export/download is not limited to authorised data."
    return "Potential A01 access-control issue if Observed Behaviour differs from Expected Behaviour."


def _recommendation(test_type: str) -> str:
    if test_type == "tenant_boundary_review":
        return "Enforce tenant/workspace authorization server-side and validate tenant context on every request."
    if test_type in {"vertical_access_control_review", "function_level_authorization_review", "admin_surface_review"}:
        return "Enforce server-side role and permission checks for the function."
    if test_type in {"object_ownership_review", "horizontal_access_control_review"}:
        return "Enforce object ownership and explicit authorization checks server-side."
    if test_type in {"sensitive_export_review", "file_download_authorization_review"}:
        return "Limit export/download operations to authorised records and redact sensitive output where appropriate."
    return "Align implementation with the documented Access-Control Matrix and validate manually."


def _safety_notes(test_type: str) -> list[str]:
    notes = [SAFE_TESTING_STATEMENT, "Do not submit forms automatically.", "Do not perform state-changing requests automatically.", "Capture redacted evidence only."]
    if test_type in {"admin_surface_review", "function_level_authorization_review", "vertical_access_control_review"}:
        notes.append("For destructive or administrative actions, document review need instead of executing.")
    return notes


def _summary_text(plan: dict[str, Any], is_issue: bool) -> str:
    if is_issue:
        return f"Manual validation recorded Observed Behaviour that differs from Expected Behaviour for {plan.get('role_label') or 'the tested role'}."
    return f"Candidate A01 Manual Validation Plan for {plan.get('role_label') or 'the tested role'}. Manual validation is required before reporting confirmed impact."


def _title_for_type(test_type: str) -> str:
    return test_type.replace("_", " ").title()


def _normalise_url(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    if parsed.scheme and parsed.netloc:
        return parsed.geturl()
    return str(url or "")


def _target(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    return parsed.netloc or parsed.path or ""


def _resolve_access_test_path(path: str | Path) -> Path:
    candidate = Path(path)
    resolved = candidate if candidate.is_absolute() else Path.cwd() / candidate
    root = (Path.cwd() / ACCESS_TESTS_DIR).resolve()
    resolved = resolved.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise AccessControlTestPlannerError("Access Control Manual Test Planner files must be under data/access_control_tests.") from exc
    return resolved
