"""Access-Control Matrix construction and endpoint-to-action inference."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from scanner.evidence import redact_nested
from scanner.permission_matrix import (
    STATE_CHANGING_METHODS,
    action_by_type_or_id,
    default_permission_actions,
    expected_permission_for,
    permission_matrix_summary,
)
from scanner.role_profiles import ROLE_REPORTS_DIR, role_profiles_summary


LIMITATIONS = [
    "Role and Permission Mapping is a planning and documentation assistant.",
    "VulScan does not perform automatic role comparison, account-to-account requests, or state-changing access checks.",
    "Endpoint-to-action mapping is inference only and requires manual validation.",
]


def infer_action_from_endpoint(endpoint_result: dict[str, Any]) -> dict[str, Any]:
    item = dict(endpoint_result or {})
    url = str(item.get("normalised_url") or item.get("url") or item.get("affected_url") or item.get("endpoint") or item.get("path") or "")
    method = str(item.get("method") or item.get("http_method") or item.get("method_hint") or "GET").upper()
    parsed = urlsplit(url)
    path = (parsed.path or url or "/").lower()
    category = str(item.get("endpoint_category") or item.get("category") or "").lower()
    tokens = f"{path} {category}"

    action_type = "view"
    if "admin/users" in tokens or "users" in tokens and "admin" in tokens:
        action_type = "manage_users"
    elif "admin" in tokens:
        action_type = "admin"
    elif "roles" in tokens or "permissions" in tokens:
        action_type = "manage_roles"
    elif "billing" in tokens or "payment" in tokens or "invoice" in tokens:
        action_type = "billing"
    elif "export" in tokens:
        action_type = "export"
    elif "import" in tokens:
        action_type = "import"
    elif "upload" in tokens:
        action_type = "upload"
    elif "download" in tokens:
        action_type = "download"
    elif "delete" in tokens or "remove" in tokens or method == "DELETE":
        action_type = "delete"
    elif "approve" in tokens:
        action_type = "approve"
    elif "reject" in tokens:
        action_type = "reject"
    elif "settings" in tokens or "edit" in tokens or "update" in tokens:
        action_type = "edit"
    elif method == "POST":
        action_type = "create"
    elif method in {"PUT", "PATCH"}:
        action_type = "edit"
    elif "login" in tokens or "signin" in tokens or "auth" in tokens:
        action_type = "authentication"

    action = action_by_type_or_id(action_type, default_permission_actions())
    state_changing = bool(action.get("state_changing")) or method in STATE_CHANGING_METHODS
    destructive = bool(action.get("destructive")) or action_type == "delete" or method == "DELETE"
    return redact_nested(
        {
            "endpoint": url,
            "method": method,
            "inferred_action": action_type,
            "action_id": action.get("action_id") or action_type,
            "action_name": action.get("action_name") or action_type.replace("_", " ").title(),
            "sensitivity": action.get("sensitivity") or ("critical" if destructive else "medium"),
            "state_changing": state_changing,
            "destructive": destructive,
            "requires_manual_validation": True,
            "inference_reason": _reason(action_type, path, method),
            "source": item.get("source") or item.get("input_source") or "endpoint_results",
            "role_label": item.get("role_label") or "",
            "auth_required_likely": bool(item.get("auth_required_likely")),
            "endpoint_category": item.get("endpoint_category") or item.get("category") or "",
        }
    )


def map_endpoints_to_actions(endpoint_results: list[dict[str, Any]], permission_actions: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    actions = permission_actions or default_permission_actions()
    rows: list[dict[str, Any]] = []
    for endpoint in endpoint_results or []:
        inferred = infer_action_from_endpoint(endpoint)
        configured = action_by_type_or_id(str(inferred.get("inferred_action") or "view"), actions)
        inferred.update(
            {
                "action_id": configured.get("action_id") or inferred.get("action_id"),
                "action_name": configured.get("action_name") or inferred.get("action_name"),
                "sensitivity": configured.get("sensitivity") or inferred.get("sensitivity"),
                "state_changing": bool(configured.get("state_changing")) or bool(inferred.get("state_changing")),
                "destructive": bool(configured.get("destructive")) or bool(inferred.get("destructive")),
                "requires_manual_validation": True,
            }
        )
        rows.append(redact_nested(inferred))
    return rows


def build_role_endpoint_matrix(
    roles: list[dict[str, Any]],
    endpoint_results: list[dict[str, Any]],
    permission_matrix: dict[str, Any],
) -> list[dict[str, Any]]:
    actions = permission_matrix.get("actions") or default_permission_actions()
    endpoint_actions = map_endpoints_to_actions(endpoint_results, actions)
    rows: list[dict[str, Any]] = []
    for role in roles or []:
        role_id = str(role.get("role_id") or "")
        for mapping in endpoint_actions:
            expected, status, notes = expected_permission_for(role_id, str(mapping.get("action_id") or ""), permission_matrix)
            manual_plan = build_role_manual_validation_plan(role, mapping, expected)
            rows.append(
                redact_nested(
                    {
                        "role_id": role_id,
                        "role_label": role.get("role_label") or role.get("role_name") or role_id,
                        "tenant_label": role.get("tenant_label") or "",
                        "endpoint": mapping.get("endpoint"),
                        "method": mapping.get("method"),
                        "action_id": mapping.get("action_id"),
                        "inferred_action": mapping.get("inferred_action"),
                        "sensitivity": mapping.get("sensitivity"),
                        "state_changing": mapping.get("state_changing"),
                        "destructive": mapping.get("destructive"),
                        "expected_permission": expected,
                        "validation_status": status,
                        "permission_notes": notes,
                        "manual_validation_required": True,
                        "manual_plan_id": manual_plan["plan_id"],
                    }
                )
            )
    return rows


def build_role_manual_validation_plan(role_profile: dict[str, Any], endpoint_result: dict[str, Any], expected_permission: str) -> dict[str, Any]:
    inferred = endpoint_result if endpoint_result.get("inferred_action") else infer_action_from_endpoint(endpoint_result)
    role_label = str(role_profile.get("role_label") or role_profile.get("role_name") or role_profile.get("role_id") or "role")
    endpoint = str(inferred.get("endpoint") or inferred.get("url") or inferred.get("normalised_url") or "")
    action = str(inferred.get("inferred_action") or inferred.get("action_id") or "view")
    denied = expected_permission == "denied"
    destructive = bool(inferred.get("destructive"))
    state_changing = bool(inferred.get("state_changing"))
    return redact_nested(
        {
            "plan_id": f"manual_plan_{uuid4().hex[:12]}",
            "role_label": role_label,
            "tenant_label": role_profile.get("tenant_label") or "",
            "endpoint": endpoint,
            "inferred_action": action,
            "expected_permission": expected_permission,
            "safe_manual_steps": _manual_steps(denied=denied, state_changing=state_changing, destructive=destructive),
            "expected_secure_result": _expected_secure_result(expected_permission, action),
            "evidence_to_collect": [
                "Redacted screenshot or response metadata showing the endpoint and role label.",
                "Timestamp, environment label, and authorised test account label.",
                "Expected Permission and Manual Validation Required status.",
                "For denied actions, evidence that access is blocked without changing state.",
            ],
            "risk_if_failed": _risk_if_failed(expected_permission, action, role_profile),
            "safety_notes": [
                "Authorised Test Accounts Only.",
                "Use test/staging data where possible.",
                "Do not access real user data.",
                "Do not perform destructive actions.",
                "Capture redacted evidence only.",
            ],
            "status": "planned",
            "manual_validation_required": True,
        }
    )


def build_role_comparison_note(
    role_a: str,
    role_b: str,
    endpoint: str,
    action: str,
    expected_difference: str,
    observed_result_manual: str = "",
    evidence_id: str | None = None,
    status: str = "planned",
    notes: str = "",
) -> dict[str, Any]:
    if status not in {"planned", "manually_verified", "needs_review", "not_applicable"}:
        status = "needs_review"
    return redact_nested(
        {
            "comparison_id": f"role_compare_{uuid4().hex[:12]}",
            "role_a": role_a,
            "role_b": role_b,
            "endpoint": endpoint,
            "action": action,
            "expected_difference": expected_difference,
            "observed_result_manual": observed_result_manual,
            "evidence_id": evidence_id,
            "status": status,
            "notes": notes,
        }
    )


def build_access_control_matrix_package(
    roles: list[dict[str, Any]],
    permission_matrix: dict[str, Any],
    endpoint_results: list[dict[str, Any]],
) -> dict[str, Any]:
    inferred = map_endpoints_to_actions(endpoint_results, permission_matrix.get("actions") or [])
    role_endpoint_matrix = build_role_endpoint_matrix(roles, endpoint_results, permission_matrix)
    plans = [
        build_role_manual_validation_plan(role, mapping, expected_permission_for(str(role.get("role_id") or ""), str(mapping.get("action_id") or ""), permission_matrix)[0])
        for role in roles or []
        for mapping in inferred
    ]
    summary = {
        "enabled": True,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "role_count": len(roles or []),
        "endpoint_count": len(endpoint_results or []),
        "role_endpoint_rows": len(role_endpoint_matrix),
        "manual_validation_plan_count": len(plans),
        "high_value_manual_candidates": sum(1 for row in role_endpoint_matrix if row.get("expected_permission") == "denied" or row.get("sensitivity") in {"high", "critical"}),
        "tenant_boundary_candidate_count": sum(1 for row in role_endpoint_matrix if row.get("tenant_label") and "tenant" in str(row.get("endpoint") or "").lower()),
        "admin_review_candidate_count": sum(1 for row in role_endpoint_matrix if row.get("inferred_action") in {"admin", "manage_users", "manage_roles"}),
        "limitations": LIMITATIONS,
    }
    return redact_nested(
        {
            "role_mapping_summary": summary,
            "role_profiles": roles or [],
            "permission_matrix_summary": permission_matrix_summary(permission_matrix),
            "permission_matrix": permission_matrix,
            "inferred_actions": inferred,
            "endpoint_action_mappings": inferred,
            "role_endpoint_matrix": role_endpoint_matrix,
            "manual_validation_plans": plans,
            "role_comparison_notes": [],
            "safety_notes": LIMITATIONS,
        }
    )


def save_role_mapping_reports(package: dict[str, Any], *, json_report: bool = False, html_report: bool = False) -> tuple[Path | None, Path | None]:
    ROLE_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    json_path: Path | None = None
    html_path: Path | None = None
    if json_report:
        json_path = ROLE_REPORTS_DIR / f"role_mapping_{stamp}.json"
        json_path.write_text(json.dumps(redact_nested(package), indent=2), encoding="utf-8")
    if html_report:
        html_path = ROLE_REPORTS_DIR / f"role_mapping_{stamp}.html"
        html_path.write_text(_html(package), encoding="utf-8")
    return json_path, html_path


def role_endpoint_map_from_authenticated_crawl(crawl_result: dict[str, Any]) -> dict[str, Any]:
    summary = crawl_result.get("authenticated_crawl_summary") or {}
    role_label = str(summary.get("role_label") or "")
    endpoints = crawl_result.get("authenticated_crawl_results") or []
    inferred = map_endpoints_to_actions(endpoints)
    return redact_nested(
        {
            "enabled": True,
            "role_label": role_label,
            "endpoints_discovered": len(endpoints),
            "inferred_actions": inferred,
            "manual_validation_needs": [item for item in inferred if item.get("requires_manual_validation")],
            "limitations": ["Authenticated Crawl endpoints are linked to the role label only. No automatic role comparison is performed."],
        }
    )


def _manual_steps(*, denied: bool, state_changing: bool, destructive: bool) -> list[str]:
    steps = [
        "Confirm the role profile and safe test account label are authorised for this assessment.",
        "Open the endpoint manually in the approved test environment.",
    ]
    if denied:
        steps.append("Verify access is blocked without changing state or attempting to force the action.")
    elif destructive:
        steps.append("Do not execute the destructive action; validate using read-only UI indicators, staging safeguards, or owner-approved screenshots.")
    elif state_changing:
        steps.append("Do not submit forms or commit changes unless the assessment owner has approved the exact test data and action.")
    else:
        steps.append("Verify the expected page or data is visible only for the intended role.")
    steps.append("Record redacted evidence and mark validation status manually.")
    return steps


def _expected_secure_result(expected_permission: str, action: str) -> str:
    if expected_permission == "denied":
        return f"{action} is blocked for the role with an appropriate access-control response and no state change."
    if expected_permission == "allowed":
        return f"{action} is available only within the role's documented authorisation boundary."
    if expected_permission == "conditional":
        return f"{action} is available only when documented business conditions are satisfied."
    return f"{action} requires Manual Validation Required before any conclusion is recorded."


def _risk_if_failed(expected_permission: str, action: str, role_profile: dict[str, Any]) -> str:
    tenant = str(role_profile.get("tenant_label") or "")
    if expected_permission == "denied":
        if tenant:
            return f"Potential tenant boundary weakness if {action} is available outside the documented {tenant} role boundary."
        return f"Potential function-level authorization weakness if {action} is available to this role."
    return f"Potential role permission mismatch if observed behaviour differs from the Access-Control Matrix for {action}."


def _reason(action_type: str, path: str, method: str) -> str:
    return f"Inferred {action_type} from {method} {path or '/'} using path keywords and HTTP method metadata."


def _html(package: dict[str, Any]) -> str:
    summary = package.get("role_mapping_summary") or {}
    roles = package.get("role_profiles") or []
    rows = package.get("role_endpoint_matrix") or []
    plans = package.get("manual_validation_plans") or []
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Role and Permission Mapping</title>
<style>body{{font-family:Arial,sans-serif;margin:24px;color:#172033}}table{{border-collapse:collapse;width:100%;margin:12px 0}}td,th{{border:1px solid #d7dce5;padding:8px;text-align:left}}th{{background:#eef2f7}}.note{{background:#f6f8fb;border:1px solid #d7dce5;padding:12px}}</style></head>
<body><h1>Role and Permission Mapping</h1>
<p class="note">Role mapping is a planning and documentation assistant. VulScan does not perform automatic role comparison, account-to-account requests, or state-changing access checks.</p>
<h2>Summary</h2><p>Roles: {summary.get('role_count', 0)}. Endpoints: {summary.get('endpoint_count', 0)}. Manual Validation Plans: {summary.get('manual_validation_plan_count', 0)}.</p>
<h2>Role Profiles</h2><table><tr><th>Role</th><th>User Type</th><th>Tenant</th><th>Access Level</th></tr>{''.join(f"<tr><td>{r.get('role_label','')}</td><td>{r.get('user_type','')}</td><td>{r.get('tenant_label','') or ''}</td><td>{r.get('expected_access_level','')}</td></tr>" for r in roles)}</table>
<h2>Role Endpoint Matrix</h2><table><tr><th>Role</th><th>Endpoint</th><th>Action</th><th>Expected</th><th>Status</th></tr>{''.join(f"<tr><td>{r.get('role_label','')}</td><td>{r.get('endpoint','')}</td><td>{r.get('inferred_action','')}</td><td>{r.get('expected_permission','')}</td><td>{r.get('validation_status','')}</td></tr>" for r in rows)}</table>
<h2>Manual Validation Plans</h2><table><tr><th>Plan</th><th>Role</th><th>Endpoint</th><th>Expected Secure Result</th></tr>{''.join(f"<tr><td>{p.get('plan_id','')}</td><td>{p.get('role_label','')}</td><td>{p.get('endpoint','')}</td><td>{p.get('expected_secure_result','')}</td></tr>" for p in plans)}</table>
</body></html>"""
