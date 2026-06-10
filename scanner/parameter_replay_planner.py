"""Safe Authenticated Parameter Replay Planner.

The planner creates local manual validation records only. It never sends replay
requests, mutates parameters, submits forms, or compares live accounts.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

from scanner.evidence import redact_nested
from scanner.parameter_review_workflow import (
    SAFE_TESTING_STATEMENT,
    build_report_ready_replay_template,
    build_replay_evidence_checklist,
    observation_to_validation_status,
    render_report_template_markdown,
    retest_summary,
)
from scanner.request_template_builder import build_redacted_request_template, normalise_url_path_ids


PARAMETER_REPLAY_DIR = Path("data") / "parameter_replay"
PARAMETER_REPLAY_REPORTS_DIR = Path("reports") / "parameter_replay"
PARAMETER_LOCATIONS = {"query", "path", "form", "header_name_only", "cookie_name_only", "json_body_schema_only", "unknown"}
PARAMETER_TYPES = {
    "object_identifier",
    "tenant_identifier",
    "role_permission",
    "auth_session",
    "search_query",
    "callback_url",
    "redirect_uri",
    "file_reference",
    "export_identifier",
    "csrf_state_nonce",
    "filter_sort",
    "generic",
}
REPLAY_INTENTS = {
    "object_ownership_review",
    "tenant_boundary_review",
    "role_permission_review",
    "reflection_context_review",
    "auth_session_review",
    "redirect_callback_review",
    "export_download_review",
    "input_validation_review",
    "manual_review",
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


class ParameterReplayPlannerError(ValueError):
    """Raised when parameter replay planning data is invalid."""


@dataclass
class ParameterReplayPlan:
    replay_plan_id: str
    title: str
    target: str
    affected_url: str
    normalised_url: str
    method: str
    endpoint_category: str
    parameter_name: str
    parameter_location: str
    parameter_type: str
    related_owasp_categories: list[str]
    role_label: str = ""
    expected_permission: str = "unknown"
    replay_intent: str = "manual_review"
    manual_steps: list[str] = field(default_factory=list)
    safe_request_template_id: str = ""
    expected_secure_behaviour: str = ""
    observed_behaviour: dict[str, Any] = field(default_factory=dict)
    validation_status: str = "planned"
    evidence_checklist: dict[str, Any] = field(default_factory=dict)
    retest_status: str = "not_started"
    safety_notes: list[str] = field(default_factory=list)
    linked_a01_plan_id: str = ""
    linked_a05_evidence_id: str = ""
    linked_a07_evidence_id: str = ""
    linked_endpoint_id: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def ensure_parameter_replay_dirs() -> None:
    PARAMETER_REPLAY_DIR.mkdir(parents=True, exist_ok=True)
    PARAMETER_REPLAY_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (PARAMETER_REPLAY_REPORTS_DIR / "templates").mkdir(parents=True, exist_ok=True)
    (PARAMETER_REPLAY_REPORTS_DIR / "evidence").mkdir(parents=True, exist_ok=True)


def build_replay_plan_from_parameter(
    parameter_result: dict[str, Any],
    endpoint_result: dict[str, Any] | None = None,
    role_profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    endpoint = endpoint_result or {}
    parameter = parameter_result or {}
    name = str(parameter.get("parameter_name") or parameter.get("name") or parameter.get("parameter") or "")
    if not name:
        raise ParameterReplayPlannerError("Replay Plan requires parameter_name.")
    affected_url = str(endpoint.get("url") or endpoint.get("affected_url") or parameter.get("url") or parameter.get("affected_url") or "")
    method = str(endpoint.get("method") or parameter.get("method") or "GET").upper()
    endpoint_category = str(endpoint.get("endpoint_category") or parameter.get("endpoint_category") or _endpoint_category(affected_url))
    parameter_type = classify_parameter_type(name, endpoint_category, parameter)
    intent = str(parameter.get("replay_intent") or classify_replay_intent(name, endpoint_category, parameter))
    categories = _related_categories(intent, parameter, endpoint)
    role = role_profile or {}
    template = build_redacted_request_template(endpoint or {"url": affected_url, "method": method}, parameter, role.get("auth_context_summary") if isinstance(role, dict) else None)
    plan_id = str(parameter.get("replay_plan_id") or f"replay_plan_{uuid4().hex[:12]}")
    plan = ParameterReplayPlan(
        replay_plan_id=plan_id,
        title=f"{intent.replace('_', ' ').title()}: {name}",
        target=_target(affected_url),
        affected_url=affected_url,
        normalised_url=normalise_url_path_ids(affected_url),
        method=method,
        endpoint_category=endpoint_category,
        parameter_name=name,
        parameter_location=_parameter_location(name, affected_url, parameter),
        parameter_type=parameter_type,
        related_owasp_categories=categories,
        role_label=str(role.get("role_label") or role.get("role_name") or parameter.get("role_label") or ""),
        expected_permission=str(parameter.get("expected_permission") or endpoint.get("expected_permission") or "unknown"),
        replay_intent=intent if intent in REPLAY_INTENTS else "manual_review",
        manual_steps=manual_steps_for_intent(intent),
        safe_request_template_id=str(template.get("template_id") or ""),
        expected_secure_behaviour=expected_secure_behaviour(intent),
        observed_behaviour={},
        validation_status="planned",
        evidence_checklist=build_replay_evidence_checklist(plan_id),
        retest_status="not_started",
        safety_notes=safety_notes_for_intent(intent),
        linked_a01_plan_id=str(parameter.get("linked_a01_plan_id") or endpoint.get("linked_a01_plan_id") or ""),
        linked_a05_evidence_id=str(parameter.get("linked_a05_evidence_id") or endpoint.get("linked_a05_evidence_id") or ""),
        linked_a07_evidence_id=str(parameter.get("linked_a07_evidence_id") or endpoint.get("linked_a07_evidence_id") or ""),
        linked_endpoint_id=str(endpoint.get("endpoint_id") or parameter.get("linked_endpoint_id") or ""),
    )
    result = plan.to_dict()
    result["redacted_request_template"] = template
    return redact_nested(result)


def build_replay_plans_from_candidates(
    parameter_results: list[dict[str, Any]],
    endpoint_results: list[dict[str, Any]] | None = None,
    a01_evidence: list[dict[str, Any]] | None = None,
    a05_evidence: list[dict[str, Any]] | None = None,
    a07_evidence: list[dict[str, Any]] | None = None,
    roles: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    endpoints = endpoint_results or []
    plans: list[dict[str, Any]] = []
    seen: set[str] = set()
    for parameter in parameter_results or []:
        endpoint = _match_endpoint(parameter, endpoints)
        enriched = dict(parameter)
        _attach_related_evidence(enriched, a01_evidence or [], a05_evidence or [], a07_evidence or [])
        role_candidates = roles or [{}]
        for role in role_candidates:
            plan = build_replay_plan_from_parameter(enriched, endpoint, role)
            fp = replay_plan_fingerprint(plan)
            if fp in seen:
                continue
            seen.add(fp)
            plans.append(plan)
    return plans


def classify_replay_intent(parameter_name: str, endpoint_category: str = "", related_evidence: dict[str, Any] | None = None) -> str:
    name = str(parameter_name or "").lower()
    text = f"{name} {endpoint_category} {json.dumps(related_evidence or {}, sort_keys=True)}".lower()
    if name in {"id", "user_id", "account_id", "order_id", "invoice_id", "document_id", "file_id"}:
        return "export_download_review" if any(token in text for token in ("export", "download", "file")) else "object_ownership_review"
    if name in {"tenant_id", "org_id", "workspace_id", "project_id", "team_id"}:
        return "tenant_boundary_review"
    if name in {"role", "permission", "is_admin", "access_level", "scope"}:
        return "role_permission_review"
    if name in {"q", "search", "query", "comment", "message", "title"}:
        return "reflection_context_review" if name in {"comment", "message", "title"} else "input_validation_review"
    if name in {"redirect_uri", "return_url", "callback_url", "next", "url"}:
        return "redirect_callback_review"
    if name in {"csrf", "state", "nonce", "token", "session"} or any(token in name for token in ("csrf", "nonce", "token", "session")):
        return "auth_session_review"
    if name in {"report_id", "export_id", "download"} or "download" in text or "export" in text:
        return "export_download_review"
    return "manual_review"


def classify_parameter_type(parameter_name: str, endpoint_category: str = "", related_evidence: dict[str, Any] | None = None) -> str:
    intent = classify_replay_intent(parameter_name, endpoint_category, related_evidence)
    mapping = {
        "object_ownership_review": "object_identifier",
        "tenant_boundary_review": "tenant_identifier",
        "role_permission_review": "role_permission",
        "reflection_context_review": "search_query",
        "input_validation_review": "search_query",
        "redirect_callback_review": "redirect_uri" if str(parameter_name).lower() == "redirect_uri" else "callback_url",
        "auth_session_review": "csrf_state_nonce" if str(parameter_name).lower() in {"csrf", "state", "nonce"} else "auth_session",
        "export_download_review": "export_identifier" if "export" in str(parameter_name).lower() else "file_reference",
    }
    return mapping.get(intent, "generic")


def manual_steps_for_intent(intent: str) -> list[str]:
    mapping = {
        "object_ownership_review": [
            "Use authorised test accounts only.",
            "Confirm original object belongs to approved test account.",
            "Prepare approved alternate test object only if programme allows.",
            "Manually verify access control without accessing real third-party data.",
            "Record expected vs observed behaviour.",
            "Redact identifiers in evidence.",
        ],
        "tenant_boundary_review": [
            "Use approved test tenants only.",
            "Verify tenant identifiers cannot cross boundaries.",
            "Do not access live third-party tenant data.",
            "Record safe labels, not real tenant data.",
        ],
        "role_permission_review": [
            "Use authorised role-specific test account.",
            "Verify server-side authorization ignores client-controlled permission/role fields.",
            "Do not change permissions or roles automatically.",
            "Avoid state-changing requests.",
        ],
        "reflection_context_review": [
            "Use harmless markers only if programme allows.",
            "Do not use exploit payloads.",
            "Review output encoding/context manually.",
            "Record reflection context safely.",
        ],
        "input_validation_review": [
            "Use harmless markers only if programme allows.",
            "Do not use exploit payloads.",
            "Review validation behaviour manually.",
            "Record parameter effect safely.",
        ],
        "auth_session_review": [
            "Review CSRF/state/nonce handling manually.",
            "Do not replay expired or stolen sessions.",
            "Do not bypass auth controls.",
            "Do not store token values.",
        ],
        "redirect_callback_review": [
            "Review allowlist and state validation manually.",
            "Do not test SSRF.",
            "Do not trigger third-party callbacks.",
            "Use approved local callback domains only if explicitly allowed.",
        ],
        "export_download_review": [
            "Use safe test files/reports only.",
            "Do not download real sensitive data.",
            "Confirm ownership/authorization checks manually.",
        ],
    }
    return mapping.get(intent, ["Use Authorised Test Accounts Only.", "Record Expected Behaviour and Observed Behaviour.", "Capture redacted evidence only."])


def expected_secure_behaviour(intent: str) -> str:
    mapping = {
        "object_ownership_review": "Only authorised owners or explicitly permitted users can access the referenced object.",
        "tenant_boundary_review": "Tenant, organisation, workspace, or project identifiers cannot cross authorised boundaries.",
        "role_permission_review": "Server-side authorization ignores client-controlled role or permission parameters.",
        "reflection_context_review": "User-controlled text is encoded or handled safely in its output context.",
        "input_validation_review": "Input is validated server-side and harmless invalid values are handled safely.",
        "auth_session_review": "CSRF, state, nonce, token, and session controls are validated without exposing raw values.",
        "redirect_callback_review": "Redirect and callback parameters are allowlisted and bound to expected state.",
        "export_download_review": "Exports and downloads are limited to authorised test-owned records.",
    }
    return mapping.get(intent, "Expected Behaviour must be documented before manual validation.")


def safety_notes_for_intent(intent: str) -> list[str]:
    notes = [
        SAFE_TESTING_STATEMENT,
        "No Automatic Replay.",
        "Do not mutate parameters automatically.",
        "Do not submit forms automatically.",
        "Do not store raw credentials, raw cookies, bearer tokens, passwords, CSRF values, or session tokens.",
    ]
    if intent in {"auth_session_review", "redirect_callback_review"}:
        notes.append("Use Redacted Auth Context only.")
    return notes


def build_parameter_replay_summary(
    plans: list[dict[str, Any]] | None = None,
    observations: list[dict[str, Any]] | None = None,
    retests: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    observed_statuses = {str(item.get("replay_plan_id")): observation_to_validation_status(item) for item in observations or []}
    statuses = [observed_statuses.get(str(plan.get("replay_plan_id")), str(plan.get("validation_status") or "planned")) for plan in plans or []]
    retest_counts = retest_summary(retests or [])
    return {
        "enabled": True,
        "replay_plans_count": len(plans or []),
        "planned_count": statuses.count("planned"),
        "in_progress_count": statuses.count("in_progress"),
        "manually_verified_secure_count": statuses.count("manually_verified_secure"),
        "manually_verified_issue_count": statuses.count("manually_verified_issue"),
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


def replay_plan_fingerprint(plan: dict[str, Any]) -> str:
    raw = "|".join(
        [
            normalise_url_path_ids(str(plan.get("normalised_url") or plan.get("affected_url") or "")).lower(),
            str(plan.get("parameter_name") or "").lower(),
            str(plan.get("replay_intent") or "manual_review").lower(),
            str(plan.get("role_label") or "").lower(),
            ",".join(sorted(str(item) for item in plan.get("related_owasp_categories") or [])).lower(),
            str(plan.get("method") or "GET").upper(),
        ]
    )
    return str(abs(hash(raw)))


def load_replay_plans(path: str | Path = PARAMETER_REPLAY_DIR / "sample_replay_plan.json") -> dict[str, Any]:
    plan_path = _resolve_parameter_replay_path(path)
    try:
        payload = json.loads(plan_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ParameterReplayPlannerError(f"Replay Plan file was not found: {plan_path}") from exc
    except json.JSONDecodeError as exc:
        raise ParameterReplayPlannerError(f"Replay Plan file is not valid JSON: {plan_path}") from exc
    plans = payload.get("parameter_replay_plans") or payload.get("replay_plans") or []
    templates = payload.get("redacted_request_templates") or []
    observations = payload.get("parameter_replay_observations") or []
    retests = payload.get("parameter_replay_retests") or []
    return redact_nested(
        {
            "parameter_replay_plans": plans,
            "redacted_request_templates": templates,
            "parameter_replay_observations": observations,
            "parameter_replay_retests": retests,
            "parameter_replay_summary": build_parameter_replay_summary(plans, observations, retests),
        }
    )


def find_replay_plan(plans: list[dict[str, Any]], plan_id: str) -> dict[str, Any]:
    for plan in plans or []:
        if str(plan.get("replay_plan_id") or "") == str(plan_id):
            return plan
    raise ParameterReplayPlannerError(f"Replay Plan was not found: {plan_id}")


def save_replay_plan_package(package: dict[str, Any], *, json_report: bool = False, html_report: bool = False) -> tuple[Path | None, Path | None]:
    ensure_parameter_replay_dirs()
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    json_path: Path | None = None
    html_path: Path | None = None
    if json_report:
        json_path = PARAMETER_REPLAY_REPORTS_DIR / f"replay_plans_{stamp}.json"
        json_path.write_text(json.dumps(redact_nested(package), indent=2), encoding="utf-8")
    if html_report:
        html_path = PARAMETER_REPLAY_REPORTS_DIR / f"replay_plans_{stamp}.html"
        html_path.write_text(render_replay_plan_html(package), encoding="utf-8")
    return json_path, html_path


def render_replay_plan_html(package: dict[str, Any]) -> str:
    summary = package.get("parameter_replay_summary") or {}
    plans = package.get("parameter_replay_plans") or []
    templates = package.get("redacted_request_templates") or []
    observations = package.get("parameter_replay_observations") or []
    retests = package.get("parameter_replay_retests") or []
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Safe Authenticated Parameter Replay Planner</title>
<style>body{{font-family:Arial,sans-serif;margin:24px;color:#172033}}table{{border-collapse:collapse;width:100%;margin:12px 0}}td,th{{border:1px solid #d7dce5;padding:8px;text-align:left}}th{{background:#eef2f7}}.note{{background:#f6f8fb;border:1px solid #d7dce5;padding:12px}}</style></head>
<body><h1>Safe Authenticated Parameter Replay Planner</h1>
<p class="note">{SAFE_TESTING_STATEMENT}</p>
<h2>Replay Plan Summary</h2><p>Plans: {summary.get('replay_plans_count', 0)}. Manually Verified Secure: {summary.get('manually_verified_secure_count', 0)}. Manually Verified Issue: {summary.get('manually_verified_issue_count', 0)}. Retest Passed: {summary.get('retest_passed_count', 0)}. Retest Failed: {summary.get('retest_failed_count', 0)}.</p>
<h2>Replay Plans</h2><table><tr><th>Plan</th><th>Endpoint</th><th>Parameter</th><th>Intent</th><th>Role</th><th>OWASP</th><th>Status</th></tr>{''.join(f"<tr><td>{p.get('replay_plan_id','')}</td><td>{p.get('affected_url','')}</td><td>{p.get('parameter_name','')}</td><td>{p.get('replay_intent','')}</td><td>{p.get('role_label','')}</td><td>{', '.join(p.get('related_owasp_categories') or [])}</td><td>{p.get('validation_status','')}</td></tr>" for p in plans)}</table>
<h2>Redacted Request Templates</h2><table><tr><th>Template</th><th>Method</th><th>URL Template</th><th>State Changing</th><th>Destructive</th><th>Warnings</th></tr>{''.join(f"<tr><td>{t.get('template_id','')}</td><td>{t.get('method','')}</td><td>{t.get('url_template','')}</td><td>{t.get('state_changing','')}</td><td>{t.get('destructive','')}</td><td>{'; '.join(t.get('warnings') or [])}</td></tr>" for t in templates)}</table>
<h2>Expected vs Observed Behaviour</h2><table><tr><th>Plan</th><th>Observed Result</th><th>Status Code</th><th>Summary</th><th>Redaction</th></tr>{''.join(f"<tr><td>{o.get('replay_plan_id','')}</td><td>{o.get('observed_access_result','')}</td><td>{o.get('observed_status_code','')}</td><td>{o.get('observed_message_summary','')}</td><td>{o.get('redaction_status','')}</td></tr>" for o in observations)}</table>
<h2>Retest Status</h2><table><tr><th>Plan</th><th>Status</th><th>Observed Result</th><th>Notes</th></tr>{''.join(f"<tr><td>{r.get('replay_plan_id','')}</td><td>{r.get('retest_status','')}</td><td>{r.get('retest_observed_result','')}</td><td>{r.get('retest_notes','')}</td></tr>" for r in retests)}</table>
</body></html>"""


def package_from_plans(plans: list[dict[str, Any]], observations: list[dict[str, Any]] | None = None, retests: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    templates = []
    clean_plans = []
    for plan in plans:
        copy = dict(plan)
        template = copy.pop("redacted_request_template", None)
        if template:
            templates.append(template)
        clean_plans.append(copy)
    return redact_nested(
        {
            "parameter_replay_plans": clean_plans,
            "redacted_request_templates": templates,
            "parameter_replay_observations": observations or [],
            "parameter_replay_retests": retests or [],
            "parameter_replay_summary": build_parameter_replay_summary(clean_plans, observations or [], retests or []),
        }
    )


def _parameter_location(name: str, url: str, parameter: dict[str, Any]) -> str:
    explicit = str(parameter.get("parameter_location") or parameter.get("location") or "")
    if explicit in PARAMETER_LOCATIONS:
        return explicit
    if name in parse_qs(urlsplit(url).query, keep_blank_values=True):
        return "query"
    if "{" + name + "}" in normalise_url_path_ids(url):
        return "path"
    return "unknown"


def _related_categories(intent: str, parameter: dict[str, Any], endpoint: dict[str, Any]) -> list[str]:
    existing = parameter.get("related_owasp_categories") or endpoint.get("related_owasp_categories") or []
    if existing:
        return [str(item) for item in existing]
    mapping = {
        "object_ownership_review": ["A01"],
        "tenant_boundary_review": ["A01"],
        "role_permission_review": ["A01", "A07"],
        "reflection_context_review": ["A05"],
        "input_validation_review": ["A05"],
        "redirect_callback_review": ["A01", "A05", "A08", "A07"],
        "auth_session_review": ["A07", "A08"],
        "export_download_review": ["A01", "A08"],
    }
    return mapping.get(intent, [])


def _match_endpoint(parameter: dict[str, Any], endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    url = str(parameter.get("url") or parameter.get("affected_url") or "")
    normalised = normalise_url_path_ids(url)
    for endpoint in endpoints:
        endpoint_url = str(endpoint.get("url") or endpoint.get("affected_url") or endpoint.get("normalised_url") or "")
        if endpoint_url == url or normalise_url_path_ids(endpoint_url) == normalised:
            return endpoint
    return {"url": url, "method": parameter.get("method") or "GET"}


def _attach_related_evidence(parameter: dict[str, Any], a01: list[dict[str, Any]], a05: list[dict[str, Any]], a07: list[dict[str, Any]]) -> None:
    name = str(parameter.get("parameter_name") or parameter.get("name") or "").lower()
    url = str(parameter.get("url") or parameter.get("affected_url") or "")
    for key, items, link_key in (("A01", a01, "linked_a01_plan_id"), ("A05", a05, "linked_a05_evidence_id"), ("A07", a07, "linked_a07_evidence_id")):
        for item in items:
            text = f"{item.get('affected_url','')} {item.get('parameter_name','')} {item.get('affected_parameter','')}".lower()
            if (name and name in text) or (url and url in text):
                parameter.setdefault(link_key, item.get("evidence_id") or item.get("test_plan_id") or "")
                cats = set(parameter.get("related_owasp_categories") or [])
                cats.add(key)
                parameter["related_owasp_categories"] = sorted(cats)
                break


def _endpoint_category(url: str) -> str:
    text = str(url or "").lower()
    if "admin" in text:
        return "admin"
    if "export" in text or "download" in text:
        return "export_download"
    if "login" in text or "session" in text or "auth" in text:
        return "authentication"
    return "web_endpoint"


def _target(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    return parsed.netloc or parsed.path or ""


def _resolve_parameter_replay_path(path: str | Path) -> Path:
    candidate = Path(path)
    resolved = candidate if candidate.is_absolute() else Path.cwd() / candidate
    root = (Path.cwd() / PARAMETER_REPLAY_DIR).resolve()
    resolved = resolved.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ParameterReplayPlannerError("Replay Plan files must be under data/parameter_replay.") from exc
    return resolved


__all__ = [
    "PARAMETER_REPLAY_DIR",
    "PARAMETER_REPLAY_REPORTS_DIR",
    "ParameterReplayPlannerError",
    "build_replay_plan_from_parameter",
    "build_replay_plans_from_candidates",
    "classify_replay_intent",
    "build_parameter_replay_summary",
    "record_observation_for_plan",
    "replay_plan_fingerprint",
    "load_replay_plans",
    "find_replay_plan",
    "save_replay_plan_package",
    "render_replay_plan_html",
    "package_from_plans",
    "build_report_ready_replay_template",
    "render_report_template_markdown",
]
