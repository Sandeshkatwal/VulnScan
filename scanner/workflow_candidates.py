"""Business Logic Review workflow candidate detection.

This module classifies existing endpoint and parameter metadata only. It does
not discover new paths, execute workflows, submit forms, or make live requests.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

from scanner.evidence import redact_nested
from scanner.request_template_builder import normalise_url_path_ids


WORKFLOW_TYPES = {
    "checkout_payment",
    "refund_transfer",
    "approval_rejection",
    "account_lifecycle",
    "password_reset",
    "subscription_plan",
    "coupon_discount",
    "quota_rate_limit",
    "import_export",
    "file_upload_processing",
    "role_permission_change",
    "multi_step_process",
    "notification_webhook",
    "custom",
}
WORKFLOW_SENSITIVITIES = {"low", "medium", "high", "critical"}
STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
FINANCIAL_TYPES = {"checkout_payment", "refund_transfer", "subscription_plan", "coupon_discount"}
DESTRUCTIVE_TOKENS = {"delete", "deactivate", "suspend", "close-account", "refund", "transfer", "withdraw", "restore"}

KEYWORD_GROUPS: dict[str, set[str]] = {
    "checkout_payment": {"checkout", "payment", "pay", "billing", "invoice", "purchase", "cart", "order"},
    "subscription_plan": {"subscription", "plan", "subscribe", "trial"},
    "refund_transfer": {"refund", "transfer", "payout", "withdraw", "credit", "balance"},
    "approval_rejection": {"approve", "reject", "review", "verify", "confirm", "pending", "workflow"},
    "account_lifecycle": {"register", "signup", "invite", "activate", "deactivate", "suspend", "close-account", "delete-account"},
    "password_reset": {"forgot-password", "reset-password", "recovery", "verify-email"},
    "coupon_discount": {"coupon", "discount", "promo", "voucher", "offer", "price"},
    "quota_rate_limit": {"quota", "limit", "rate", "usage", "credits", "allowance"},
    "import_export": {"import", "export", "bulk", "sync", "backup", "restore"},
    "file_upload_processing": {"upload", "file", "process", "parse"},
    "role_permission_change": {"role", "permission", "admin", "access", "invite", "member"},
    "notification_webhook": {"webhook", "callback", "event", "notification", "integration"},
}


@dataclass
class BusinessLogicWorkflowCandidate:
    workflow_candidate_id: str
    title: str
    workflow_type: str
    target: str
    affected_url: str
    normalised_url: str
    endpoint_category: str
    related_parameters: list[str] = field(default_factory=list)
    related_roles: list[str] = field(default_factory=list)
    related_owasp_categories: list[str] = field(default_factory=list)
    workflow_sensitivity: str = "low"
    state_changing: bool = False
    destructive_or_financial: bool = False
    manual_validation_required: bool = True
    candidate_score: int = 0
    confidence: str = "Low"
    safe_evidence_summary: str = ""
    recommendation: str = ""
    limitation: str = ""
    source: str = "workflow_candidates"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def assess_business_logic_workflow_candidates(
    endpoint_results: list[dict[str, Any]] | None,
    parameter_results: list[dict[str, Any]] | None,
    role_matrix: list[dict[str, Any]] | dict[str, Any] | None = None,
    replay_plans: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    endpoints = _collect_endpoints(endpoint_results or [], parameter_results or [], role_matrix, replay_plans or [])
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for endpoint in endpoints:
        url = str(endpoint.get("url") or endpoint.get("normalised_url") or endpoint.get("endpoint") or "")
        if not url or _is_static_or_public(url, endpoint):
            continue
        workflow_type, matched = _classify_workflow(url, endpoint)
        if workflow_type == "custom" and not matched:
            continue
        related_parameters = _parameters_for_url(url, parameter_results or [], endpoint)
        related_roles = _roles_for_endpoint(url, role_matrix)
        score = _candidate_score(workflow_type, url, endpoint, related_parameters, role_matrix)
        score = max(0, min(100, score))
        normalised = normalise_url_path_ids(url)
        key = f"{workflow_type}|{normalised}"
        if key in seen:
            continue
        seen.add(key)
        sensitivity = _sensitivity(score, workflow_type)
        state_changing = _state_changing(endpoint, url)
        destructive_or_financial = workflow_type in FINANCIAL_TYPES or any(token in url.lower() for token in DESTRUCTIVE_TOKENS)
        candidate = BusinessLogicWorkflowCandidate(
            workflow_candidate_id=f"workflow_candidate_{uuid4().hex[:12]}",
            title=f"Business Logic Review candidate: {workflow_type.replace('_', ' ')}",
            workflow_type=workflow_type,
            target=_target(url),
            affected_url=url,
            normalised_url=normalised,
            endpoint_category=str(endpoint.get("endpoint_category") or workflow_type),
            related_parameters=related_parameters,
            related_roles=related_roles,
            related_owasp_categories=_related_owasp_categories(workflow_type),
            workflow_sensitivity=sensitivity,
            state_changing=state_changing,
            destructive_or_financial=destructive_or_financial,
            candidate_score=score,
            confidence="High" if score >= 70 else ("Medium" if score >= 35 else "Low"),
            safe_evidence_summary=f"Existing endpoint metadata matched {workflow_type.replace('_', ' ')} workflow keywords: {', '.join(sorted(matched)) or 'metadata context'}. Candidate only.",
            recommendation=_recommendation(workflow_type),
            limitation="Business Logic Review candidates are manual planning records only. No Automatic Workflow Execution.",
            source=str(endpoint.get("source") or "endpoint_discovery"),
        )
        candidates.append(redact_nested(candidate.to_dict()))
    return sorted(candidates, key=lambda item: int(item.get("candidate_score") or 0), reverse=True)


def workflow_risk_label(score: int) -> str:
    if score >= 80:
        return "Critical Review"
    if score >= 60:
        return "High Review"
    if score >= 35:
        return "Medium Review"
    if score >= 15:
        return "Low Review"
    return "Informational"


def _collect_endpoints(endpoint_results: list[dict[str, Any]], parameter_results: list[dict[str, Any]], role_matrix: list[dict[str, Any]] | dict[str, Any] | None, replay_plans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    endpoints = [dict(item or {}) for item in endpoint_results]
    for item in parameter_results:
        url = str(item.get("url") or item.get("affected_url") or "")
        if url:
            endpoints.append({"url": url, "method": item.get("method") or "GET", "source": item.get("source") or "parameter_intelligence"})
    rows = role_matrix.get("role_endpoint_matrix") if isinstance(role_matrix, dict) else role_matrix
    for row in rows or []:
        url = str(row.get("endpoint") or row.get("url") or "")
        if url:
            endpoints.append({"url": url, "method": row.get("method") or "GET", "endpoint_category": row.get("endpoint_category") or "", "source": "role_mapping", "expected_permission": row.get("expected_permission")})
    for plan in replay_plans:
        url = str(plan.get("affected_url") or plan.get("normalised_url") or "")
        if url:
            endpoints.append({"url": url, "method": plan.get("method") or "GET", "endpoint_category": plan.get("endpoint_category") or "", "source": "parameter_replay_planner"})
    return endpoints


def _classify_workflow(url: str, endpoint: dict[str, Any]) -> tuple[str, set[str]]:
    text = " ".join([url, str(endpoint.get("endpoint_category") or ""), str(endpoint.get("title") or "")]).lower().replace("_", "-")
    best_type = "custom"
    best_hits: set[str] = set()
    for workflow_type, keywords in KEYWORD_GROUPS.items():
        hits = {keyword for keyword in keywords if keyword in text}
        if len(hits) > len(best_hits):
            best_type = workflow_type
            best_hits = hits
    return best_type, best_hits


def _candidate_score(workflow_type: str, url: str, endpoint: dict[str, Any], related_parameters: list[str], role_matrix: list[dict[str, Any]] | dict[str, Any] | None) -> int:
    score = 0
    if workflow_type in {"checkout_payment", "subscription_plan"}:
        score += 35
    if workflow_type == "refund_transfer":
        score += 35
    if workflow_type == "approval_rejection":
        score += 25
    if workflow_type == "role_permission_change":
        score += 30
    if workflow_type in {"password_reset", "account_lifecycle"}:
        score += 30
    if workflow_type in {"import_export", "file_upload_processing"}:
        score += 25
    if workflow_type == "notification_webhook":
        score += 20
    if any(name.lower() in {"id", "user_id", "account_id", "order_id", "tenant_id", "org_id", "workspace_id"} for name in related_parameters):
        score += 20
    if _role_expected_denied_or_conditional(url, role_matrix):
        score += 20
    if endpoint.get("source") == "authenticated_crawl":
        score += 15
    if _state_changing(endpoint, url):
        score += 20
    if workflow_type in FINANCIAL_TYPES or any(token in url.lower() for token in DESTRUCTIVE_TOKENS):
        score += 30
    if _is_static_or_public(url, endpoint):
        score -= 40
    if "home" in url.lower() or "about" in url.lower() or "help" in url.lower():
        score -= 20
    return score


def _parameters_for_url(url: str, parameter_results: list[dict[str, Any]], endpoint: dict[str, Any]) -> list[str]:
    names = [name for name, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    for item in parameter_results:
        if str(item.get("url") or item.get("affected_url") or "") == url:
            name = str(item.get("parameter_name") or item.get("name") or "")
            if name:
                names.append(name)
    for param in endpoint.get("parameters") or []:
        if isinstance(param, dict):
            names.append(str(param.get("name") or param.get("parameter_name") or ""))
    return sorted(set(filter(None, names)))


def _roles_for_endpoint(url: str, role_matrix: list[dict[str, Any]] | dict[str, Any] | None) -> list[str]:
    rows = role_matrix.get("role_endpoint_matrix") if isinstance(role_matrix, dict) else role_matrix
    roles = [str(row.get("role_label") or row.get("role_id") or "") for row in rows or [] if str(row.get("endpoint") or row.get("url") or "") == url]
    return sorted(set(filter(None, roles)))


def _role_expected_denied_or_conditional(url: str, role_matrix: list[dict[str, Any]] | dict[str, Any] | None) -> bool:
    rows = role_matrix.get("role_endpoint_matrix") if isinstance(role_matrix, dict) else role_matrix
    for row in rows or []:
        if str(row.get("endpoint") or row.get("url") or "") == url and str(row.get("expected_permission") or "") in {"denied", "conditional"}:
            return True
    return False


def _state_changing(endpoint: dict[str, Any], url: str) -> bool:
    method = str(endpoint.get("method") or "GET").upper()
    if method in STATE_METHODS:
        return True
    return any(token in url.lower() for token in ("create", "update", "delete", "approve", "reject", "checkout", "pay", "refund", "transfer", "submit"))


def _is_static_or_public(url: str, endpoint: dict[str, Any]) -> bool:
    lower = url.lower()
    if any(lower.endswith(ext) for ext in (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2")):
        return True
    return str(endpoint.get("endpoint_category") or "") in {"static_asset", "public_page"}


def _sensitivity(score: int, workflow_type: str) -> str:
    if score >= 80 or workflow_type in {"checkout_payment", "refund_transfer"}:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _related_owasp_categories(workflow_type: str) -> list[str]:
    mapping = {
        "checkout_payment": ["A01", "A06", "A08"],
        "refund_transfer": ["A01", "A06", "A08"],
        "approval_rejection": ["A01", "A06"],
        "account_lifecycle": ["A01", "A06", "A07"],
        "password_reset": ["A06", "A07"],
        "coupon_discount": ["A06"],
        "quota_rate_limit": ["A06"],
        "import_export": ["A01", "A06", "A08"],
        "file_upload_processing": ["A05", "A06", "A08"],
        "role_permission_change": ["A01", "A06"],
        "notification_webhook": ["A06", "A08"],
    }
    return mapping.get(workflow_type, ["A06"])


def _recommendation(workflow_type: str) -> str:
    return {
        "checkout_payment": "Document and manually validate server-side payment, order, and price-sensitive Business Rule Review controls.",
        "approval_rejection": "Document allowed state transitions and manually validate role-specific approval controls.",
        "coupon_discount": "Document coupon, discount, and pricing rules and manually validate server-side enforcement.",
        "quota_rate_limit": "Document quota, usage, and limit rules and manually validate server-side enforcement.",
        "notification_webhook": "Document webhook trust boundaries, signature validation, timestamp checks, and allowed destinations.",
    }.get(workflow_type, "Document Expected Behaviour and complete Business Logic Review with Authorised Test Data Only.")


def _target(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    return parsed.netloc or parsed.path or ""
