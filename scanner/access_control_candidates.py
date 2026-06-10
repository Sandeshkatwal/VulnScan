"""A01 Broken Access Control candidate helpers.

This module is intentionally passive. It analyses existing URL, endpoint, and
parameter metadata and never performs authorization tests or sends requests.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from scanner.evidence import redact_nested
from scanner.finding_fingerprint import build_finding_fingerprint, normalise_path_for_fingerprint


UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE)
HEX_UUID_RE = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)
NUMERIC_RE = re.compile(r"^\d+$")
INVOICE_RE = re.compile(r"^\d{4}-\d+$")

OBJECT_ID_PARAMETERS = {
    "id",
    "uid",
    "user_id",
    "account_id",
    "customer_id",
    "order_id",
    "invoice_id",
    "profile_id",
    "document_id",
    "file_id",
    "report_id",
    "payment_id",
    "subscription_id",
    "address_id",
    "message_id",
}
SENSITIVE_OBJECT_PARAMETERS = {
    "account_id",
    "customer_id",
    "order_id",
    "invoice_id",
    "document_id",
    "file_id",
    "report_id",
    "payment_id",
    "subscription_id",
}
TENANT_PARAMETERS = {
    "tenant",
    "tenant_id",
    "org",
    "org_id",
    "organisation",
    "organisation_id",
    "organization",
    "organization_id",
    "workspace",
    "workspace_id",
    "team",
    "team_id",
    "project",
    "project_id",
    "company",
    "company_id",
}
ROLE_PARAMETERS = {"role", "roles", "permission", "permissions", "is_admin", "admin", "access", "access_level", "scope", "scopes", "privilege", "group"}
FUNCTION_KEYWORDS = {
    "admin",
    "manage",
    "management",
    "settings",
    "permissions",
    "roles",
    "users",
    "invite",
    "team",
    "organisation",
    "organization",
    "billing",
    "payment",
    "export",
    "import",
    "delete",
    "update",
    "edit",
    "approve",
    "reject",
    "suspend",
    "enable",
    "disable",
}
SENSITIVE_RESOURCE_KEYWORDS = {"download", "export", "reports", "report", "invoice", "document", "attachment", "file", "files", "private"}
PUBLIC_INFO_KEYWORDS = {"health", "status", "robots.txt", "sitemap.xml", "favicon.ico", "about", "contact", "docs", "public"}
STATIC_EXTENSIONS = {".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".webp", ".avif"}


def collect_a01_candidate_evidence(
    endpoint_results: list[dict[str, Any]] | None = None,
    parameter_results: list[dict[str, Any]] | None = None,
    evidence_records: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    evidence.extend(assess_object_identifier_candidates(endpoint_results, parameter_results))
    evidence.extend(assess_function_level_candidates(endpoint_results))
    evidence.extend(assess_tenant_boundary_candidates(endpoint_results, parameter_results))
    evidence.extend(assess_sensitive_resource_candidates(endpoint_results, parameter_results))
    evidence.extend(assess_role_permission_indicators(endpoint_results, parameter_results))
    evidence.extend(assess_api_access_control_candidates(endpoint_results, parameter_results))
    evidence.extend(assess_manual_a01_evidence(evidence_records))
    return _dedupe_evidence(evidence)


def assess_object_identifier_candidates(endpoint_results: list[dict[str, Any]] | None, parameter_results: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for param in _collect_parameters(endpoint_results, parameter_results):
        name = param["name"]
        if name not in OBJECT_ID_PARAMETERS:
            continue
        url = param["url"]
        rule_id = "idor_parameter_detected" if name in {"id", "uid"} else f"{name}_parameter_detected"
        score = score_a01_candidate(url=url, parameter_names=[name], candidate_type="object_level_authorization_candidate")
        evidence.append(
            make_a01_evidence_item(
                rule_id=rule_id,
                rule_group="object_level_authorization_candidates",
                title=f"Object-level authorization candidate: {name}",
                affected_url=url,
                affected_parameter=name,
                access_control_candidate_type="object-level authorization candidate",
                object_type_hint=_object_type_hint(name, url),
                candidate_score=score,
                evidence_strength="strong_indicator" if name in SENSITIVE_OBJECT_PARAMETERS else "weak_indicator",
                safe_evidence_summary=f"Object identifier parameter {name} was observed. Candidate requiring manual validation.",
                manual_test_plan_id="horizontal_access_control_review",
                recommendation="Manually validate object ownership enforcement using authorised test accounts and programme-approved test data.",
            )
        )
    for endpoint in _collect_endpoints(endpoint_results):
        url = endpoint["url"]
        path_info = normalise_object_id_path(url)
        if not path_info["has_object_id"]:
            continue
        rule_id = "uuid_object_id_path_detected" if path_info["identifier_kind"] == "uuid" else "numeric_object_id_path_detected"
        score = score_a01_candidate(url=url, parameter_names=[], candidate_type="object_level_authorization_candidate")
        evidence.append(
            make_a01_evidence_item(
                rule_id=rule_id,
                rule_group="object_level_authorization_candidates",
                title=f"Object-level authorization candidate path: {path_info['normalised_path']}",
                affected_url=_normalised_url_without_values(url),
                endpoint_category=str(endpoint.get("endpoint_category") or ""),
                access_control_candidate_type="object-level authorization candidate",
                object_type_hint=path_info["object_type_hint"],
                candidate_score=score,
                evidence_strength="weak_indicator",
                safe_evidence_summary=f"Object identifier path pattern {path_info['normalised_path']} was observed. Candidate requiring manual validation.",
                manual_test_plan_id="horizontal_access_control_review",
                recommendation="Manually validate server-side object ownership controls. Do not access real user data.",
                extra={"normalised_path": path_info["normalised_path"], "identifier_kind": path_info["identifier_kind"]},
            )
        )
    return _dedupe_evidence(evidence)


def assess_function_level_candidates(endpoint_results: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for endpoint in _collect_endpoints(endpoint_results):
        url = endpoint["url"]
        keywords = _path_keywords(url)
        matched = sorted(keywords & FUNCTION_KEYWORDS)
        if not matched:
            continue
        primary = _primary_function_keyword(matched)
        if primary in {"delete", "update", "edit", "approve", "reject", "suspend", "enable", "disable"}:
            rule_id = "delete_update_action_endpoint_detected"
        elif primary in {"manage", "management"}:
            rule_id = "management_endpoint_detected"
        elif primary in {"roles"}:
            rule_id = "role_endpoint_detected"
        elif primary == "permissions":
            rule_id = "permissions_endpoint_detected"
        elif primary == "users":
            rule_id = "user_management_endpoint_detected"
        else:
            rule_id = f"{primary}_endpoint_detected"
        score = score_a01_candidate(url=url, parameter_names=_query_names(url), candidate_type="function_level_authorization_candidate")
        evidence.append(
            make_a01_evidence_item(
                rule_id=rule_id,
                rule_group="function_level_authorization_candidates",
                title=f"Function-level authorization candidate: {primary}",
                affected_url=_normalised_url_without_values(url),
                endpoint_category=primary,
                access_control_candidate_type="function-level authorization candidate",
                object_type_hint=_object_type_hint("", url),
                candidate_score=score,
                evidence_strength="strong_indicator" if score >= 70 else "weak_indicator",
                safe_evidence_summary=f"Function surface indicator observed in endpoint path: {', '.join(matched)}. Candidate only; no authorization testing was performed.",
                manual_test_plan_id="vertical_access_control_review" if primary in {"admin", "manage", "management", "roles", "permissions"} else "function_authorization_review",
                recommendation="Manually validate function authorization using authorised roles. Avoid state-changing actions unless explicitly allowed.",
            )
        )
    return _dedupe_evidence(evidence)


def assess_tenant_boundary_candidates(endpoint_results: list[dict[str, Any]] | None, parameter_results: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for param in _collect_parameters(endpoint_results, parameter_results):
        name = param["name"]
        if name not in TENANT_PARAMETERS:
            continue
        score = score_a01_candidate(url=param["url"], parameter_names=[name], candidate_type="tenant_boundary_candidate")
        rule_id = f"{name}_parameter_detected" if name.endswith("_id") else "multi_tenant_path_detected"
        evidence.append(
            make_a01_evidence_item(
                rule_id=rule_id,
                rule_group="tenant_boundary_candidates",
                title=f"Tenant boundary candidate: {name}",
                affected_url=param["url"],
                affected_parameter=name,
                access_control_candidate_type="tenant boundary candidate",
                object_type_hint=_object_type_hint(name, param["url"]),
                candidate_score=score,
                evidence_strength="strong_indicator",
                safe_evidence_summary=f"Tenant boundary indicator {name} was observed. Candidate requiring manual validation.",
                manual_test_plan_id="tenant_boundary_review",
                recommendation="Manually validate tenant isolation using approved test tenants only.",
            )
        )
    for endpoint in _collect_endpoints(endpoint_results):
        url = endpoint["url"]
        matched = sorted(_path_keywords(url) & TENANT_PARAMETERS)
        if not matched:
            continue
        score = score_a01_candidate(url=url, parameter_names=_query_names(url), candidate_type="tenant_boundary_candidate")
        evidence.append(
            make_a01_evidence_item(
                rule_id="multi_tenant_path_detected",
                rule_group="tenant_boundary_candidates",
                title=f"Tenant boundary candidate path: {', '.join(matched)}",
                affected_url=_normalised_url_without_values(url),
                access_control_candidate_type="tenant boundary candidate",
                object_type_hint=_object_type_hint(matched[0], url),
                candidate_score=score,
                evidence_strength="strong_indicator" if score >= 45 else "weak_indicator",
                safe_evidence_summary=f"Tenant boundary path indicators were observed: {', '.join(matched)}. Candidate only; no tenant data access was attempted.",
                manual_test_plan_id="tenant_boundary_review",
                recommendation="Verify tenant isolation with approved test tenants. Do not access third-party tenant data.",
            )
        )
    return _dedupe_evidence(evidence)


def assess_sensitive_resource_candidates(endpoint_results: list[dict[str, Any]] | None, parameter_results: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    parameter_by_url = {param["url"]: [] for param in _collect_parameters(endpoint_results, parameter_results)}
    for param in _collect_parameters(endpoint_results, parameter_results):
        parameter_by_url.setdefault(param["url"], []).append(param["name"])
    for endpoint in _collect_endpoints(endpoint_results):
        url = endpoint["url"]
        keywords = _path_keywords(url)
        matched = sorted(keywords & SENSITIVE_RESOURCE_KEYWORDS)
        if not matched and not any(marker in url.lower() for marker in ("/media/private", "/api/files", "/api/reports")):
            continue
        params = sorted(set(parameter_by_url.get(url, []) + _query_names(url)))
        rule_id = _sensitive_rule_id(matched, url)
        score = score_a01_candidate(url=url, parameter_names=params, candidate_type="sensitive_resource_candidate")
        evidence.append(
            make_a01_evidence_item(
                rule_id=rule_id,
                rule_group="sensitive_resource_candidates",
                title=f"Sensitive resource access-control candidate: {', '.join(matched) or 'private resource'}",
                affected_url=_normalised_url_without_values(url),
                affected_parameter=", ".join(params),
                endpoint_category="sensitive_resource",
                access_control_candidate_type="access-control candidate",
                object_type_hint=_object_type_hint(params[0] if params else "", url),
                candidate_score=score,
                evidence_strength="strong_indicator" if score >= 45 else "weak_indicator",
                safe_evidence_summary="Sensitive resource endpoint indicator observed. Candidate requiring manual validation; no download or authorization test was performed.",
                manual_test_plan_id="sensitive_export_review",
                recommendation="Confirm users can access only owned resources. Do not download real sensitive files.",
            )
        )
    return _dedupe_evidence(evidence)


def assess_role_permission_indicators(endpoint_results: list[dict[str, Any]] | None, parameter_results: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for param in _collect_parameters(endpoint_results, parameter_results):
        name = param["name"]
        if name not in ROLE_PARAMETERS:
            continue
        rule_id = "is_admin_parameter_detected" if name == "is_admin" else f"{name.rstrip('s')}_parameter_detected"
        if name in {"access", "access_level"}:
            rule_id = "access_level_parameter_detected"
        if name in {"scope", "scopes"}:
            rule_id = "scope_parameter_detected"
        score = score_a01_candidate(url=param["url"], parameter_names=[name], candidate_type="role_permission_indicator")
        evidence.append(
            make_a01_evidence_item(
                rule_id=rule_id,
                rule_group="role_and_permission_indicators",
                title=f"Role or permission indicator: {name}",
                affected_url=param["url"],
                affected_parameter=name,
                access_control_candidate_type="function-level authorization candidate",
                object_type_hint="role_permission",
                candidate_score=score,
                evidence_strength="strong_indicator",
                safe_evidence_summary=f"Role or permission parameter {name} was observed. Candidate only; values were not modified.",
                manual_test_plan_id="vertical_access_control_review",
                recommendation="Manually validate role and permission enforcement using authorised roles only.",
            )
        )
    return _dedupe_evidence(evidence)


def assess_api_access_control_candidates(endpoint_results: list[dict[str, Any]] | None, parameter_results: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    urls = {endpoint["url"] for endpoint in _collect_endpoints(endpoint_results)}
    urls.update(param["url"] for param in _collect_parameters(endpoint_results, parameter_results))
    for url in sorted(item for item in urls if item):
        lower = url.lower()
        if "/graphql" in lower:
            rule_id, title, strength, plan = "graphql_endpoint_access_control_review", "GraphQL endpoint access-control review", "informational", "function_authorization_review"
        elif not _is_api_endpoint(url):
            continue
        elif "admin" in _path_keywords(url):
            rule_id, title, strength, plan = "api_admin_endpoint_detected", "API admin access-control candidate", "strong_indicator", "vertical_access_control_review"
        elif "bulk" in _path_keywords(url):
            rule_id, title, strength, plan = "api_bulk_action_endpoint_detected", "API bulk action access-control candidate", "strong_indicator", "function_authorization_review"
        elif {"users", "user"} & _path_keywords(url):
            rule_id, title, strength, plan = "api_user_endpoint_detected", "API user access-control candidate", "weak_indicator", "horizontal_access_control_review"
        elif {"accounts", "account"} & _path_keywords(url):
            rule_id, title, strength, plan = "api_account_endpoint_detected", "API account access-control candidate", "weak_indicator", "horizontal_access_control_review"
        elif {"orders", "order"} & _path_keywords(url):
            rule_id, title, strength, plan = "api_order_endpoint_detected", "API order access-control candidate", "weak_indicator", "horizontal_access_control_review"
        elif normalise_object_id_path(url)["has_object_id"]:
            rule_id, title, strength, plan = "rest_object_endpoint_detected", "REST object endpoint access-control candidate", "weak_indicator", "horizontal_access_control_review"
        else:
            continue
        params = _query_names(url)
        score = score_a01_candidate(url=url, parameter_names=params, candidate_type="api_access_control_candidate")
        evidence.append(
            make_a01_evidence_item(
                rule_id=rule_id,
                rule_group="api_access_control_candidates",
                title=title,
                affected_url=_normalised_url_without_values(url),
                affected_parameter=", ".join(params),
                endpoint_category="api",
                access_control_candidate_type="access-control candidate",
                object_type_hint=_object_type_hint(params[0] if params else "", url),
                candidate_score=score,
                evidence_strength=strength if score < 70 else "strong_indicator",
                safe_evidence_summary="API access-control candidate observed from URL structure and parameter names. No schema probing or authorization test was performed.",
                manual_test_plan_id=plan,
                recommendation="Review API object, tenant, and function authorization server-side. Manual validation required.",
            )
        )
    return _dedupe_evidence(evidence)


def assess_manual_a01_evidence(evidence_records: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for record in evidence_records or []:
        text = " ".join(str(record.get(key) or "") for key in ("title", "category", "evidence_summary", "observed_signal")).lower()
        categories = record.get("owasp_categories") or record.get("owasp_ids") or []
        if isinstance(categories, str):
            categories = [categories]
        is_a01 = any(str(item.get("owasp_id") if isinstance(item, dict) else item) == "A01:2025" for item in categories)
        if not is_a01 and "access control" not in text and "idor" not in text and "tenant" not in text:
            continue
        strength = str(record.get("evidence_strength") or "strong_indicator")
        if strength == "confirmed_finding" and str(record.get("confidence") or "") != "High":
            strength = "strong_indicator"
        score = 100 if strength == "confirmed_finding" else 70
        evidence.append(
            make_a01_evidence_item(
                rule_id="manual_a01_evidence_record",
                rule_group="manual_validation_plans",
                title=str(record.get("title") or "A01 manual evidence record"),
                affected_url=str(record.get("affected_url") or ""),
                affected_parameter=str(record.get("affected_parameter") or ""),
                access_control_candidate_type=str(record.get("access_control_candidate_type") or "access-control candidate"),
                object_type_hint=str(record.get("object_type_hint") or ""),
                candidate_score=score,
                evidence_strength=strength,
                confidence=str(record.get("confidence") or ("High" if strength == "confirmed_finding" else "Medium")),
                safe_evidence_summary=str(record.get("evidence_summary") or "Manual A01 evidence record supplied."),
                manual_test_plan_id=str(record.get("manual_test_plan_id") or "horizontal_access_control_review"),
                recommendation=str(record.get("recommendation") or "Review supplied manual A01 evidence and validate remediation requirements."),
                manual_validation_required=strength != "confirmed_finding",
                source="manual_evidence",
            )
        )
    return _dedupe_evidence(evidence)


def score_a01_candidate(*, url: str, parameter_names: list[str], candidate_type: str = "") -> int:
    lower_url = str(url or "").lower()
    lower_params = {str(name or "").lower() for name in parameter_names}
    score = 0
    if lower_params & OBJECT_ID_PARAMETERS or normalise_object_id_path(url)["has_object_id"]:
        score += 20
    if lower_params & SENSITIVE_OBJECT_PARAMETERS:
        score += 25
    if lower_params & TENANT_PARAMETERS or candidate_type == "tenant_boundary_candidate":
        score += 30
    if _path_keywords(url) & {"admin", "manage", "management"}:
        score += 25
    if lower_params & ROLE_PARAMETERS:
        score += 30
    if _path_keywords(url) & {"export", "download"}:
        score += 20
    if _is_api_endpoint(url):
        score += 15
    if _path_keywords(url) & {"account", "accounts", "user", "users", "profile", "billing", "payment"}:
        score += 10
    if _is_static_asset(url):
        score -= 30
    if _path_keywords(url) & PUBLIC_INFO_KEYWORDS:
        score -= 15
    return max(0, min(100, score))


def interest_label(score: int) -> str:
    if score >= 70:
        return "High Interest"
    if score >= 45:
        return "Medium Interest"
    if score >= 20:
        return "Low Interest"
    return "Informational"


def confidence_from_score(score: int, signal_count: int = 1) -> str:
    if score >= 70 and signal_count >= 2:
        return "High"
    if score >= 45:
        return "Medium"
    return "Low"


def normalise_object_id_path(url_or_path: str) -> dict[str, Any]:
    parsed = urlsplit(str(url_or_path or ""))
    raw_path = parsed.path or str(url_or_path or "").split("?", 1)[0]
    segments = [segment for segment in raw_path.split("/") if segment]
    normalised: list[str] = []
    has_object_id = False
    identifier_kind = ""
    object_type_hint = ""
    for index, segment in enumerate(segments):
        lowered = segment.lower()
        replacement = lowered
        if UUID_RE.match(lowered) or HEX_UUID_RE.match(lowered):
            replacement = "{uuid}"
            identifier_kind = identifier_kind or "uuid"
            has_object_id = True
        elif NUMERIC_RE.match(lowered) or INVOICE_RE.match(lowered):
            replacement = "{id}"
            identifier_kind = identifier_kind or "numeric"
            has_object_id = True
        if replacement in {"{id}", "{uuid}"} and index > 0:
            object_type_hint = _singular(segments[index - 1].lower())
        normalised.append(replacement)
    return {
        "has_object_id": has_object_id,
        "normalised_path": "/" + "/".join(normalised) if normalised else "/",
        "identifier_kind": identifier_kind,
        "object_type_hint": object_type_hint,
    }


def make_a01_evidence_item(
    *,
    rule_id: str,
    rule_group: str,
    title: str,
    affected_url: str = "",
    affected_host: str = "",
    affected_parameter: str = "",
    endpoint_category: str = "",
    object_type_hint: str = "",
    access_control_candidate_type: str = "access-control candidate",
    evidence_strength: str = "weak_indicator",
    confidence: str | None = None,
    candidate_score: int = 0,
    safe_evidence_summary: str = "",
    manual_validation_required: bool = True,
    manual_test_plan_id: str = "horizontal_access_control_review",
    recommended_manual_steps: list[str] | None = None,
    recommendation: str = "",
    limitation: str = "",
    source: str = "owasp_a01",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    safe_url = _normalised_url_without_values(affected_url)
    host = affected_host or (urlsplit(safe_url).hostname or "")
    score = int(max(0, min(100, candidate_score)))
    signal_count = sum(
        bool(value)
        for value in [
            affected_parameter,
            endpoint_category,
            object_type_hint,
            _is_api_endpoint(safe_url),
            _path_keywords(safe_url) & (FUNCTION_KEYWORDS | SENSITIVE_RESOURCE_KEYWORDS),
        ]
    )
    plan = build_a01_manual_validation_plan({"manual_test_plan_id": manual_test_plan_id, "access_control_candidate_type": access_control_candidate_type})
    item = {
        "evidence_id": "",
        "rule_id": rule_id,
        "rule_group": rule_group,
        "title": title,
        "affected_url": safe_url,
        "affected_host": host,
        "affected_parameter": affected_parameter,
        "endpoint_category": endpoint_category,
        "object_type_hint": object_type_hint,
        "access_control_candidate_type": access_control_candidate_type,
        "evidence_strength": evidence_strength if evidence_strength in {"informational", "weak_indicator", "strong_indicator", "confirmed_finding"} else "weak_indicator",
        "candidate_score": score,
        "interest_label": interest_label(score),
        "confidence": confidence or confidence_from_score(score, signal_count),
        "safe_evidence_summary": safe_evidence_summary,
        "manual_validation_required": bool(manual_validation_required),
        "manual_test_plan_id": manual_test_plan_id,
        "recommended_manual_steps": recommended_manual_steps or plan["safe_manual_steps"],
        "recommendation": recommendation or "Review A01 Broken Access Control candidate using authorised test accounts only.",
        "limitation": limitation or "Candidate requiring Manual Validation Required workflow. No automatic account-to-account request or state-changing request was performed.",
        "source": source,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if extra:
        item.update(extra)
    item["evidence_template"] = build_a01_evidence_template(item)
    item["duplicate_fingerprint"] = build_a01_candidate_fingerprint(item)
    item["evidence_id"] = _evidence_id(item)
    return redact_nested(item)


def build_a01_manual_validation_plan(evidence_item: dict[str, Any]) -> dict[str, Any]:
    plan_id = str(evidence_item.get("manual_test_plan_id") or "")
    candidate_type = str(evidence_item.get("access_control_candidate_type") or "").lower()
    if not plan_id:
        if "tenant" in candidate_type:
            plan_id = "tenant_boundary_review"
        elif "function" in candidate_type:
            plan_id = "function_authorization_review"
        else:
            plan_id = "horizontal_access_control_review"
    plans = {
        "horizontal_access_control_review": {
            "plan_type": "Horizontal access-control review",
            "safe_manual_steps": [
                "Verify with authorised test accounts only.",
                "Confirm object ownership enforcement server-side.",
                "Do not access real user data.",
                "Use programme-approved test data.",
            ],
            "expected_secure_behaviour": "A user can access only objects they own or are explicitly authorised to view.",
            "evidence_needed_for_confirmation": "Screenshots or redacted logs showing server-side ownership checks with authorised test accounts.",
            "risk_if_confirmed": "Unauthorised access to another user's object or record may be possible if validation confirms missing ownership checks.",
        },
        "vertical_access_control_review": {
            "plan_type": "Vertical access-control review",
            "safe_manual_steps": [
                "Confirm lower-privileged roles cannot access admin functions.",
                "Use authorised test roles only.",
                "Avoid state-changing actions unless explicitly allowed.",
            ],
            "expected_secure_behaviour": "Privileged functions require server-side role and permission checks.",
            "evidence_needed_for_confirmation": "Role matrix, test-role requests, and redacted responses proving authorization enforcement or failure.",
            "risk_if_confirmed": "Unauthorised use of privileged functions may be possible if validation confirms missing role checks.",
        },
        "tenant_boundary_review": {
            "plan_type": "Tenant boundary review",
            "safe_manual_steps": [
                "Verify tenant isolation with approved test tenants.",
                "Avoid accessing third-party tenant data.",
                "Use only programme-approved test data.",
            ],
            "expected_secure_behaviour": "Tenant, workspace, organisation, team, and project boundaries are enforced server-side.",
            "evidence_needed_for_confirmation": "Redacted test-tenant evidence showing isolation checks and expected denial behaviour.",
            "risk_if_confirmed": "Cross-tenant data exposure may be possible if validation confirms boundary enforcement failure.",
        },
        "sensitive_export_review": {
            "plan_type": "Sensitive export/download review",
            "safe_manual_steps": [
                "Confirm user can access only owned resources.",
                "Do not download real sensitive files.",
                "Use approved test files, reports, and invoices only.",
            ],
            "expected_secure_behaviour": "Exports and downloads require authorization for the requested resource.",
            "evidence_needed_for_confirmation": "Redacted proof that test users are allowed or denied according to resource ownership.",
            "risk_if_confirmed": "Sensitive files or reports may be exposed if validation confirms missing authorization.",
        },
        "function_authorization_review": {
            "plan_type": "Function authorization review",
            "safe_manual_steps": [
                "Do not perform destructive actions.",
                "Use staging, sandbox, or programme-approved test assets only.",
                "Confirm server-side authorization before any state-changing workflow is tested.",
            ],
            "expected_secure_behaviour": "Update, delete, import, approval, and management functions require explicit authorization.",
            "evidence_needed_for_confirmation": "Redacted test evidence showing unauthorized roles are blocked before any state change.",
            "risk_if_confirmed": "Unauthorised function execution may be possible if validation confirms missing server-side checks.",
        },
        "object_ownership_review": {
            "plan_type": "Object ownership review",
            "safe_manual_steps": [
                "Use authorised test accounts and owned objects only.",
                "Confirm server-side ownership checks for every object reference.",
                "Do not access real user data.",
            ],
            "expected_secure_behaviour": "Object references are bound to the authenticated user's permissions.",
            "evidence_needed_for_confirmation": "Redacted test evidence showing ownership validation at the server.",
            "risk_if_confirmed": "Object-level authorization failure may expose records if manual validation confirms it.",
        },
    }
    plan = dict(plans.get(plan_id, plans["horizontal_access_control_review"]))
    plan["plan_id"] = plan_id if plan_id in plans else "horizontal_access_control_review"
    plan["manual_validation_required"] = True
    plan["safety_note"] = "Manual Validation Required. Use Authorised Test Accounts Only; VulScan does not perform live access-control requests for this plan."
    return plan


def build_a01_evidence_template(evidence_item: dict[str, Any]) -> dict[str, Any]:
    plan = build_a01_manual_validation_plan(evidence_item)
    return {
        "candidate_title": evidence_item.get("title") or "A01 Broken Access Control candidate",
        "affected_endpoint": evidence_item.get("affected_url") or "",
        "parameter_or_object_identifier": evidence_item.get("affected_parameter") or evidence_item.get("object_type_hint") or "",
        "candidate_type": evidence_item.get("access_control_candidate_type") or "access-control candidate",
        "why_it_may_matter": evidence_item.get("safe_evidence_summary") or "Candidate requiring manual validation.",
        "safe_manual_validation_steps": plan["safe_manual_steps"],
        "expected_secure_behaviour": plan["expected_secure_behaviour"],
        "evidence_needed_for_confirmation": plan["evidence_needed_for_confirmation"],
        "risk_if_confirmed": plan["risk_if_confirmed"],
        "recommendation": evidence_item.get("recommendation") or "Manually validate server-side access-control enforcement.",
    }


def build_a01_candidate_fingerprint(evidence_item: dict[str, Any]) -> dict[str, Any]:
    item = {
        "affected_url": evidence_item.get("affected_url") or "",
        "affected_host": evidence_item.get("affected_host") or "",
        "parameter_names": [evidence_item.get("affected_parameter")] if evidence_item.get("affected_parameter") else [],
        "issue_type": evidence_item.get("access_control_candidate_type") or "access_control_candidate",
        "object_type_hint": evidence_item.get("object_type_hint") or "",
        "owasp_id": "A01:2025",
        "source": "owasp_a01",
        "title": evidence_item.get("title") or "",
    }
    fp = build_finding_fingerprint(item, item_type="a01_candidate")
    fp["object_type_hint"] = str(evidence_item.get("object_type_hint") or "")
    return fp


def _collect_endpoints(endpoint_results: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for endpoint in endpoint_results or []:
        url = str(endpoint.get("normalised_url") or endpoint.get("url") or endpoint.get("path") or endpoint.get("affected_url") or "")
        if not url:
            continue
        item = dict(endpoint)
        item["url"] = url
        rows.append(item)
    return rows


def _collect_parameters(endpoint_results: list[dict[str, Any]] | None, parameter_results: list[dict[str, Any]] | None) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for item in parameter_results or []:
        name = str(item.get("parameter_name") or item.get("name") or item.get("parameter") or "").strip().lower()
        url = str(item.get("url") or item.get("normalised_url") or item.get("path") or "")
        if name:
            rows.append({"name": name, "url": _normalised_url_without_values(url), "source": str(item.get("source") or "parameter_intelligence")})
    for endpoint in endpoint_results or []:
        url = str(endpoint.get("normalised_url") or endpoint.get("url") or endpoint.get("path") or "")
        for name, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            if name:
                rows.append({"name": name.strip().lower(), "url": _normalised_url_without_values(url), "source": "endpoint_query"})
        for param in endpoint.get("parameters") or []:
            if isinstance(param, dict):
                name = str(param.get("name") or param.get("parameter_name") or "").strip().lower()
                if name:
                    rows.append({"name": name, "url": _normalised_url_without_values(url), "source": "endpoint_parameters"})
    return rows


def _normalised_url_without_values(url: str) -> str:
    raw = str(url or "").strip()
    parsed = urlsplit(raw)
    if not parsed.scheme and not parsed.netloc:
        path = normalise_object_id_path(raw)["normalised_path"] if normalise_object_id_path(raw)["has_object_id"] else normalise_path_for_fingerprint(raw.split("?", 1)[0])
        names = sorted({name.lower() for name, _value in parse_qsl(raw.split("?", 1)[1] if "?" in raw else "", keep_blank_values=True) if name})
        return path + (("?" + "&".join(names)) if names else "")
    path_info = normalise_object_id_path(raw)
    path = path_info["normalised_path"] if path_info["has_object_id"] else normalise_path_for_fingerprint(parsed.path or "/")
    query = "&".join(sorted({name.lower() for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name}))
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, query, ""))


def _query_names(url: str) -> list[str]:
    return sorted({name.lower() for name, _value in parse_qsl(urlsplit(str(url or "")).query, keep_blank_values=True) if name})


def _path_keywords(url: str) -> set[str]:
    path = urlsplit(str(url or "")).path or str(url or "")
    tokens = re.split(r"[^a-zA-Z0-9_]+", path.lower())
    return {token for token in tokens if token}


def _is_api_endpoint(url: str) -> bool:
    lower = str(url or "").lower()
    return "/api/" in lower or re.search(r"/v\d+/", lower) is not None or "/graphql" in lower


def _is_static_asset(url: str) -> bool:
    path = urlsplit(str(url or "")).path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)


def _object_type_hint(parameter_name: str, url: str) -> str:
    name = str(parameter_name or "").lower()
    if name.endswith("_id"):
        return name[:-3]
    if name in {"id", "uid"}:
        path_hint = normalise_object_id_path(url).get("object_type_hint")
        return str(path_hint or "object")
    keywords = _path_keywords(url)
    for candidate in ("account", "user", "customer", "order", "invoice", "profile", "document", "file", "report", "tenant", "workspace", "team", "project"):
        if candidate in keywords or f"{candidate}s" in keywords:
            return candidate
    return name or ""


def _singular(value: str) -> str:
    if value.endswith("ies"):
        return value[:-3] + "y"
    if value.endswith("s") and len(value) > 3:
        return value[:-1]
    return value


def _primary_function_keyword(matched: list[str]) -> str:
    priority = ["admin", "management", "manage", "settings", "permissions", "roles", "users", "export", "import", "delete", "update", "edit", "approve", "reject", "suspend", "enable", "disable"]
    for item in priority:
        if item in matched:
            return item
    return matched[0]


def _sensitive_rule_id(matched: list[str], url: str) -> str:
    lower = str(url or "").lower()
    if "download" in matched:
        return "file_download_endpoint_detected"
    if "export" in matched or "/api/reports" in lower:
        return "report_export_endpoint_detected"
    if "invoice" in matched:
        return "invoice_download_endpoint_detected"
    if "document" in matched:
        return "document_endpoint_detected"
    if "attachment" in matched:
        return "attachment_endpoint_detected"
    if "private" in matched or "/media/private" in lower:
        return "private_api_endpoint_detected"
    return "file_download_endpoint_detected"


def _dedupe_evidence(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for item in evidence:
        key = "|".join(
            [
                str(item.get("rule_id") or ""),
                str(item.get("affected_url") or ""),
                str(item.get("affected_parameter") or ""),
                str(item.get("access_control_candidate_type") or ""),
                str(item.get("object_type_hint") or ""),
            ]
        )
        current = deduped.get(key)
        if not current or int(item.get("candidate_score") or 0) > int(current.get("candidate_score") or 0):
            deduped[key] = item
    return sorted(deduped.values(), key=lambda item: (int(item.get("candidate_score") or 0), str(item.get("title") or "")), reverse=True)


def _evidence_id(item: dict[str, Any]) -> str:
    basis = {
        "rule_id": item.get("rule_id"),
        "rule_group": item.get("rule_group"),
        "affected_url": item.get("affected_url"),
        "affected_parameter": item.get("affected_parameter"),
        "candidate_type": item.get("access_control_candidate_type"),
        "object_type_hint": item.get("object_type_hint"),
    }
    digest = hashlib.sha256(json.dumps(basis, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return f"a01_{digest[:16]}"
