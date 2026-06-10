"""A05 Injection candidate and safe reflection analysis.

This module classifies existing endpoint, parameter, and form evidence. Optional
safe reflection observation is limited to harmless markers on GET parameters.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from scanner.evidence import redact_nested
from scanner.finding import create_finding, finding_to_dict
from scanner.parameter_replay_planner import build_parameter_replay_summary
from scanner.reflection_analysis import observe_safe_reflection


A05_RULES_PATH = Path("data") / "owasp" / "a05" / "a05_rules.json"
A05_REPORTS_DIR = Path("reports") / "owasp" / "a05"

REFLECTION_NAMES = {"q", "query", "search", "keyword", "term", "name", "message", "comment", "description", "title", "content"}
QUERY_NAMES = {"id", "user_id", "account_id", "order_id", "filter", "sort", "where", "query", "search", "category", "type"}
COMMAND_TEMPLATE_NAMES = {"cmd", "command", "exec", "run", "path", "file", "template", "view", "page", "include"}
CALLBACK_NAMES = {"callback", "cb", "jsonp"}
API_FILTER_NAMES = {"filter", "sort", "fields", "include", "expand", "limit", "offset"}
TEXT_INPUT_TYPES = {"", "text", "search", "email", "url", "tel"}
LIMITATIONS = [
    "A05 Injection checks are candidate and indicator based.",
    "Safe reflection observation uses harmless markers for selected GET parameters only.",
    "No exploit payloads, form submission, schema probing, or exploitability confirmation is performed.",
    "Manual validation is required before reporting any injection impact.",
]


class A05RulesError(ValueError):
    """Raised when A05 rules are unavailable or invalid."""


def load_a05_rules(path: str | Path = A05_RULES_PATH) -> dict[str, Any]:
    rules_path = Path(path)
    try:
        payload = json.loads(rules_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise A05RulesError(f"A05 rules file was not found: {rules_path}") from exc
    except json.JSONDecodeError as exc:
        raise A05RulesError(f"A05 rules file is not valid JSON: {rules_path}") from exc
    if payload.get("owasp_id") != "A05:2025":
        raise A05RulesError("A05 rules file must describe A05:2025.")
    if not isinstance(payload.get("rule_groups"), dict):
        raise A05RulesError("A05 rules file must include rule_groups.")
    return payload


def ensure_a05_dirs() -> None:
    A05_RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    A05_REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def assess_injection_parameter_candidates(parameter_results: list[dict[str, Any]] | None, endpoint_results: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    known = list(parameter_results or [])
    for endpoint in endpoint_results or []:
        url = str(endpoint.get("normalised_url") or endpoint.get("url") or endpoint.get("path") or "")
        for name, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            known.append({"url": url, "parameter_name": name})
        for param in endpoint.get("parameters") or []:
            if isinstance(param, dict):
                known.append({"url": url, "parameter_name": param.get("name") or param.get("parameter_name")})
    for item in known:
        name = _parameter_name(item)
        if not name:
            continue
        category = _candidate_category(name)
        if not category:
            continue
        url = str(item.get("url") or item.get("normalised_url") or item.get("path") or "")
        evidence.append(
            _evidence(
                rule_id=category["rule_id"],
                rule_group="parameter_candidates",
                title=f"A05 injection candidate parameter: {name}",
                affected_url=url,
                affected_parameter=name,
                input_type=category["candidate_type"],
                evidence_strength="weak_indicator",
                confidence=category["confidence"],
                observed_value=name,
                safe_evidence_summary=f"Parameter name {name} is an input handling indicator for {category['label']}. Parameter names alone do not prove injection.",
                reflection_context="unknown",
                recommendation="Manually validate server-side input handling and output encoding for this parameter.",
                manual_validation_required=True,
                extra={"candidate_type": category["candidate_type"], "potential_issue": category["label"]},
            )
        )
    return _dedupe_evidence(evidence)


def assess_form_input_candidates(forms: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for form in forms or []:
        fields = _form_fields(form)
        action = str(form.get("action_url") or form.get("action") or form.get("page_url") or form.get("url") or "")
        names: list[str] = []
        hidden_names: list[str] = []
        input_types: list[str] = []
        for field in fields:
            name = str(field.get("name") or "").strip()
            input_type = str(field.get("type") or field.get("input_type") or "").strip().lower()
            if name:
                names.append(name)
            input_types.append(input_type or "text")
            if input_type == "hidden" and name:
                hidden_names.append(name)
        for field in fields:
            name = str(field.get("name") or "").strip()
            input_type = str(field.get("type") or field.get("input_type") or "").strip().lower()
            tag = str(field.get("tag") or field.get("field_type") or "").strip().lower()
            if tag == "textarea":
                rule_id, strength = "textarea_detected", "weak_indicator"
            elif input_type == "hidden":
                rule_id, strength = "hidden_input_names_only", "informational"
            elif input_type == "search":
                rule_id, strength = "search_input_detected", "weak_indicator"
            elif input_type == "email":
                rule_id, strength = "email_input_detected", "informational"
            elif input_type in TEXT_INPUT_TYPES:
                rule_id, strength = "text_input_detected", "weak_indicator"
            else:
                continue
            reason = _form_reason(form, name)
            evidence.append(
                _evidence(
                    rule_id=rule_id,
                    rule_group="form_input_indicators",
                    title=f"A05 form input candidate: {name or input_type or tag}",
                    affected_url=action,
                    affected_parameter=name,
                    input_type=input_type or tag or "text",
                    evidence_strength=strength,
                    confidence="Medium" if strength == "weak_indicator" else "Low",
                    observed_value=name,
                    safe_evidence_summary="Form input candidate observed. Field values, hidden values, and submitted data were not stored.",
                    reflection_context="unknown",
                    recommendation="Review server-side validation and output encoding for form inputs. Manual validation required.",
                    manual_validation_required=True,
                    extra={"form_action": action, "input_names": sorted(set(names)), "input_types": sorted(set(input_types)), "hidden_field_names": sorted(set(hidden_names)), "candidate_reason": reason},
                )
            )
    return _dedupe_evidence(evidence)


def assess_api_input_candidates(endpoint_results: list[dict[str, Any]] | None, parameter_results: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    urls = [str(item.get("normalised_url") or item.get("url") or item.get("path") or "") for item in endpoint_results or []]
    urls.extend(str(item.get("url") or item.get("path") or "") for item in parameter_results or [])
    for url in sorted({item for item in urls if item}):
        lower = url.lower()
        query_names = [name for name, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
        if "/graphql" in lower:
            rule_id, pattern, confidence = "graphql_endpoint_detected", "GraphQL endpoint detected", "Low"
        elif any(marker in lower for marker in ("/api/", "/v1/", "/v2/")) and query_names:
            rule_id, pattern, confidence = "api_endpoint_with_query_params", "API endpoint with query parameters", "Medium"
        elif any(name.lower() in API_FILTER_NAMES for name in query_names):
            rule_id, pattern, confidence = "filter_sort_query_pattern", "Filter/sort query pattern", "Medium"
        elif _has_object_id_path(lower):
            rule_id, pattern, confidence = "rest_endpoint_with_object_id", "REST endpoint with object ID", "Low"
        else:
            continue
        evidence.append(
            _evidence(
                rule_id=rule_id,
                rule_group="api_input_indicators",
                title=f"A05 API input candidate: {pattern}",
                affected_url=url,
                affected_parameter=", ".join(query_names),
                input_type="api_input_candidate",
                evidence_strength="weak_indicator" if confidence == "Medium" else "informational",
                confidence=confidence,
                observed_value=pattern,
                safe_evidence_summary=f"{pattern}. Candidate only; no schema fuzzing, GraphQL introspection, POST, or PUT requests were performed.",
                reflection_context="unknown",
                recommendation="Review API query/filter/sort handling and object lookup controls. Manual validation required.",
                manual_validation_required=True,
                extra={"api_pattern": pattern, "parameter_names": query_names, "candidate_score": 20 if confidence == "Medium" else 10},
            )
        )
    return _dedupe_evidence(evidence)


def assess_a05_injection(
    *,
    target: str = "",
    endpoint_results: list[dict[str, Any]] | None = None,
    parameter_results: list[dict[str, Any]] | None = None,
    forms: list[dict[str, Any]] | None = None,
    safe_reflection: bool = False,
    max_reflection_checks: int = 10,
    request_delay: float = 1.0,
) -> dict[str, Any]:
    ensure_a05_dirs()
    load_a05_rules()
    evidence: list[dict[str, Any]] = []
    parameter_evidence = assess_injection_parameter_candidates(parameter_results, endpoint_results)
    form_evidence = assess_form_input_candidates(forms)
    api_evidence = assess_api_input_candidates(endpoint_results, parameter_results)
    evidence.extend(parameter_evidence)
    evidence.extend(form_evidence)
    evidence.extend(api_evidence)
    if safe_reflection:
        evidence.extend(_safe_reflection_evidence(parameter_evidence, max_reflection_checks=max_reflection_checks, request_delay=request_delay))
    evidence = _dedupe_evidence(evidence)
    summary = build_a05_summary(target=target or _first_target(endpoint_results, parameter_results, forms), evidence=evidence)
    findings = build_a05_findings(summary, evidence)
    return redact_nested({"a05_injection_summary": summary, "a05_injection_evidence": evidence, "findings": findings})


def attach_a05_injection(scan_result: dict[str, Any], *, safe_reflection: bool = False, max_reflection_checks: int = 10, request_delay: float = 1.0) -> dict[str, Any]:
    target = str(scan_result.get("target") or scan_result.get("url") or scan_result.get("host") or "")
    forms = list(scan_result.get("web_form_results") or scan_result.get("discovered_forms") or [])
    payload = assess_a05_injection(
        target=target,
        endpoint_results=scan_result.get("endpoint_results") or [],
        parameter_results=scan_result.get("parameter_results") or [],
        forms=forms,
        safe_reflection=safe_reflection,
        max_reflection_checks=max_reflection_checks,
        request_delay=request_delay,
    )
    findings = list(payload.get("findings", []))
    replay_plans = [plan for plan in scan_result.get("parameter_replay_plans") or [] if "A05" in (plan.get("related_owasp_categories") or [])]
    replay_observations = scan_result.get("parameter_replay_observations") or []
    if replay_plans or replay_observations:
        replay_summary = build_parameter_replay_summary(replay_plans, replay_observations, scan_result.get("parameter_replay_retests") or [])
        payload["a05_injection_summary"].update(
            {
                "replay_plans_count": replay_summary.get("replay_plans_count", 0),
                "reflection_review_plans_count": sum(1 for plan in replay_plans if plan.get("replay_intent") in {"reflection_context_review", "input_validation_review"}),
                "manually_verified_reflection_issue_count": sum(1 for item in replay_observations if item.get("observed_access_result") == "reflected_with_context_risk"),
            }
        )
    payload_without_findings = dict(payload)
    payload_without_findings.pop("findings", None)
    scan_result.update(payload_without_findings)
    scan_result.setdefault("findings", [])
    scan_result["findings"].extend(findings)
    return scan_result


def build_a05_summary(target: str, evidence: list[dict[str, Any]]) -> dict[str, Any]:
    strength_counts = Counter(str(item.get("evidence_strength") or "") for item in evidence)
    group_counts = Counter(str(item.get("rule_group") or "") for item in evidence)
    context_counts = Counter(str(item.get("reflection_context") or "") for item in evidence)
    confidence_order = {"Low": 1, "Medium": 2, "High": 3}
    highest = "Low"
    for item in evidence:
        confidence = str(item.get("confidence") or "Low")
        if confidence_order.get(confidence, 0) > confidence_order.get(highest, 0):
            highest = confidence
    return {
        "enabled": True,
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_evidence_items": len(evidence),
        "strong_indicators_count": strength_counts.get("strong_indicator", 0),
        "weak_indicators_count": strength_counts.get("weak_indicator", 0),
        "informational_count": strength_counts.get("informational", 0),
        "manual_validation_required_count": sum(1 for item in evidence if item.get("manual_validation_required")),
        "parameter_candidate_count": group_counts.get("parameter_candidates", 0),
        "form_input_candidate_count": group_counts.get("form_input_indicators", 0),
        "api_input_candidate_count": group_counts.get("api_input_indicators", 0),
        "reflection_observed_count": sum(1 for item in evidence if item.get("rule_group") == "reflection_observation"),
        "script_like_reflection_count": context_counts.get("script_like", 0),
        "attribute_like_reflection_count": context_counts.get("attribute_like", 0),
        "json_like_reflection_count": context_counts.get("json_like", 0),
        "rule_group_counts": dict(group_counts),
        "highest_confidence": highest,
        "top_risks": _top_risks(evidence),
        "recommendations": [
            "Review output encoding for reflected input indicators.",
            "Review server-side input validation and parameterised queries.",
            "Review API filter/sort handling and template rendering context.",
            "Confirm impact manually before reporting.",
        ],
        "limitations": LIMITATIONS,
    }


def build_a05_findings(summary: dict[str, Any], evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = [
        finding_to_dict(create_finding(title="A05 Injection Candidate Assessment Completed", severity="Informational", category="OWASP A05 Injection", affected_host=str(summary.get("target") or "a05-assessment"), evidence="VulScan evaluated available parameters, forms, API endpoints, and safe reflection observations.", recommendation="Review A05 candidates and manually validate input handling controls.", source="owasp_a05", confidence="High", impact="A05 candidate evidence supports manual input handling review.", verification="Review a05_injection_summary and a05_injection_evidence.", limitation="A05 checks are candidate/indicator-based and do not use exploit payloads."))
    ]
    if summary.get("parameter_candidate_count", 0):
        findings.append(finding_to_dict(create_finding(title="Injection-Prone Parameter Candidates", severity="Low" if summary.get("parameter_candidate_count", 0) >= 3 else "Informational", category="OWASP A05 Injection", affected_host=str(summary.get("target") or "a05-assessment"), evidence="One or more parameters may influence queries, output, filtering, paths, callbacks, or templates.", recommendation="Manually validate server-side input handling and output encoding.", source="owasp_a05", confidence=str(summary.get("highest_confidence") or "Medium"), impact="Parameter intelligence identified A05 input handling indicators.", verification="Review grouped parameter candidate evidence.", limitation="Parameter names alone do not prove injection.")))
    if summary.get("reflection_observed_count", 0):
        severity = "Medium" if summary.get("script_like_reflection_count", 0) or summary.get("attribute_like_reflection_count", 0) else "Low"
        findings.append(finding_to_dict(create_finding(title="Safe Reflection Indicator Observed", severity=severity, category="OWASP A05 Injection", affected_host=str(summary.get("target") or "a05-assessment"), evidence="A harmless marker was reflected in response content.", recommendation="Manually review output context and encoding.", source="owasp_a05", confidence="High", impact="Reflection indicator may warrant manual review of output encoding.", verification="Review reflection context and redacted snippets.", limitation="Reflection alone does not confirm XSS or injection.")))
    return findings


def _safe_reflection_evidence(parameter_evidence: list[dict[str, Any]], *, max_reflection_checks: int, request_delay: float) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    checked = 0
    for candidate in parameter_evidence:
        url = str(candidate.get("affected_url") or "")
        parameter = str(candidate.get("affected_parameter") or "")
        if checked >= max_reflection_checks or not urlsplit(url).query:
            continue
        checked += 1
        observation = observe_safe_reflection(url, parameter, request_delay=request_delay)
        if not observation.get("marker_reflected"):
            continue
        context = str(observation.get("reflection_context") or "unknown")
        rule_id = {
            "html_text": "marker_reflected_in_html_text",
            "attribute_like": "marker_reflected_in_attribute_like_context",
            "script_like": "marker_reflected_in_script_like_context",
            "json_like": "marker_reflected_in_json_like_context",
            "url_like": "marker_reflected_in_url_context",
        }.get(context, "safe_marker_reflected")
        items.append(
            _evidence(
                rule_id=rule_id,
                rule_group="reflection_observation",
                title=f"Safe reflection indicator observed: {parameter}",
                affected_url=url,
                affected_parameter=parameter,
                input_type="get_query_parameter",
                evidence_strength="strong_indicator",
                confidence="High",
                observed_value="harmless marker reflected",
                safe_evidence_summary="Harmless marker was reflected in the response. Full response body was not stored and exploitability is not confirmed.",
                reflection_context=context,
                recommendation="Manually review output context and encoding before reporting any A05 impact.",
                manual_validation_required=True,
                extra={"marker_reflected": True, "redacted_snippet": observation.get("redacted_snippet") or "", "full_body_stored": False},
            )
        )
    return items


def _evidence(*, rule_id: str, rule_group: str, title: str, affected_url: str, affected_parameter: str, input_type: str, evidence_strength: str, confidence: str, observed_value: str, safe_evidence_summary: str, reflection_context: str, recommendation: str, manual_validation_required: bool, source: str = "owasp_a05", extra: dict[str, Any] | None = None) -> dict[str, Any]:
    item = {
        "evidence_id": "",
        "rule_id": rule_id,
        "rule_group": rule_group,
        "title": title,
        "affected_url": affected_url,
        "affected_host": urlsplit(str(affected_url or "")).netloc,
        "affected_parameter": affected_parameter,
        "input_type": input_type,
        "evidence_strength": evidence_strength,
        "confidence": confidence,
        "observed_value": observed_value,
        "safe_evidence_summary": safe_evidence_summary,
        "reflection_context": reflection_context,
        "recommendation": recommendation,
        "manual_validation_required": manual_validation_required,
        "source": source,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if extra:
        item.update(extra)
    item["evidence_id"] = _evidence_id(item)
    return item


def _candidate_category(name: str) -> dict[str, str] | None:
    normalised = name.strip().lower()
    if normalised in CALLBACK_NAMES:
        return {"rule_id": "callback_parameter_detected", "candidate_type": "callback_jsonp_candidate", "label": "callback/JSONP handling", "confidence": "Medium"}
    if normalised in COMMAND_TEMPLATE_NAMES:
        rule = "template_parameter_detected" if normalised in {"template", "view", "page", "include"} else "expression_parameter_detected"
        return {"rule_id": rule, "candidate_type": "command_path_template_candidate", "label": "path/template-like input handling", "confidence": "Medium"}
    if normalised in API_FILTER_NAMES:
        return {"rule_id": "filter_parameter_detected" if normalised != "sort" else "sort_parameter_detected", "candidate_type": "api_filter_candidate", "label": "API filter/sort handling", "confidence": "Medium"}
    if normalised in QUERY_NAMES:
        return {"rule_id": "query_parameter_detected", "candidate_type": "query_input_candidate", "label": "query or object lookup handling", "confidence": "Low"}
    if normalised in REFLECTION_NAMES:
        rule = "search_parameter_detected" if normalised in {"q", "query", "search", "keyword", "term"} else ("comment_parameter_detected" if normalised == "comment" else "message_parameter_detected")
        return {"rule_id": rule, "candidate_type": "reflection_input_candidate", "label": "reflection/output handling", "confidence": "Low"}
    return None


def _form_fields(form: dict[str, Any]) -> list[dict[str, Any]]:
    fields = form.get("fields") or form.get("inputs") or form.get("input_fields") or []
    return [dict(field) for field in fields if isinstance(field, dict)]


def _form_reason(form: dict[str, Any], name: str) -> str:
    text = " ".join([str(form.get("classification") or ""), str(form.get("action") or ""), str(name or "")]).lower()
    if "comment" in text:
        return "comment_form_detected"
    if "feedback" in text or "contact" in text:
        return "feedback_form_detected"
    if str(name or "").lower() in REFLECTION_NAMES | QUERY_NAMES:
        return "input name likely used for search/comment/message/filter"
    return "form input candidate"


def _parameter_name(item: dict[str, Any]) -> str:
    return str(item.get("parameter_name") or item.get("parameter") or item.get("name") or "").strip()


def _has_object_id_path(url: str) -> bool:
    parts = [part for part in urlsplit(url).path.split("/") if part]
    return any(part.isdigit() for part in parts)


def _top_risks(evidence: list[dict[str, Any]]) -> list[str]:
    risks: list[str] = []
    if any(item.get("reflection_context") == "script_like" for item in evidence):
        risks.append("script-like reflection context requires manual validation")
    if any(item.get("reflection_context") == "attribute_like" for item in evidence):
        risks.append("attribute-like reflection context requires manual validation")
    if any(item.get("rule_group") == "api_input_indicators" for item in evidence):
        risks.append("API query/filter input handling requires manual validation")
    if any(item.get("input_type") == "command_path_template_candidate" for item in evidence):
        risks.append("path/template-like parameters require manual validation")
    return risks[:5]


def _first_target(*groups: Any) -> str:
    for group in groups:
        for item in group or []:
            value = str(item.get("url") or item.get("normalised_url") or item.get("action") or item.get("action_url") or "")
            if value:
                return value
    return ""


def _evidence_id(item: dict[str, Any]) -> str:
    basis = "|".join(str(item.get(key) or "") for key in ("source", "rule_id", "affected_url", "affected_parameter", "reflection_context"))
    return "a05-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _dedupe_evidence(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    order = {"informational": 1, "weak_indicator": 2, "strong_indicator": 3, "confirmed_finding": 4}
    for item in items:
        key = (str(item.get("rule_id")), str(item.get("affected_url")), str(item.get("affected_parameter")), str(item.get("reflection_context")))
        existing = by_key.get(key)
        if existing is None or order.get(str(item.get("evidence_strength")), 0) > order.get(str(existing.get("evidence_strength")), 0):
            by_key[key] = item
    return list(by_key.values())
