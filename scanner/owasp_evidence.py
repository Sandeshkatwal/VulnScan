"""OWASP Assessment Engine evidence classification.

This module only classifies existing VulScan evidence. It does not run tests,
send payloads, or confirm vulnerabilities from weak indicators.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from scanner.evidence import redact_nested
from scanner.finding import finding_to_dict
from scanner.owasp_rules import categories_by_id, load_owasp_assessment_rules


CONFIDENCE_ORDER = {"Low": 1, "Medium": 2, "High": 3}
STRENGTH_ORDER = {"not_assessed": 0, "informational": 1, "weak_indicator": 2, "strong_indicator": 3, "confirmed_finding": 4}
CONFIDENCE_VALUES = {"Low", "Medium", "High"}
STRENGTH_VALUES = {"weak_indicator", "strong_indicator", "confirmed_finding", "informational", "not_assessed"}
STATUS_VALUES = {"detected_indicator", "needs_manual_validation", "confirmed", "not_detected", "not_assessed", "coverage_gap"}


def build_owasp_evidence_items(
    scan_result: dict[str, Any] | None = None,
    endpoint_results: list[dict[str, Any]] | None = None,
    parameter_results: list[dict[str, Any]] | None = None,
    validation_results: list[dict[str, Any]] | None = None,
    findings: list[dict[str, Any]] | None = None,
    evidence_records: list[dict[str, Any]] | None = None,
    rules: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    rules = rules or load_owasp_assessment_rules()
    categories = categories_by_id(rules)
    scan_result = scan_result or {}
    items: list[dict[str, Any]] = []
    all_findings = [_safe_finding_dict(item) for item in (findings if findings is not None else scan_result.get("findings", []) or [])]
    all_findings.extend(_safe_finding_dict(item) for item in (scan_result.get("web_findings", []) or []))
    for index, finding in enumerate(all_findings):
        items.extend(_items_from_finding(finding, index, categories))
    for index, result in enumerate(endpoint_results if endpoint_results is not None else scan_result.get("endpoint_results", []) or []):
        items.extend(_items_from_endpoint(result, index, categories))
    for index, result in enumerate(parameter_results if parameter_results is not None else scan_result.get("parameter_results", []) or []):
        items.extend(_items_from_parameter(result, index, categories))
    for index, result in enumerate(validation_results if validation_results is not None else scan_result.get("safe_active_validation_results", []) or []):
        items.extend(_items_from_validation(result, index, categories))
    for index, record in enumerate(evidence_records if evidence_records is not None else scan_result.get("evidence_records", []) or []):
        items.extend(_items_from_manual_evidence(record, index, categories))
    for index, record in enumerate(scan_result.get("a04_crypto_evidence", []) or []):
        items.extend(_items_from_a04_evidence(record, index, categories))
    for index, record in enumerate(scan_result.get("a07_authentication_evidence", []) or []):
        items.extend(_items_from_a07_evidence(record, index, categories))
    for index, record in enumerate(scan_result.get("a05_injection_evidence", []) or []):
        items.extend(_items_from_a05_evidence(record, index, categories))
    for index, record in enumerate(scan_result.get("a10_error_handling_evidence", []) or []):
        items.extend(_items_from_a10_evidence(record, index, categories))
    for index, record in enumerate(scan_result.get("a01_access_control_evidence", []) or []):
        items.extend(_items_from_a01_evidence(record, index, categories))
    return _dedupe(items)


def make_evidence_item(
    *,
    source: str,
    source_id: str,
    title: str,
    owasp_id: str,
    categories: dict[str, dict[str, Any]],
    confidence: str,
    evidence_strength: str,
    observed_signal: str,
    affected_url: str = "",
    affected_parameter: str = "",
    endpoint_category: str = "",
    finding_category: str = "",
    assessment_status: str | None = None,
    manual_validation_required: bool | None = None,
    evidence_summary: str = "",
    recommendation_theme: str = "",
    limitation: str = "",
) -> dict[str, Any]:
    category = categories[owasp_id]
    confidence = confidence if confidence in CONFIDENCE_VALUES else "Low"
    evidence_strength = evidence_strength if evidence_strength in STRENGTH_VALUES else "weak_indicator"
    if evidence_strength == "confirmed_finding":
        assessment_status = "confirmed"
    elif assessment_status is None:
        assessment_status = "needs_manual_validation" if (manual_validation_required if manual_validation_required is not None else category.get("manual_validation_required")) else "detected_indicator"
    manual = bool(category.get("manual_validation_required")) if manual_validation_required is None else bool(manual_validation_required)
    item = {
        "evidence_id": "",
        "source": source,
        "source_id": source_id,
        "title": title,
        "affected_url": affected_url,
        "affected_parameter": affected_parameter,
        "endpoint_category": endpoint_category,
        "finding_category": finding_category,
        "observed_signal": observed_signal,
        "owasp_id": owasp_id,
        "owasp_name": category.get("name") or "",
        "confidence": confidence,
        "evidence_strength": evidence_strength,
        "assessment_status": assessment_status if assessment_status in STATUS_VALUES else "detected_indicator",
        "manual_validation_required": manual,
        "evidence_summary": evidence_summary or observed_signal,
        "recommendation_theme": recommendation_theme or _first(category.get("recommendation_themes")),
        "limitation": limitation or str(category.get("limitations") or ""),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    item["evidence_id"] = _evidence_id(item)
    return redact_nested(item)


def strongest_item(items: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not items:
        return None
    return sorted(items, key=lambda item: (STRENGTH_ORDER.get(str(item.get("evidence_strength")), 0), CONFIDENCE_ORDER.get(str(item.get("confidence")), 0)), reverse=True)[0]


def _items_from_finding(finding: dict[str, Any], index: int, categories: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    item = _safe_finding_dict(finding)
    source = str(item.get("source") or "finding")
    title = str(item.get("title") or "Finding")
    category = str(item.get("category") or "")
    text = " ".join([source, title, category, str(item.get("evidence") or ""), str(item.get("recommendation") or "")]).lower()
    mapped = list(item.get("owasp_categories") or [])
    owasp_ids = [str(mapped_item.get("owasp_id")) for mapped_item in mapped if str(mapped_item.get("owasp_id")) in categories]
    if not owasp_ids:
        owasp_ids = _category_ids_from_text(text, source, categories)
    results = []
    for owasp_id in owasp_ids[:3]:
        confidence = "High" if source in {"vuln_intel", "cve_feed"} and ("cve" in text or item.get("cve")) else str(item.get("confidence") or "Medium")
        strength = "confirmed_finding" if item.get("confirmed") is True else ("strong_indicator" if source in {"vuln_intel", "cve_feed", "web_header_audit", "web_cookie_audit"} else "weak_indicator")
        results.append(make_evidence_item(source=source, source_id=f"finding-{index}", title=title, owasp_id=owasp_id, categories=categories, confidence=confidence, evidence_strength=strength, observed_signal=title, affected_url=_first(item.get("affected_urls")) or str(item.get("affected_url") or ""), finding_category=category, manual_validation_required=strength != "confirmed_finding" and bool(categories[owasp_id].get("manual_validation_required")), evidence_summary=str(item.get("evidence") or title)))
    return results


def _items_from_endpoint(endpoint: dict[str, Any], index: int, categories: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    endpoint_category = str(endpoint.get("endpoint_category") or "")
    url = str(endpoint.get("normalised_url") or endpoint.get("url") or endpoint.get("path") or "")
    mapping = {
        "admin": ["A01:2025", "A02:2025"],
        "user_account": ["A01:2025"],
        "payment_or_billing": ["A01:2025", "A06:2025"],
        "file_upload": ["A08:2025"],
        "export": ["A08:2025", "A06:2025"],
        "password_reset": ["A06:2025", "A07:2025"],
        "debug": ["A02:2025", "A10:2025"],
        "authentication": ["A07:2025"],
        "redirect": ["A01:2025", "A06:2025"],
    }
    results = []
    for owasp_id in mapping.get(endpoint_category, [])[:3]:
        results.append(make_evidence_item(source="endpoint_discovery", source_id=f"endpoint-{index}", title=f"{endpoint_category.replace('_', ' ').title()} endpoint indicator", owasp_id=owasp_id, categories=categories, confidence="Low" if owasp_id in {"A01:2025", "A06:2025"} else "Medium", evidence_strength="weak_indicator", observed_signal=f"Endpoint classified as {endpoint_category}.", affected_url=url, endpoint_category=endpoint_category, manual_validation_required=True, evidence_summary="Passive endpoint classification indicator."))
    return results


def _safe_finding_dict(finding: Any) -> dict[str, Any]:
    try:
        item = finding_to_dict(finding)
    except Exception:
        item = dict(finding or {})
    item.setdefault("title", "Finding")
    item.setdefault("severity", "Informational")
    item.setdefault("category", "")
    item.setdefault("source", "finding")
    item.setdefault("evidence", "")
    item.setdefault("confidence", "Low")
    return item


def _items_from_parameter(parameter: dict[str, Any], index: int, categories: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    parameter_type = str(parameter.get("parameter_type") or "")
    name = str(parameter.get("parameter_name") or parameter.get("name") or "")
    url = str(parameter.get("url") or parameter.get("path") or "")
    mapping = {
        "idor": ["A01:2025"],
        "injection_reflection": ["A05:2025"],
        "redirect": ["A01:2025", "A06:2025"],
        "path_traversal": ["A08:2025", "A05:2025"],
        "ssrf": ["A06:2025"],
        "debug_config": ["A02:2025"],
        "sensitive_token": ["A07:2025", "A04:2025"],
    }
    results = []
    for owasp_id in mapping.get(parameter_type, [])[:3]:
        results.append(make_evidence_item(source="parameter_intelligence", source_id=f"parameter-{index}", title=f"Parameter indicator: {name}", owasp_id=owasp_id, categories=categories, confidence="Low", evidence_strength="weak_indicator", observed_signal=f"Parameter name classified as {parameter_type}.", affected_url=url, affected_parameter=name, finding_category=str(parameter.get("potential_issue") or ""), manual_validation_required=True, evidence_summary="Parameter-name analysis only; not a confirmed finding."))
    return results


def _items_from_validation(result: dict[str, Any], index: int, categories: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    if result.get("indicator_found") is False:
        return []
    check = str(result.get("check_name") or result.get("candidate_type") or "").lower()
    mapping = {
        "reflected_input_observation": [("A05:2025", "Reflected input observation")],
        "directory_listing_indicator": [("A02:2025", "Directory listing indicator")],
        "cors_indicator": [("A02:2025", "CORS indicator"), ("A07:2025", "CORS/session context indicator")],
        "http_methods_indicator": [("A02:2025", "HTTP methods indicator")],
        "default_file_exposure_indicator": [("A02:2025", "Default public file observed")],
        "open_redirect_indicator": [("A06:2025", "Redirect workflow indicator"), ("A01:2025", "Redirect access-control context indicator")],
    }
    pairs = mapping.get(check, [])
    if not pairs:
        return []
    results = []
    for owasp_id, title in pairs[:3]:
        strength = "informational" if check == "default_file_indicator" else "strong_indicator"
        results.append(make_evidence_item(source="safe_active_validation", source_id=f"validation-{index}", title=title, owasp_id=owasp_id, categories=categories, confidence="Medium", evidence_strength=strength, observed_signal=title, affected_url=str(result.get("url") or ""), affected_parameter=str(result.get("parameter") or ""), manual_validation_required=owasp_id in {"A05:2025", "A07:2025"} or bool(categories[owasp_id].get("manual_validation_required")), evidence_summary=_validation_summary(result)))
    return results


def _items_from_manual_evidence(record: dict[str, Any], index: int, categories: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    raw_ids = record.get("owasp_categories") or record.get("owasp_ids") or []
    if isinstance(raw_ids, str):
        raw_ids = [raw_ids]
    text = " ".join([str(record.get("title") or ""), str(record.get("category") or ""), str(record.get("evidence_summary") or "")]).lower()
    ids = [str(item.get("owasp_id") if isinstance(item, dict) else item) for item in raw_ids if str(item.get("owasp_id") if isinstance(item, dict) else item) in categories]
    if not ids:
        ids = _category_ids_from_text(text, "manual_evidence", categories)
    results = []
    for owasp_id in ids[:3]:
        strength = str(record.get("evidence_strength") or "strong_indicator")
        if strength == "confirmed_finding" and str(record.get("confidence") or "") != "High":
            strength = "strong_indicator"
        results.append(make_evidence_item(source="manual_evidence", source_id=f"manual-{index}", title=str(record.get("title") or "Manual evidence"), owasp_id=owasp_id, categories=categories, confidence=str(record.get("confidence") or "Medium"), evidence_strength=strength, observed_signal=str(record.get("observed_signal") or record.get("title") or "Manual evidence"), affected_url=str(record.get("affected_url") or ""), affected_parameter=str(record.get("affected_parameter") or ""), manual_validation_required=bool(record.get("manual_validation_required", categories[owasp_id].get("manual_validation_required"))), evidence_summary=str(record.get("evidence_summary") or record.get("summary") or "")))
    return results


def _items_from_a04_evidence(record: dict[str, Any], index: int, categories: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    if "A04:2025" not in categories:
        return []
    strength = str(record.get("evidence_strength") or "weak_indicator")
    confidence = str(record.get("confidence") or "Medium")
    return [
        make_evidence_item(
            source="owasp_a04",
            source_id=str(record.get("evidence_id") or f"a04-{index}"),
            title=str(record.get("title") or "A04 Cryptographic Failures indicator"),
            owasp_id="A04:2025",
            categories=categories,
            confidence=confidence,
            evidence_strength=strength,
            observed_signal=str(record.get("safe_evidence_summary") or record.get("observed_value") or record.get("title") or ""),
            affected_url=str(record.get("affected_url") or ""),
            manual_validation_required=bool(record.get("manual_validation_required", True)),
            evidence_summary=str(record.get("safe_evidence_summary") or ""),
            recommendation_theme=str(record.get("recommendation") or "Review A04 Cryptographic Failures evidence and apply transport/security hardening."),
            limitation="A04 evidence is indicator-based and may require manual validation.",
        )
    ]


def _items_from_a01_evidence(record: dict[str, Any], index: int, categories: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    if "A01:2025" not in categories:
        return []
    strength = str(record.get("evidence_strength") or "weak_indicator")
    confidence = str(record.get("confidence") or "Medium")
    score = int(record.get("candidate_score") or 0)
    if record.get("evidence_strength") != "confirmed_finding":
        strong_signals = {
            "tenant_boundary_candidates",
            "role_and_permission_indicators",
            "sensitive_resource_candidates",
            "api_access_control_candidates",
        }
        if record.get("rule_group") in strong_signals and score >= 45:
            strength = "strong_indicator"
        elif score >= 70:
            strength = "strong_indicator"
    return [
        make_evidence_item(
            source="owasp_a01",
            source_id=str(record.get("evidence_id") or f"a01-{index}"),
            title=str(record.get("title") or "A01 Broken Access Control candidate"),
            owasp_id="A01:2025",
            categories=categories,
            confidence=confidence,
            evidence_strength=strength,
            observed_signal=str(record.get("safe_evidence_summary") or record.get("title") or ""),
            affected_url=str(record.get("affected_url") or ""),
            affected_parameter=str(record.get("affected_parameter") or ""),
            endpoint_category=str(record.get("endpoint_category") or record.get("access_control_candidate_type") or ""),
            manual_validation_required=bool(record.get("manual_validation_required", True)),
            evidence_summary=str(record.get("safe_evidence_summary") or "A01 access-control candidate requiring manual validation."),
            recommendation_theme=str(record.get("recommendation") or "Review A01 Broken Access Control candidates using authorised test accounts only."),
            limitation=str(record.get("limitation") or "A01 evidence is candidate-based and does not perform auth bypass or cross-account testing."),
        )
    ]


def _items_from_a07_evidence(record: dict[str, Any], index: int, categories: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    if "A07:2025" not in categories:
        return []
    strength = str(record.get("evidence_strength") or "weak_indicator")
    confidence = str(record.get("confidence") or "Medium")
    return [
        make_evidence_item(
            source="owasp_a07",
            source_id=str(record.get("evidence_id") or f"a07-{index}"),
            title=str(record.get("title") or "A07 Authentication Failures indicator"),
            owasp_id="A07:2025",
            categories=categories,
            confidence=confidence,
            evidence_strength=strength,
            observed_signal=str(record.get("safe_evidence_summary") or record.get("observed_value") or record.get("title") or ""),
            affected_url=str(record.get("affected_url") or ""),
            affected_parameter=str(record.get("affected_parameter") or ""),
            manual_validation_required=bool(record.get("manual_validation_required", True)),
            evidence_summary=str(record.get("safe_evidence_summary") or ""),
            recommendation_theme=str(record.get("recommendation") or "Review A07 Authentication Failures evidence and manually validate authentication workflow controls."),
            limitation="A07 evidence is indicator-based and does not perform login attempts or brute force.",
        )
    ]


def _items_from_a05_evidence(record: dict[str, Any], index: int, categories: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    if "A05:2025" not in categories:
        return []
    strength = str(record.get("evidence_strength") or "weak_indicator")
    confidence = str(record.get("confidence") or "Medium")
    return [
        make_evidence_item(
            source="owasp_a05",
            source_id=str(record.get("evidence_id") or f"a05-{index}"),
            title=str(record.get("title") or "A05 Injection indicator"),
            owasp_id="A05:2025",
            categories=categories,
            confidence=confidence,
            evidence_strength=strength,
            observed_signal=str(record.get("safe_evidence_summary") or record.get("observed_value") or record.get("title") or ""),
            affected_url=str(record.get("affected_url") or ""),
            affected_parameter=str(record.get("affected_parameter") or ""),
            manual_validation_required=bool(record.get("manual_validation_required", True)),
            evidence_summary=str(record.get("safe_evidence_summary") or ""),
            recommendation_theme=str(record.get("recommendation") or "Review A05 Injection candidates and manually validate input handling controls."),
            limitation="A05 evidence is candidate/indicator-based and does not confirm exploitability.",
        )
    ]


def _items_from_a10_evidence(record: dict[str, Any], index: int, categories: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    if "A10:2025" not in categories:
        return []
    return [
        make_evidence_item(
            source="owasp_a10",
            source_id=str(record.get("evidence_id") or f"a10-{index}"),
            title=str(record.get("title") or "A10 Mishandling of Exceptional Conditions indicator"),
            owasp_id="A10:2025",
            categories=categories,
            confidence=str(record.get("confidence") or "Medium"),
            evidence_strength=str(record.get("evidence_strength") or "weak_indicator"),
            observed_signal=str(record.get("safe_evidence_summary") or record.get("observed_pattern") or record.get("title") or ""),
            affected_url=str(record.get("affected_url") or ""),
            manual_validation_required=bool(record.get("manual_validation_required", True)),
            evidence_summary=str(record.get("safe_evidence_summary") or ""),
            recommendation_theme=str(record.get("recommendation") or "Review A10 error-handling evidence and ensure fail-safe behaviour."),
            limitation="A10 evidence is observation-based and does not force application errors.",
        )
    ]


def _category_ids_from_text(text: str, source: str, categories: dict[str, dict[str, Any]]) -> list[str]:
    signals = [
        ("A03:2025", ("cve", "component", "dependency", "outdated", "package", "vulnerability intelligence")),
        ("A02:2025", ("missing csp", "content security policy", "server banner", "debug", "directory listing", "misconfiguration")),
        ("A04:2025", ("hsts", "secure flag", "tls", "cleartext", "cryptographic")),
        ("A07:2025", ("httponly", "cookie", "login", "authentication", "session")),
        ("A05:2025", ("injection", "reflected", "search", "comment", "message")),
        ("A01:2025", ("idor", "access control", "admin", "account id", "user_id")),
        ("A08:2025", ("upload", "import", "export", "file", "integrity")),
        ("A06:2025", ("redirect", "reset-password", "workflow", "design")),
        ("A10:2025", ("error", "exception", "debug")),
        ("A09:2025", ("logging", "alerting", "monitoring")),
    ]
    matched = [owasp_id for owasp_id, needles in signals if owasp_id in categories and any(needle in text for needle in needles)]
    if source in {"vuln_intel", "cve_feed"} and "A03:2025" in categories and "A03:2025" not in matched:
        matched.insert(0, "A03:2025")
    return matched[:3]


def _validation_summary(result: dict[str, Any]) -> str:
    summary = result.get("evidence_summary")
    if isinstance(summary, dict):
        keys = [key for key, value in summary.items() if value]
        return ", ".join(keys[:5]) or "Safe validation indicator observed."
    return str(summary or "Safe validation indicator observed.")


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for item in items:
        key = (
            str(item.get("source")),
            str(item.get("affected_url")),
            str(item.get("affected_parameter")),
            str(item.get("owasp_id")),
            str(item.get("observed_signal")).lower(),
        )
        existing = by_key.get(key)
        if not existing or STRENGTH_ORDER.get(str(item.get("evidence_strength")), 0) > STRENGTH_ORDER.get(str(existing.get("evidence_strength")), 0):
            by_key[key] = item
    return list(by_key.values())


def _evidence_id(item: dict[str, Any]) -> str:
    stable = "|".join(str(item.get(key) or "") for key in ("source", "source_id", "affected_url", "affected_parameter", "owasp_id", "observed_signal"))
    return "owasp_ev_" + hashlib.sha256(stable.encode("utf-8")).hexdigest()[:16]


def _first(value: Any) -> str:
    if isinstance(value, list) and value:
        return str(value[0])
    return str(value or "")
