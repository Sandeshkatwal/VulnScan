"""OWASP Top 10 indicator mapping.

This module classifies existing findings and bug intelligence candidates only. It
does not run tests, send payloads, or confirm vulnerabilities.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from scanner.finding import create_finding, finding_to_dict, findings_to_dicts


OWASP_MAPPING_PATH = Path("data") / "owasp" / "owasp_top10_2025_mapping.json"
OWASP_VERSION = "2025"
OWASP_LIMITATIONS = [
    "OWASP mapping is indicator-based and does not confirm vulnerability presence.",
    "No active OWASP testing, payload injection, exploitation, or bypass automation is performed.",
    "No indicator for a category does not mean the application is free from that weakness.",
]


class OWASPMappingError(ValueError):
    """Raised when OWASP mapping data is invalid."""


def load_owasp_mapping(path: str | Path = OWASP_MAPPING_PATH) -> dict[str, Any]:
    mapping_path = Path(path)
    try:
        payload = json.loads(mapping_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        payload = _fallback_mapping()
    except json.JSONDecodeError as exc:
        raise OWASPMappingError(f"OWASP mapping file is not valid JSON: {mapping_path}") from exc
    categories = payload.get("categories")
    if not isinstance(categories, list) or not categories:
        raise OWASPMappingError("OWASP mapping must include a non-empty categories list.")
    return payload


def map_finding_to_owasp(finding: dict[str, Any], mapping: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    mapping = mapping or load_owasp_mapping()
    item = finding_to_dict(finding)
    source = str(item.get("source") or "")
    category = str(item.get("category") or "")
    title = str(item.get("title") or "")
    evidence = str(item.get("evidence") or "")
    text = " ".join([source, category, title, evidence, str(item.get("recommendation") or "")]).lower()
    candidates: list[dict[str, Any]] = []
    for owasp_category in mapping["categories"]:
        reason = ""
        confidence = "Low"
        if source and source in set(owasp_category.get("finding_sources") or []):
            reason = f"Finding source '{source}' maps to {owasp_category['owasp_id']}."
            confidence = "High" if source in {"vuln_intel", "cve_feed"} else "Medium"
        elif _keyword_match(text, owasp_category.get("indicator_keywords") or []):
            reason = f"Finding text contains indicator keywords for {owasp_category['owasp_id']}."
            confidence = "Medium"
        elif _service_crypto_signal(item, owasp_category):
            reason = "Cleartext or cryptographic service exposure indicator."
            confidence = "Medium"
        if reason:
            candidates.append(_mapping_item(owasp_category, confidence, reason, source or "finding", bool(item.get("confirmed") is not True)))
    return _top_three(candidates)


def map_endpoint_to_owasp(
    endpoint_result: dict[str, Any],
    parameter_results: list[dict[str, Any]] | None = None,
    mapping: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    mapping = mapping or load_owasp_mapping()
    endpoint_category = str(endpoint_result.get("endpoint_category") or "")
    url = str(endpoint_result.get("normalised_url") or endpoint_result.get("path") or "")
    related_parameters = [
        item for item in (parameter_results or [])
        if str(item.get("url") or "") == str(endpoint_result.get("normalised_url") or "")
        or str(item.get("path") or "") == str(endpoint_result.get("path") or "")
    ]
    parameter_types = {str(item.get("parameter_type") or "") for item in related_parameters}
    candidates: list[dict[str, Any]] = []
    for owasp_category in mapping["categories"]:
        if endpoint_category and endpoint_category in set(owasp_category.get("endpoint_categories") or []):
            candidates.append(
                _mapping_item(
                    owasp_category,
                    "Medium",
                    f"Endpoint category '{endpoint_category}' is an OWASP indicator.",
                    "endpoint_discovery",
                    True,
                )
            )
            continue
        matched_parameter = parameter_types.intersection(set(owasp_category.get("parameter_types") or []))
        if matched_parameter:
            candidates.append(
                _mapping_item(
                    owasp_category,
                    "Low",
                    f"Related parameter type '{sorted(matched_parameter)[0]}' is an OWASP indicator.",
                    "endpoint_discovery",
                    True,
                )
            )
            continue
        if _keyword_match(url.lower(), owasp_category.get("indicator_keywords") or []):
            candidates.append(_mapping_item(owasp_category, "Low", "Endpoint URL contains OWASP indicator keywords.", "endpoint_discovery", True))
    return _top_three(candidates)


def map_parameter_to_owasp(parameter_result: dict[str, Any], mapping: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    mapping = mapping or load_owasp_mapping()
    parameter_type = str(parameter_result.get("parameter_type") or "")
    text = " ".join(
        [
            str(parameter_result.get("parameter_name") or ""),
            str(parameter_result.get("potential_issue") or ""),
            str(parameter_result.get("path") or ""),
        ]
    ).lower()
    candidates: list[dict[str, Any]] = []
    for owasp_category in mapping["categories"]:
        if parameter_type and parameter_type in set(owasp_category.get("parameter_types") or []):
            candidates.append(_mapping_item(owasp_category, "Medium", f"Parameter type '{parameter_type}' maps to this OWASP indicator.", "parameter_intelligence", True))
        elif _keyword_match(text, owasp_category.get("indicator_keywords") or []):
            candidates.append(_mapping_item(owasp_category, "Low", "Parameter metadata contains OWASP indicator keywords.", "parameter_intelligence", True))
    return _top_three(candidates)


def build_owasp_summary(
    findings: list[dict[str, Any]] | None,
    endpoint_results: list[dict[str, Any]] | None = None,
    parameter_results: list[dict[str, Any]] | None = None,
    mapping: dict[str, Any] | None = None,
) -> dict[str, Any]:
    mapping = mapping or load_owasp_mapping()
    mapped_items = build_owasp_mapped_items(findings or [], endpoint_results or [], parameter_results or [], mapping)
    category_counts = Counter(item["owasp_id"] for item in mapped_items)
    confidence_counts: dict[str, dict[str, int]] = defaultdict(lambda: {"High": 0, "Medium": 0, "Low": 0})
    for item in mapped_items:
        confidence_counts[item["owasp_id"]][item["confidence"]] += 1
    category_ids = [category["owasp_id"] for category in mapping["categories"]]
    coverage_gaps = [
        {
            "owasp_id": category["owasp_id"],
            "owasp_name": category["name"],
            "explanation": "No indicators were mapped. This does not mean no vulnerability exists.",
        }
        for category in mapping["categories"]
        if category["owasp_id"] not in category_counts
    ]
    mapped_finding_keys = {
        item["item_key"] for item in mapped_items if item["item_type"] == "finding"
    }
    return {
        "enabled": True,
        "version": OWASP_VERSION,
        "mapped_findings_count": len(mapped_finding_keys),
        "unmapped_findings_count": max(0, len(findings or []) - len(mapped_finding_keys)),
        "mapped_endpoint_candidates_count": len({item["item_key"] for item in mapped_items if item["item_type"] == "endpoint"}),
        "mapped_parameter_candidates_count": len({item["item_key"] for item in mapped_items if item["item_type"] == "parameter"}),
        "category_counts": {category_id: category_counts.get(category_id, 0) for category_id in category_ids},
        "category_confidence_counts": {category_id: dict(confidence_counts[category_id]) for category_id in category_ids},
        "highest_signal_categories": _highest_signal_categories(mapping, category_counts),
        "coverage_gaps": coverage_gaps,
        "manual_validation_required_count": sum(1 for item in mapped_items if item.get("manual_validation_required")),
        "limitations": OWASP_LIMITATIONS,
    }


def build_owasp_mapped_items(
    findings: list[dict[str, Any]],
    endpoint_results: list[dict[str, Any]],
    parameter_results: list[dict[str, Any]],
    mapping: dict[str, Any],
) -> list[dict[str, Any]]:
    mapped_items: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        item = finding_to_dict(finding)
        mappings = map_finding_to_owasp(item, mapping)
        for mapped in mappings:
            mapped_items.append(_mapped_output("finding", _finding_title(item), item.get("source") or "", item.get("category") or "", f"finding-{index}", mapped))
    for index, endpoint in enumerate(endpoint_results):
        mappings = map_endpoint_to_owasp(endpoint, parameter_results, mapping)
        for mapped in mappings:
            mapped_items.append(_mapped_output("endpoint", endpoint.get("normalised_url") or endpoint.get("path") or "Endpoint candidate", endpoint.get("source") or "endpoint_discovery", endpoint.get("endpoint_category") or "", f"endpoint-{index}", mapped))
    for index, parameter in enumerate(parameter_results):
        mappings = map_parameter_to_owasp(parameter, mapping)
        for mapped in mappings:
            title = f"{parameter.get('parameter_name') or 'parameter'} on {parameter.get('path') or parameter.get('url') or 'endpoint'}"
            mapped_items.append(_mapped_output("parameter", title, "parameter_intelligence", parameter.get("parameter_type") or "", f"parameter-{index}", mapped))
    return mapped_items


def attach_owasp_metadata(scan_result: dict[str, Any], mapping_path: str | Path = OWASP_MAPPING_PATH) -> dict[str, Any]:
    mapping = load_owasp_mapping(mapping_path)
    findings = findings_to_dicts(scan_result.get("findings", []))
    mapped_items = build_owasp_mapped_items(
        findings,
        scan_result.get("endpoint_results", []) or [],
        scan_result.get("parameter_results", []) or [],
        mapping,
    )
    for index, finding in enumerate(findings):
        finding["owasp_categories"] = [
            _public_mapping_fields(item)
            for item in mapped_items
            if item.get("item_type") == "finding" and item.get("item_key") == f"finding-{index}"
        ]
    summary = build_owasp_summary(
        findings,
        scan_result.get("endpoint_results", []) or [],
        scan_result.get("parameter_results", []) or [],
        mapping,
    )
    summary["mapped_findings_count"] = len({item["item_key"] for item in mapped_items if item["item_type"] == "finding"})
    scan_result["findings"] = findings
    scan_result["owasp_top10_summary"] = summary
    scan_result["owasp_top10_mapped_items"] = mapped_items
    scan_result["findings"].append(_owasp_completed_finding(summary))
    return scan_result


def _owasp_completed_finding(summary: dict[str, Any]) -> dict[str, Any]:
    return finding_to_dict(
        create_finding(
            title="OWASP Top 10 Mapping Completed",
            severity="Informational",
            category="OWASP Top 10",
            affected_host="owasp-mapping",
            evidence="VulScan mapped findings and candidates to OWASP Top 10:2025 indicator categories.",
            recommendation="Use OWASP mapping to guide manual validation and report organisation.",
            source="owasp_mapping",
            confidence="High",
            impact=f"{summary.get('mapped_findings_count', 0)} finding(s) and candidate groups were mapped to OWASP indicators.",
            verification="Review owasp_top10_summary and owasp_top10_mapped_items in the report.",
            limitation="OWASP mapping is indicator-based and does not confirm vulnerability presence.",
        )
    )


def _mapping_item(category: dict[str, Any], confidence: str, reason: str, source: str, manual_validation_required: bool) -> dict[str, Any]:
    return {
        "owasp_id": category["owasp_id"],
        "owasp_name": category["name"],
        "confidence": confidence,
        "mapping_reason": reason,
        "source": source,
        "limitation": category.get("limitation") or OWASP_LIMITATIONS[0],
        "manual_validation_required": manual_validation_required,
    }


def _mapped_output(item_type: str, title: str, source: str, category: str, item_key: str, mapped: dict[str, Any]) -> dict[str, Any]:
    return {
        "item_type": item_type,
        "item_key": item_key,
        "title": str(title or ""),
        "source": str(source or mapped.get("source") or ""),
        "category": str(category or ""),
        **mapped,
    }


def _public_mapping_fields(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "owasp_id": item["owasp_id"],
        "owasp_name": item["owasp_name"],
        "confidence": item["confidence"],
        "mapping_reason": item["mapping_reason"],
        "manual_validation_required": item["manual_validation_required"],
    }


def _top_three(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rank = {"High": 0, "Medium": 1, "Low": 2}
    unique: dict[str, dict[str, Any]] = {}
    for item in sorted(items, key=lambda value: rank.get(value.get("confidence", "Low"), 9)):
        unique.setdefault(item["owasp_id"], item)
    return list(unique.values())[:3]


def _keyword_match(text: str, keywords: list[str]) -> bool:
    return any(str(keyword).lower() in text for keyword in keywords if str(keyword).strip())


def _service_crypto_signal(finding: dict[str, Any], category: dict[str, Any]) -> bool:
    if category.get("owasp_id") != "A04:2025":
        return False
    service = str(finding.get("service") or "").lower()
    return service in {"ftp", "telnet"} or ("http" in service and "login" in str(finding.get("title") or "").lower())


def _finding_title(finding: dict[str, Any]) -> str:
    return str(finding.get("title") or finding.get("id") or "Finding")


def _highest_signal_categories(mapping: dict[str, Any], counts: Counter[str]) -> list[dict[str, Any]]:
    names = {category["owasp_id"]: category["name"] for category in mapping["categories"]}
    return [
        {"owasp_id": owasp_id, "owasp_name": names.get(owasp_id, ""), "count": count}
        for owasp_id, count in counts.most_common(3)
        if count > 0
    ]


def _fallback_mapping() -> dict[str, Any]:
    return {
        "version": OWASP_VERSION,
        "categories": [
            {"owasp_id": "A01:2025", "name": "Broken Access Control", "short_description": "Access control indicators.", "indicator_keywords": ["idor", "admin", "user id"], "finding_sources": [], "endpoint_categories": ["admin", "user_account"], "parameter_types": ["idor"], "recommendation_theme": "Review authorization.", "limitation": OWASP_LIMITATIONS[0]},
            {"owasp_id": "A02:2025", "name": "Security Misconfiguration", "short_description": "Configuration indicators.", "indicator_keywords": ["missing security header", "debug"], "finding_sources": ["web_header_audit"], "endpoint_categories": ["debug"], "parameter_types": ["debug_config"], "recommendation_theme": "Review hardening.", "limitation": OWASP_LIMITATIONS[0]},
            {"owasp_id": "A03:2025", "name": "Software Supply Chain Failures", "short_description": "Component indicators.", "indicator_keywords": ["cve", "component"], "finding_sources": ["vuln_intel", "cve_feed"], "endpoint_categories": [], "parameter_types": [], "recommendation_theme": "Patch components.", "limitation": OWASP_LIMITATIONS[0]},
            {"owasp_id": "A04:2025", "name": "Cryptographic Failures", "short_description": "Transport and sensitive data indicators.", "indicator_keywords": ["missing hsts", "insecure cookie", "cleartext"], "finding_sources": ["web_cookie_audit", "tls_audit"], "endpoint_categories": [], "parameter_types": ["sensitive_token"], "recommendation_theme": "Review crypto.", "limitation": OWASP_LIMITATIONS[0]},
            {"owasp_id": "A05:2025", "name": "Injection", "short_description": "Input indicators.", "indicator_keywords": ["injection", "query", "search"], "finding_sources": ["web_form_audit"], "endpoint_categories": ["search"], "parameter_types": ["injection_reflection"], "recommendation_theme": "Review input handling.", "limitation": OWASP_LIMITATIONS[0]},
            {"owasp_id": "A06:2025", "name": "Insecure Design", "short_description": "Design review indicators.", "indicator_keywords": ["workflow", "password reset"], "finding_sources": [], "endpoint_categories": ["password_reset", "payment_or_billing"], "parameter_types": [], "recommendation_theme": "Review design.", "limitation": OWASP_LIMITATIONS[0]},
            {"owasp_id": "A07:2025", "name": "Authentication Failures", "short_description": "Auth indicators.", "indicator_keywords": ["login", "session", "cookie"], "finding_sources": ["web_cookie_audit"], "endpoint_categories": ["authentication"], "parameter_types": ["sensitive_token"], "recommendation_theme": "Review auth.", "limitation": OWASP_LIMITATIONS[0]},
            {"owasp_id": "A08:2025", "name": "Software or Data Integrity Failures", "short_description": "Integrity indicators.", "indicator_keywords": ["upload", "import", "export"], "finding_sources": [], "endpoint_categories": ["file_upload", "export"], "parameter_types": ["path_traversal"], "recommendation_theme": "Review integrity.", "limitation": OWASP_LIMITATIONS[0]},
            {"owasp_id": "A09:2025", "name": "Security Logging & Alerting Failures", "short_description": "Logging indicators.", "indicator_keywords": ["logging disabled", "audit disabled"], "finding_sources": ["windows_audit", "ssh_audit"], "endpoint_categories": [], "parameter_types": [], "recommendation_theme": "Review logging.", "limitation": OWASP_LIMITATIONS[0]},
            {"owasp_id": "A10:2025", "name": "Mishandling of Exceptional Conditions", "short_description": "Error handling indicators.", "indicator_keywords": ["stack trace", "exception", "500 error"], "finding_sources": [], "endpoint_categories": [], "parameter_types": [], "recommendation_theme": "Review error handling.", "limitation": OWASP_LIMITATIONS[0]},
        ],
    }
