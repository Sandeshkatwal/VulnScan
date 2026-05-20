"""Local vulnerability intelligence matching for VulScan."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scanner.finding import Confidence, Severity, create_finding
from scanner.software_inventory import build_software_inventory


DEFAULT_RULES_PATH = Path("data") / "vuln_intel" / "sample_vuln_rules.json"
SUPPORTED_MATCH_FIELDS = {
    "service_name",
    "product",
    "version_exact",
    "version_contains",
    "port",
    "protocol",
    "source",
}
OPTIONAL_INTELLIGENCE_FIELDS = {
    "cve",
    "cvss_score",
    "epss_score",
    "epss_percentile",
    "exploit_available",
    "exploit_reference_label",
    "severity",
    "category",
    "confidence",
    "recommendation",
    "limitation",
    "references",
}
VULN_INTEL_LIMITATION = "Version 14.0 uses local rules only and does not confirm CVE exploitability."


class VulnIntelRulesError(ValueError):
    """Raised when a local vulnerability intelligence ruleset is invalid."""


def disabled_vulnerability_intelligence_summary() -> dict[str, Any]:
    """Return a consistent disabled vulnerability intelligence summary."""
    return {
        "enabled": False,
        "ruleset_name": None,
        "ruleset_version": None,
        "rules_loaded": 0,
        "inventory_items_checked": 0,
        "matches_found": 0,
        "cve_matches_count": 0,
        "exploit_available_count": 0,
        "highest_cvss_score": None,
        "highest_epss_score": None,
        "highest_intel_risk_label": "Informational",
        "limitations": [VULN_INTEL_LIMITATION],
        "matches": [],
    }


def run_vulnerability_intelligence(
    scan_result: dict[str, Any],
    rules_path: Path = DEFAULT_RULES_PATH,
) -> tuple[dict[str, Any], dict[str, Any], list[Any]]:
    """Build inventory, match local rules, and generate standard findings."""
    inventory = build_software_inventory(scan_result)
    ruleset = load_ruleset(rules_path)
    matches = match_rules(inventory.get("items", []), ruleset.get("rules", []))
    summary = build_vulnerability_intelligence_summary(
        ruleset=ruleset,
        inventory=inventory,
        matches=matches,
    )
    findings = build_vulnerability_intelligence_findings(matches, summary, scan_result)
    return inventory, summary, findings


def load_ruleset(path: Path) -> dict[str, Any]:
    """Load and validate a local vulnerability intelligence ruleset."""
    rules_path = Path(path)
    if not rules_path.exists():
        raise VulnIntelRulesError(f"Vulnerability rules file was not found: {rules_path}")
    try:
        data = json.loads(rules_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise VulnIntelRulesError(f"Vulnerability rules file is not valid JSON: {rules_path}") from exc

    validate_ruleset(data)
    return data


def validate_ruleset(data: Any) -> None:
    """Validate a VulScan local vulnerability intelligence ruleset."""
    if not isinstance(data, dict):
        raise VulnIntelRulesError("Vulnerability ruleset must be a JSON object.")
    if not str(data.get("ruleset_name") or "").strip():
        raise VulnIntelRulesError("Vulnerability ruleset is missing ruleset_name.")
    if not str(data.get("ruleset_version") or "").strip():
        raise VulnIntelRulesError("Vulnerability ruleset is missing ruleset_version.")
    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        raise VulnIntelRulesError("Vulnerability ruleset must contain at least one rule.")
    for index, rule in enumerate(rules, start=1):
        _validate_rule(rule, index)


def match_rules(items: list[dict[str, Any]], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Match local rules against normalised inventory items."""
    matches: list[dict[str, Any]] = []
    for item in items:
        for rule in rules:
            if _rule_matches_item(rule, item):
                matches.append(_build_match(rule, item))
    return matches


def build_vulnerability_intelligence_summary(
    *,
    ruleset: dict[str, Any],
    inventory: dict[str, Any],
    matches: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the top-level vulnerability intelligence summary."""
    cvss_scores = [_as_float(match.get("cvss_score")) for match in matches]
    epss_scores = [_as_float(match.get("epss_score")) for match in matches]
    cvss_scores = [score for score in cvss_scores if score is not None]
    epss_scores = [score for score in epss_scores if score is not None]
    return {
        "enabled": True,
        "ruleset_name": ruleset.get("ruleset_name"),
        "ruleset_version": ruleset.get("ruleset_version"),
        "rules_loaded": len(ruleset.get("rules") or []),
        "inventory_items_checked": int(inventory.get("total_items") or 0),
        "matches_found": len(matches),
        "cve_matches_count": sum(1 for match in matches if match.get("cve")),
        "exploit_available_count": sum(1 for match in matches if match.get("exploit_available") is True),
        "highest_cvss_score": max(cvss_scores) if cvss_scores else None,
        "highest_epss_score": max(epss_scores) if epss_scores else None,
        "highest_intel_risk_label": _highest_severity(matches),
        "limitations": [
            "Vulnerability intelligence uses local rules only in Version 14.0.",
            "Matches are indicators requiring validation and do not prove exploitability.",
            "Service exposure alone does not confirm a vulnerability.",
        ],
        "matches": matches,
    }


def build_vulnerability_intelligence_findings(
    matches: list[dict[str, Any]],
    summary: dict[str, Any],
    scan_result: dict[str, Any],
) -> list[Any]:
    """Create standard VulScan findings from vulnerability intelligence matches."""
    findings: list[Any] = [
        create_finding(
            title="Vulnerability Intelligence Matching Completed",
            severity="Informational",
            category="Vulnerability Intelligence",
            affected_host=str(scan_result.get("host") or ""),
            evidence="Local vulnerability intelligence rules were evaluated against discovered services/software.",
            confidence="High",
            impact="Local intelligence matches can help prioritise authorised manual verification and remediation.",
            recommendation="Use intelligence matches to prioritise manual verification and remediation.",
            verification="Review the vulnerability_intelligence section in the report.",
            limitation="Version 14.0 uses local rules only and does not perform live CVE, EPSS, or exploit lookups.",
            source="vuln_intel",
            evidence_details={
                "ruleset_name": summary.get("ruleset_name"),
                "ruleset_version": summary.get("ruleset_version"),
                "rules_loaded": summary.get("rules_loaded"),
                "inventory_items_checked": summary.get("inventory_items_checked"),
                "matches_found": summary.get("matches_found"),
            },
        )
    ]
    for match in matches:
        item = match.get("matched_item") or {}
        rule_id = str(match.get("rule_id") or "")
        service = str(item.get("service_name") or "unknown")
        host = str(item.get("host") or scan_result.get("host") or "")
        port = item.get("port")
        protocol = str(item.get("protocol") or "tcp")
        cve = str(match.get("cve") or "")
        title = str(match.get("title") or rule_id)
        if cve and cve not in title:
            title = f"{title} ({cve})"
        evidence = f"Local intelligence rule {rule_id} matched service {service} on {host}"
        if port:
            evidence += f":{port}/{protocol}"
        evidence += "."
        if cve:
            evidence += f" Local rule references {cve}; VulScan does not confirm vulnerability without supporting product/version evidence."
        limitation = " ".join(
            part
            for part in [str(match.get("limitation") or ""), VULN_INTEL_LIMITATION]
            if part
        )
        findings.append(
            create_finding(
                title=title,
                severity=_safe_severity(match.get("severity")),
                category=str(match.get("category") or "Vulnerability Intelligence"),
                affected_host=host or None,
                affected_port=int(port) if port is not None else None,
                service=service,
                evidence=evidence,
                confidence=_safe_confidence(match.get("confidence")),
                impact="The matched intelligence indicator may increase remediation priority, but it requires validation in context.",
                recommendation=str(match.get("recommendation") or "Review the matched service and validate applicability before remediation."),
                verification="Manually validate product, version, exposure, configuration, and business context.",
                limitation=limitation,
                source="vuln_intel",
                evidence_details={
                    "rule_id": rule_id,
                    "cve": match.get("cve"),
                    "cvss_score": match.get("cvss_score"),
                    "epss_score": match.get("epss_score"),
                    "epss_percentile": match.get("epss_percentile"),
                    "exploit_available": match.get("exploit_available"),
                    "exploit_reference_label": match.get("exploit_reference_label"),
                    "matched_item": item,
                    "references": match.get("references") or [],
                    "limitation": match.get("limitation"),
                },
            )
        )
    return findings


def _validate_rule(rule: Any, index: int) -> None:
    if not isinstance(rule, dict):
        raise VulnIntelRulesError(f"Vulnerability rule {index} must be an object.")
    if not str(rule.get("rule_id") or "").strip():
        raise VulnIntelRulesError(f"Vulnerability rule {index} is missing rule_id.")
    if not str(rule.get("title") or "").strip():
        raise VulnIntelRulesError(f"Vulnerability rule {rule.get('rule_id') or index} is missing title.")
    match = rule.get("match")
    if not isinstance(match, dict) or not match:
        raise VulnIntelRulesError(f"Vulnerability rule {rule.get('rule_id')} must include a non-empty match object.")
    unsupported = set(match) - SUPPORTED_MATCH_FIELDS
    if unsupported:
        raise VulnIntelRulesError(
            f"Vulnerability rule {rule.get('rule_id')} contains unsupported match field(s): {', '.join(sorted(unsupported))}."
        )
    if not any(_has_match_value(value) for value in match.values()):
        raise VulnIntelRulesError(f"Vulnerability rule {rule.get('rule_id')} has no usable match values.")
    severity = rule.get("severity", "Informational")
    _safe_severity(severity)
    confidence = rule.get("confidence", "Medium")
    _safe_confidence(confidence)


def _rule_matches_item(rule: dict[str, Any], item: dict[str, Any]) -> bool:
    match = rule.get("match") or {}
    if set(match).issubset({"service_name", "port"}) and {"service_name", "port"}.issubset(match):
        return _field_matches("service_name", match["service_name"], item) or _field_matches("port", match["port"], item)
    return all(_field_matches(field, expected, item) for field, expected in match.items())


def _field_matches(field: str, expected: Any, item: dict[str, Any]) -> bool:
    expected_values = expected if isinstance(expected, list) else [expected]
    expected_values = [value for value in expected_values if value is not None and value != ""]
    if not expected_values:
        return False
    if field == "version_exact":
        actual = item.get("version")
        return any(_lower(actual) == _lower(value) for value in expected_values)
    if field == "version_contains":
        actual = _lower(item.get("version"))
        return bool(actual) and any(_lower(value) in actual for value in expected_values)
    if field == "port":
        actual_port = item.get("port")
        return any(_safe_int(value) == actual_port for value in expected_values)
    actual = item.get(field)
    return any(_lower(actual) == _lower(value) for value in expected_values)


def _build_match(rule: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    result = {
        "rule_id": rule.get("rule_id"),
        "title": rule.get("title"),
        "matched_item": dict(item),
        "cve": rule.get("cve"),
        "cvss_score": rule.get("cvss_score"),
        "epss_score": rule.get("epss_score"),
        "epss_percentile": rule.get("epss_percentile"),
        "exploit_available": bool(rule.get("exploit_available")) if rule.get("exploit_available") is not None else False,
        "exploit_reference_label": rule.get("exploit_reference_label"),
        "severity": rule.get("severity") or "Informational",
        "category": rule.get("category") or "Vulnerability Intelligence",
        "confidence": rule.get("confidence") or "Medium",
        "recommendation": rule.get("recommendation") or "Review the matched service and validate applicability.",
        "limitation": rule.get("limitation") or "Local intelligence match requires manual validation.",
        "references": list(rule.get("references") or []),
        "evidence": item.get("evidence"),
    }
    return result


def _highest_severity(matches: list[dict[str, Any]]) -> str:
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}
    highest = "Informational"
    for match in matches:
        severity = _safe_severity(match.get("severity"))
        if order[severity] > order[highest]:
            highest = severity
    return highest


def _safe_severity(value: Any) -> Severity:
    severity = str(value or "Informational").strip()
    allowed = {"Critical", "High", "Medium", "Low", "Informational"}
    if severity not in allowed:
        raise VulnIntelRulesError(f"Unsupported vulnerability intelligence severity: {severity}")
    return severity  # type: ignore[return-value]


def _safe_confidence(value: Any) -> Confidence:
    confidence = str(value or "Medium").strip()
    allowed = {"High", "Medium", "Low"}
    if confidence not in allowed:
        raise VulnIntelRulesError(f"Unsupported vulnerability intelligence confidence: {confidence}")
    return confidence  # type: ignore[return-value]


def _has_match_value(value: Any) -> bool:
    if isinstance(value, list):
        return any(item is not None and item != "" for item in value)
    return value is not None and value != ""


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
