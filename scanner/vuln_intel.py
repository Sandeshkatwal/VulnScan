"""Local vulnerability intelligence matching for VulScan."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from scanner.finding import Confidence, Severity, create_finding
from scanner.service_fingerprint import normalise_cpe, normalise_product, normalise_vendor
from scanner.software_inventory import build_software_inventory


DEFAULT_RULES_PATH = Path("data") / "vuln_intel" / "sample_vuln_rules.json"
IDENTITY_MATCH_FIELDS = {
    "service_name",
    "vendor",
    "product",
    "cpe",
    "cpe_prefix",
    "port",
    "protocol",
    "source",
}
VERSION_MATCH_FIELDS = {
    "version_exact",
    "version_contains",
    "version_startswith",
    "version_less_than",
    "version_less_than_or_equal",
    "version_greater_than",
    "version_greater_than_or_equal",
    "version_between",
}
SUPPORTED_MATCH_FIELDS = IDENTITY_MATCH_FIELDS | VERSION_MATCH_FIELDS
OPTIONAL_INTELLIGENCE_FIELDS = {
    "cve",
    "cvss_score",
    "cvss_vector",
    "epss_score",
    "epss_percentile",
    "exploit_available",
    "exploit_reference_label",
    "affected_versions",
    "fixed_version",
    "severity",
    "category",
    "confidence",
    "recommendation",
    "limitation",
    "references",
    "detection_note",
    "allow_unknown_version",
}
VULN_INTEL_LIMITATION = "Version 14.5 uses local rules, local CVE feed files, local EPSS metadata files, and local exploit metadata files only; it does not perform live feed validation."


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
        "version_rules_loaded": 0,
        "version_rules_evaluated": 0,
        "version_matches_found": 0,
        "unknown_version_count": 0,
        "insufficient_evidence_count": 0,
        "confirmed_version_match_count": 0,
        "local_cve_metadata_count": 0,
        "exploit_available_count": 0,
        "highest_cvss_score": None,
        "highest_epss_score": None,
        "highest_intel_risk_label": "Informational",
        "limitations": [VULN_INTEL_LIMITATION],
        "matches": [],
        "cve_feed_enabled": False,
        "cve_feed_name": None,
        "cve_feed_version": None,
        "cve_feed_items_loaded": 0,
        "cve_feed_items_evaluated": 0,
        "cve_feed_matches_found": 0,
        "cve_feed_insufficient_evidence_count": 0,
        "cve_feed_unknown_version_count": 0,
        "cve_feed_highest_cvss": None,
        "cve_feed_exploit_available_count": 0,
        "cve_feed_limitations": [],
        "cve_feed_matches": [],
        **_disabled_epss_summary(),
        **_disabled_exploit_metadata_summary(),
    }


def run_vulnerability_intelligence(
    scan_result: dict[str, Any],
    rules_path: Path = DEFAULT_RULES_PATH,
    use_cve_feed: bool = False,
    cve_feed_path: Path | None = None,
    use_epss: bool = False,
    epss_file: Path | None = None,
    use_exploit_metadata: bool = False,
    exploit_metadata_file: Path | None = None,
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
    cve_feed_summary = _disabled_cve_feed_summary()
    epss_summary = _disabled_epss_summary()
    exploit_metadata_summary = _disabled_exploit_metadata_summary()
    if use_cve_feed:
        from scanner.cve_feed import (
            DEFAULT_CVE_FEED_PATH,
            CveFeedError,
            build_cve_feed_findings,
            build_cve_feed_summary,
            load_cve_feed,
            match_cve_feed,
        )
        from scanner.epss_importer import (
            DEFAULT_EPSS_PATH,
            EpssImportError,
            build_epss_import_findings,
            build_epss_summary,
            enrich_cve_matches_with_epss,
            load_epss_file,
        )
        from scanner.exploit_metadata import (
            DEFAULT_EXPLOIT_METADATA_PATH,
            ExploitMetadataError,
            build_exploit_metadata_import_findings,
            build_exploit_metadata_summary,
            enrich_cve_matches_with_exploit_metadata,
            load_exploit_metadata,
        )

        selected_feed_path = cve_feed_path or DEFAULT_CVE_FEED_PATH
        try:
            feed = load_cve_feed(selected_feed_path)
        except CveFeedError as exc:
            cve_feed_summary = build_cve_feed_summary(
                feed=None,
                matches=[],
                enabled=True,
                error=f"Local CVE feed was not loaded: {exc}",
            )
        else:
            cve_matches = match_cve_feed(inventory.get("items", []), feed)
            epss_failed = False
            if use_epss:
                selected_epss_path = epss_file or DEFAULT_EPSS_PATH
                try:
                    epss_data = load_epss_file(selected_epss_path)
                except EpssImportError as exc:
                    epss_failed = True
                    epss_summary = build_epss_summary(
                        enabled=True,
                        epss_file=selected_epss_path,
                        epss_data=None,
                        cve_matches=cve_matches,
                        error=f"Local EPSS metadata was not loaded: {exc}",
                    )
                else:
                    cve_matches = enrich_cve_matches_with_epss(cve_matches, epss_data)
                    epss_summary = build_epss_summary(
                        enabled=True,
                        epss_file=selected_epss_path,
                        epss_data=epss_data,
                        cve_matches=cve_matches,
                    )
            exploit_metadata_failed = False
            if use_exploit_metadata:
                selected_exploit_metadata_path = exploit_metadata_file or DEFAULT_EXPLOIT_METADATA_PATH
                try:
                    exploit_metadata = load_exploit_metadata(selected_exploit_metadata_path)
                except ExploitMetadataError as exc:
                    exploit_metadata_failed = True
                    exploit_metadata_summary = build_exploit_metadata_summary(
                        enabled=True,
                        metadata_file=selected_exploit_metadata_path,
                        metadata=None,
                        cve_matches=cve_matches,
                        error=f"Local exploit metadata was not loaded: {exc}",
                    )
                else:
                    cve_matches = enrich_cve_matches_with_exploit_metadata(cve_matches, exploit_metadata)
                    exploit_metadata_summary = build_exploit_metadata_summary(
                        enabled=True,
                        metadata_file=selected_exploit_metadata_path,
                        metadata=exploit_metadata,
                        cve_matches=cve_matches,
                    )
            cve_feed_summary = build_cve_feed_summary(
                feed=feed,
                matches=cve_matches,
                enabled=True,
            )
            findings.extend(build_cve_feed_findings(cve_matches, cve_feed_summary, scan_result))
            if use_epss:
                findings.extend(build_epss_import_findings(epss_summary, scan_result, failed=epss_failed))
            if use_exploit_metadata:
                findings.extend(
                    build_exploit_metadata_import_findings(
                        exploit_metadata_summary,
                        scan_result,
                        failed=exploit_metadata_failed,
                    )
                )
    elif use_epss:
        from scanner.epss_importer import DEFAULT_EPSS_PATH, build_epss_summary

        selected_epss_path = epss_file or DEFAULT_EPSS_PATH
        epss_summary = build_epss_summary(
            enabled=True,
            epss_file=selected_epss_path,
            epss_data=None,
            cve_matches=[],
            error="EPSS enrichment was requested without local CVE feed matching.",
        )
    elif use_exploit_metadata:
        from scanner.exploit_metadata import DEFAULT_EXPLOIT_METADATA_PATH, build_exploit_metadata_summary

        selected_exploit_metadata_path = exploit_metadata_file or DEFAULT_EXPLOIT_METADATA_PATH
        exploit_metadata_summary = build_exploit_metadata_summary(
            enabled=True,
            metadata_file=selected_exploit_metadata_path,
            metadata=None,
            cve_matches=[],
            error="Exploit metadata enrichment was requested without local CVE feed matching.",
        )
    summary.update(cve_feed_summary)
    summary.update(epss_summary)
    summary.update(exploit_metadata_summary)
    _refresh_combined_summary_metrics(summary)
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


def parse_version(value: Any) -> tuple[int, ...] | None:
    """Parse common service version strings into comparable numeric tuples."""
    raw = str(value or "").strip().lower()
    if not raw:
        return None
    parts = re.findall(r"\d+", raw)
    if not parts:
        return None
    try:
        return tuple(int(part) for part in parts)
    except ValueError:
        return None


def compare_versions(left: Any, right: Any) -> int | None:
    """Compare two version strings. Return -1, 0, 1, or None if unparsable."""
    left_parts = parse_version(left)
    right_parts = parse_version(right)
    if left_parts is None or right_parts is None:
        return None
    max_len = max(len(left_parts), len(right_parts))
    left_padded = left_parts + (0,) * (max_len - len(left_parts))
    right_padded = right_parts + (0,) * (max_len - len(right_parts))
    if left_padded < right_padded:
        return -1
    if left_padded > right_padded:
        return 1
    return 0


def match_rules(items: list[dict[str, Any]], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Match local rules against normalised inventory items."""
    matches: list[dict[str, Any]] = []
    for item in items:
        for rule in rules:
            evaluation = _evaluate_rule(rule, item)
            if evaluation["match_status"] in {"matched", "unknown_version", "insufficient_evidence"}:
                matches.append(_build_match(rule, item, evaluation))
    return matches


def build_vulnerability_intelligence_summary(
    *,
    ruleset: dict[str, Any],
    inventory: dict[str, Any],
    matches: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the top-level vulnerability intelligence summary."""
    finding_matches = _finding_eligible_matches(matches)
    cvss_scores = [_as_float(match.get("cvss_score")) for match in finding_matches]
    epss_scores = [_as_float(match.get("epss_score")) for match in finding_matches]
    cvss_scores = [score for score in cvss_scores if score is not None]
    epss_scores = [score for score in epss_scores if score is not None]
    rules = list(ruleset.get("rules") or [])
    version_rules_loaded = sum(1 for rule in rules if _version_condition(rule))
    version_matches = [match for match in matches if match.get("version_condition") and match.get("match_status") == "matched"]
    confirmed_version_matches = [
        match
        for match in version_matches
        if match.get("matched_item", {}).get("product") and match.get("matched_item", {}).get("version")
    ]
    return {
        "enabled": True,
        "ruleset_name": ruleset.get("ruleset_name"),
        "ruleset_version": ruleset.get("ruleset_version"),
        "rules_loaded": len(rules),
        "inventory_items_checked": int(inventory.get("total_items") or 0),
        "matches_found": len(finding_matches),
        "cve_matches_count": sum(1 for match in finding_matches if match.get("cve")),
        "version_rules_loaded": version_rules_loaded,
        "version_rules_evaluated": sum(1 for match in matches if match.get("version_condition")),
        "version_matches_found": len(version_matches),
        "unknown_version_count": sum(1 for match in matches if match.get("match_status") == "unknown_version"),
        "insufficient_evidence_count": sum(1 for match in matches if match.get("match_status") == "insufficient_evidence"),
        "confirmed_version_match_count": len(confirmed_version_matches),
        "local_cve_metadata_count": sum(1 for match in finding_matches if match.get("cve") or match.get("cvss_score") is not None),
        "exploit_available_count": sum(1 for match in finding_matches if match.get("exploit_available") is True),
        "highest_cvss_score": max(cvss_scores) if cvss_scores else None,
        "highest_epss_score": max(epss_scores) if epss_scores else None,
        "highest_intel_risk_label": _highest_severity(finding_matches),
        "limitations": [
            VULN_INTEL_LIMITATION,
            "Version-specific rules require local product and version evidence unless allow_unknown_version is explicitly set.",
            "CVE, CVSS, EPSS, and exploit availability fields are local metadata only.",
        ],
        "matches": matches,
        **_disabled_cve_feed_summary(),
        **_disabled_epss_summary(),
        **_disabled_exploit_metadata_summary(),
    }


def _disabled_cve_feed_summary() -> dict[str, Any]:
    return {
        "cve_feed_enabled": False,
        "cve_feed_name": None,
        "cve_feed_version": None,
        "cve_feed_items_loaded": 0,
        "cve_feed_items_evaluated": 0,
        "cve_feed_matches_found": 0,
        "cve_feed_insufficient_evidence_count": 0,
        "cve_feed_unknown_version_count": 0,
        "cve_feed_highest_cvss": None,
        "cve_feed_exploit_available_count": 0,
        "cve_feed_limitations": [],
        "cve_feed_matches": [],
    }


def _disabled_epss_summary() -> dict[str, Any]:
    return {
        "epss_enabled": False,
        "epss_file": None,
        "epss_records_loaded": 0,
        "epss_invalid_records": 0,
        "epss_duplicate_records": 0,
        "epss_matches_enriched": 0,
        "epss_missing_for_cve_count": 0,
        "highest_epss_percentile": None,
        "high_epss_count": 0,
        "medium_epss_count": 0,
        "low_epss_count": 0,
        "epss_limitations": [],
    }


def _disabled_exploit_metadata_summary() -> dict[str, Any]:
    return {
        "exploit_metadata_enabled": False,
        "exploit_metadata_file": None,
        "exploit_metadata_feed_name": None,
        "exploit_metadata_feed_version": None,
        "exploit_metadata_records_loaded": 0,
        "exploit_metadata_invalid_records": 0,
        "exploit_metadata_unsafe_records_skipped": 0,
        "exploit_metadata_duplicate_records": 0,
        "exploit_metadata_matches_enriched": 0,
        "exploit_metadata_missing_for_cve_count": 0,
        "active_exploitation_reported_count": 0,
        "exploit_maturity_counts": {
            "active_exploitation_reported": 0,
            "none": 0,
            "poc": 0,
            "unknown": 0,
            "weaponized": 0,
        },
        "exploit_metadata_limitations": [],
    }


def _refresh_combined_summary_metrics(summary: dict[str, Any]) -> None:
    """Keep top-level intelligence metrics conservative across rules and feeds."""
    rule_highest = _as_float(summary.get("highest_cvss_score"))
    feed_highest = _as_float(summary.get("cve_feed_highest_cvss"))
    feed_epss = _as_float(summary.get("highest_epss_score"))
    cvss_scores = [score for score in (rule_highest, feed_highest) if score is not None]
    if cvss_scores:
        summary["highest_cvss_score"] = max(cvss_scores)
    summary["exploit_available_count"] = int(summary.get("exploit_available_count") or 0) + int(
        summary.get("cve_feed_exploit_available_count") or 0
    )
    if summary.get("cve_feed_limitations"):
        limitations = list(summary.get("limitations") or [])
        for limitation in summary.get("cve_feed_limitations") or []:
            if limitation not in limitations:
                limitations.append(limitation)
        summary["limitations"] = limitations
    if feed_epss is not None:
        summary["highest_epss_score"] = feed_epss
    if summary.get("epss_limitations"):
        limitations = list(summary.get("limitations") or [])
        for limitation in summary.get("epss_limitations") or []:
            if limitation not in limitations:
                limitations.append(limitation)
        summary["limitations"] = limitations
    if summary.get("exploit_metadata_limitations"):
        limitations = list(summary.get("limitations") or [])
        for limitation in summary.get("exploit_metadata_limitations") or []:
            if limitation not in limitations:
                limitations.append(limitation)
        summary["limitations"] = limitations


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
            limitation="Version 14.5 uses local rules, local CVE feed files, local EPSS metadata files, and local exploit metadata files only and does not perform live CVE, EPSS, exploit metadata, or exploit lookups.",
            source="vuln_intel",
            evidence_details={
                "ruleset_name": summary.get("ruleset_name"),
                "ruleset_version": summary.get("ruleset_version"),
                "rules_loaded": summary.get("rules_loaded"),
                "inventory_items_checked": summary.get("inventory_items_checked"),
                "matches_found": summary.get("matches_found"),
                "unknown_version_count": summary.get("unknown_version_count"),
            },
        )
    ]
    for match in _finding_eligible_matches(matches):
        item = match.get("matched_item") or {}
        rule_id = str(match.get("rule_id") or "")
        product = str(item.get("product") or item.get("service_name") or "unknown")
        version = item.get("version")
        host = str(item.get("host") or scan_result.get("host") or "")
        port = item.get("port")
        cve = str(match.get("cve") or "")
        title = str(match.get("title") or rule_id)
        if cve and cve not in title:
            title = f"{title} ({cve})"
        evidence = _finding_evidence(match, product, version)
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
                service=str(item.get("service_name") or "unknown"),
                evidence=evidence,
                confidence=_safe_confidence(match.get("match_confidence") or match.get("confidence")),
                impact="The matched local intelligence indicator may increase remediation priority, but it requires validation in context.",
                recommendation=str(match.get("recommendation") or "Review the matched service and validate applicability before remediation."),
                verification="Manually validate product, version, exposure, configuration, and business context.",
                limitation=limitation,
                source="vuln_intel",
                evidence_details={
                    "rule_id": rule_id,
                    "cve": match.get("cve"),
                    "cvss_score": match.get("cvss_score"),
                    "cvss_vector": match.get("cvss_vector"),
                    "epss_score": match.get("epss_score"),
                    "epss_percentile": match.get("epss_percentile"),
                    "exploit_available": match.get("exploit_available"),
                    "exploit_reference_label": match.get("exploit_reference_label"),
                    "affected_versions": match.get("affected_versions"),
                    "fixed_version": match.get("fixed_version"),
                    "match_status": match.get("match_status"),
                    "match_confidence": match.get("match_confidence"),
                    "version_condition": match.get("version_condition"),
                    "detection_note": match.get("detection_note"),
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
    _validate_version_conditions(rule)
    _safe_severity(rule.get("severity", "Informational"))
    _safe_confidence(rule.get("confidence", "Medium"))
    _safe_float_metadata(rule, "cvss_score", minimum=0.0, maximum=10.0)
    _safe_float_metadata(rule, "epss_score", minimum=0.0, maximum=1.0)
    _safe_float_metadata(rule, "epss_percentile", minimum=0.0, maximum=1.0)
    if rule.get("references") is not None and not isinstance(rule.get("references"), list):
        raise VulnIntelRulesError(f"Vulnerability rule {rule.get('rule_id')} references must be a list.")


def _validate_version_conditions(rule: dict[str, Any]) -> None:
    match = rule.get("match") or {}
    operators = [field for field in VERSION_MATCH_FIELDS if field in match]
    if len(operators) > 1:
        raise VulnIntelRulesError(
            f"Vulnerability rule {rule.get('rule_id')} has conflicting version conditions: {', '.join(operators)}."
        )
    if not operators:
        return
    operator = operators[0]
    value = match.get(operator)
    if operator == "version_between":
        if not isinstance(value, list) or len(value) != 2:
            raise VulnIntelRulesError(f"Vulnerability rule {rule.get('rule_id')} version_between must contain two versions.")
        if parse_version(value[0]) is None or parse_version(value[1]) is None:
            raise VulnIntelRulesError(f"Vulnerability rule {rule.get('rule_id')} has malformed version_between values.")
        return
    if isinstance(value, list):
        raise VulnIntelRulesError(f"Vulnerability rule {rule.get('rule_id')} {operator} must be a single version string.")
    if operator in {
        "version_less_than",
        "version_less_than_or_equal",
        "version_greater_than",
        "version_greater_than_or_equal",
    } and parse_version(value) is None:
        raise VulnIntelRulesError(f"Vulnerability rule {rule.get('rule_id')} has malformed version condition.")


def _evaluate_rule(rule: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    match = rule.get("match") or {}
    if not _identity_matches(match, item):
        return {"match_status": "not_matched", "match_confidence": "Low", "version_condition": None}
    condition = _version_condition(rule)
    if not condition:
        return {"match_status": "matched", "match_confidence": "Low", "version_condition": None}
    if not item.get("product") and any(field in match for field in {"product", "vendor", "cpe", "cpe_prefix"}):
        return {"match_status": "insufficient_evidence", "match_confidence": "Low", "version_condition": condition}
    version = item.get("version")
    if not version:
        if rule.get("allow_unknown_version") is True:
            return {"match_status": "unknown_version", "match_confidence": "Low", "version_condition": condition}
        return {"match_status": "insufficient_evidence", "match_confidence": "Low", "version_condition": condition}
    status = _version_matches(condition, version)
    if status is None:
        if rule.get("allow_unknown_version") is True:
            return {"match_status": "unknown_version", "match_confidence": "Low", "version_condition": condition}
        return {"match_status": "unknown_version", "match_confidence": "Low", "version_condition": condition}
    if not status:
        return {"match_status": "not_matched", "match_confidence": "Low", "version_condition": condition}
    return {"match_status": "matched", "match_confidence": _version_match_confidence(condition), "version_condition": condition}


def _identity_matches(match: dict[str, Any], item: dict[str, Any]) -> bool:
    identity_fields = [field for field in IDENTITY_MATCH_FIELDS if field in match]
    if not identity_fields:
        return True
    if set(identity_fields).issubset({"service_name", "port"}) and {"service_name", "port"}.issubset(identity_fields):
        return _field_matches("service_name", match["service_name"], item) or _field_matches("port", match["port"], item)
    return all(_field_matches(field, match[field], item) for field in identity_fields)


def _field_matches(field: str, expected: Any, item: dict[str, Any]) -> bool:
    expected_values = expected if isinstance(expected, list) else [expected]
    expected_values = [value for value in expected_values if value is not None and value != ""]
    if not expected_values:
        return False
    if field == "port":
        actual_port = item.get("port")
        return any(_safe_int(value) == actual_port for value in expected_values)
    if field == "product":
        actual = normalise_product(item.get("product"))
        return any(actual == normalise_product(value) for value in expected_values)
    if field == "vendor":
        actual = normalise_vendor(item.get("vendor"))
        return any(actual == normalise_vendor(value) for value in expected_values)
    if field == "cpe":
        actual = normalise_cpe(item.get("cpe"))
        return any(actual == normalise_cpe(value) for value in expected_values)
    if field == "cpe_prefix":
        actual = normalise_cpe(item.get("cpe") or item.get("cpe_prefix"))
        return bool(actual) and any(actual.startswith(str(normalise_cpe(value) or "")) for value in expected_values)
    actual = _lower(item.get(field))
    return any(actual == _lower(value) for value in expected_values)


def _version_condition(rule: dict[str, Any]) -> dict[str, Any] | None:
    match = rule.get("match") or {}
    for operator in VERSION_MATCH_FIELDS:
        if operator in match:
            return {"operator": operator, "value": match[operator], "display": _condition_display(operator, match[operator])}
    return None


def _version_matches(condition: dict[str, Any], version: Any) -> bool | None:
    operator = condition["operator"]
    expected = condition["value"]
    version_text = str(version or "")
    if operator == "version_exact":
        comparison = compare_versions(version_text, expected)
        return comparison == 0 if comparison is not None else _lower(version_text) == _lower(expected)
    if operator == "version_contains":
        return _lower(expected) in _lower(version_text) if version_text else None
    if operator == "version_startswith":
        return _lower(version_text).startswith(_lower(expected)) if version_text else None
    if operator == "version_between":
        lower, upper = expected
        lower_compare = compare_versions(version_text, lower)
        upper_compare = compare_versions(version_text, upper)
        if lower_compare is None or upper_compare is None:
            return None
        return lower_compare >= 0 and upper_compare <= 0
    comparison = compare_versions(version_text, expected)
    if comparison is None:
        return None
    if operator == "version_less_than":
        return comparison < 0
    if operator == "version_less_than_or_equal":
        return comparison <= 0
    if operator == "version_greater_than":
        return comparison > 0
    if operator == "version_greater_than_or_equal":
        return comparison >= 0
    return None


def _build_match(rule: dict[str, Any], item: dict[str, Any], evaluation: dict[str, Any]) -> dict[str, Any]:
    result = {
        "rule_id": rule.get("rule_id"),
        "title": rule.get("title"),
        "matched_item": dict(item),
        "match_status": evaluation.get("match_status"),
        "match_confidence": evaluation.get("match_confidence"),
        "version_condition": evaluation.get("version_condition"),
        "cve": rule.get("cve"),
        "cvss_score": rule.get("cvss_score"),
        "cvss_vector": rule.get("cvss_vector"),
        "epss_score": rule.get("epss_score"),
        "epss_percentile": rule.get("epss_percentile"),
        "exploit_available": bool(rule.get("exploit_available")) if rule.get("exploit_available") is not None else False,
        "exploit_reference_label": rule.get("exploit_reference_label"),
        "affected_versions": rule.get("affected_versions"),
        "fixed_version": rule.get("fixed_version"),
        "severity": rule.get("severity") or "Informational",
        "category": rule.get("category") or "Vulnerability Intelligence",
        "confidence": rule.get("confidence") or evaluation.get("match_confidence") or "Medium",
        "recommendation": rule.get("recommendation") or "Review the matched service and validate applicability.",
        "limitation": rule.get("limitation") or "Local intelligence match requires manual validation.",
        "references": list(rule.get("references") or []),
        "detection_note": rule.get("detection_note"),
        "allow_unknown_version": bool(rule.get("allow_unknown_version")),
        "evidence": item.get("evidence"),
    }
    if result["match_status"] == "unknown_version":
        result["match_confidence"] = "Low"
        result["confidence"] = "Low"
    return result


def _finding_eligible_matches(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        match
        for match in matches
        if match.get("match_status") == "matched"
        or (match.get("match_status") == "unknown_version" and match.get("allow_unknown_version") is True)
    ]


def _finding_evidence(match: dict[str, Any], product: str, version: Any) -> str:
    rule_id = str(match.get("rule_id") or "")
    condition = match.get("version_condition") or {}
    cve = str(match.get("cve") or "")
    if match.get("match_status") == "unknown_version":
        return (
            f"Local rule {rule_id} matched {product} service identity, but product version was not confirmed. "
            "Treat as a low-confidence indicator. Matched using local rule metadata."
        )
    if condition:
        evidence = (
            f"Local rule {rule_id} matched product {product} version {version} because version is "
            f"{_condition_phrase(condition)}. Matched using local rule metadata."
        )
    else:
        item = match.get("matched_item") or {}
        service = item.get("service_name") or product
        evidence = f"Local intelligence rule {rule_id} matched service {service} on {item.get('host') or ''}"
        if item.get("port"):
            evidence += f":{item.get('port')}/{item.get('protocol') or 'tcp'}"
        evidence += "."
    if cve:
        evidence += f" Local rule references {cve}; this is local metadata and requires validation."
    return evidence


def _condition_display(operator: str, value: Any) -> str:
    if operator == "version_between" and isinstance(value, list) and len(value) == 2:
        return f"{value[0]} to {value[1]}"
    return f"{operator.replace('version_', '').replace('_', ' ')} {value}"


def _condition_phrase(condition: dict[str, Any]) -> str:
    operator = condition.get("operator")
    value = condition.get("value")
    phrases = {
        "version_exact": f"exactly {value}",
        "version_contains": f"containing {value}",
        "version_startswith": f"starting with {value}",
        "version_less_than": f"less than {value}",
        "version_less_than_or_equal": f"less than or equal to {value}",
        "version_greater_than": f"greater than {value}",
        "version_greater_than_or_equal": f"greater than or equal to {value}",
    }
    if operator == "version_between" and isinstance(value, list) and len(value) == 2:
        return f"between {value[0]} and {value[1]}"
    return phrases.get(str(operator), str(condition.get("display") or "matched"))


def _version_match_confidence(condition: dict[str, Any]) -> str:
    if condition.get("operator") == "version_exact":
        return "High"
    return "Medium"


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


def _safe_float_metadata(rule: dict[str, Any], field: str, *, minimum: float, maximum: float) -> None:
    if rule.get(field) is None:
        return
    value = _as_float(rule.get(field))
    if value is None or value < minimum or value > maximum:
        raise VulnIntelRulesError(f"Vulnerability rule {rule.get('rule_id')} has invalid {field}.")


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
