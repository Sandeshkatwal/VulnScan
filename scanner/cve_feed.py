"""Local CVE-style feed loading and matching for VulScan."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from scanner.finding import create_finding
from scanner.service_fingerprint import normalise_cpe, normalise_product, normalise_vendor


DEFAULT_CVE_FEED_PATH = Path("data") / "cve_feeds" / "sample_cve_feed.json"
CVE_FEED_LIMITATION = "Version 14.5 uses local CVE feed, EPSS, and exploit metadata files only and does not validate against live CVE sources."
SUPPORTED_AFFECTED_VERSION_FIELDS = {
    "exact",
    "less_than",
    "less_than_or_equal",
    "greater_than",
    "greater_than_or_equal",
    "between",
}


class CveFeedError(ValueError):
    """Raised when a local CVE-style feed cannot be used."""


def load_cve_feed(path: Path) -> dict[str, Any]:
    """Load, validate, and normalise a local CVE-style JSON feed."""
    feed_path = Path(path)
    if not feed_path.exists():
        raise CveFeedError(f"Local CVE feed file was not found: {feed_path}")
    try:
        feed = json.loads(feed_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CveFeedError(f"Local CVE feed file is not valid JSON: {feed_path}") from exc
    validate_cve_feed(feed)
    normalised = dict(feed)
    normalised["items"] = [normalise_cve_item(item) for item in feed.get("items", [])]
    return normalised


def validate_cve_feed(feed: Any) -> None:
    """Validate the top-level feed and each CVE-style item."""
    if not isinstance(feed, dict):
        raise CveFeedError("Local CVE feed must be a JSON object.")
    if not str(feed.get("feed_name") or "").strip():
        raise CveFeedError("Local CVE feed is missing feed_name.")
    if not str(feed.get("feed_version") or "").strip():
        raise CveFeedError("Local CVE feed is missing feed_version.")
    items = feed.get("items")
    if not isinstance(items, list):
        raise CveFeedError("Local CVE feed must contain an items list.")
    if not items:
        raise CveFeedError("Local CVE feed does not contain any items.")
    for index, item in enumerate(items, start=1):
        _validate_cve_item(item, index)


def normalise_cve_item(item: dict[str, Any]) -> dict[str, Any]:
    """Return a conservative normalised CVE-style feed item."""
    normalised = dict(item)
    normalised["cve"] = str(item.get("cve") or "").strip()
    normalised["vendor"] = normalise_vendor(item.get("vendor"))
    normalised["product"] = normalise_product(item.get("product"))
    normalised["cpe"] = normalise_cpe(item.get("cpe"))
    normalised["cpe_prefix"] = normalise_cpe(item.get("cpe_prefix"))
    normalised["service_name"] = _lower_or_none(item.get("service_name"))
    normalised["affected_versions"] = _normalise_affected_versions(item.get("affected_versions"))
    normalised["cvss_score"] = _as_float(item.get("cvss_score"))
    normalised["epss_score"] = _as_float(item.get("epss_score"))
    normalised["epss_percentile"] = _as_float(item.get("epss_percentile"))
    normalised["exploit_available"] = bool(item.get("exploit_available")) if item.get("exploit_available") is not None else False
    normalised["references"] = list(item.get("references") or [])
    normalised["severity"] = str(item.get("severity") or "Informational")
    normalised["limitation"] = str(item.get("limitation") or "Local CVE feed item requires manual validation.")
    return normalised


def match_cve_feed(items: list[dict[str, Any]], feed: dict[str, Any]) -> list[dict[str, Any]]:
    """Match normalised inventory items against local CVE-style feed items."""
    matches: list[dict[str, Any]] = []
    for feed_item in feed.get("items", []) or []:
        for inventory_item in items:
            identity = _identity_match(feed_item, inventory_item)
            if not identity.get("matched"):
                continue
            evaluation = _evaluate_affected_versions(feed_item, inventory_item, identity)
            if evaluation["match_status"] in {"matched", "insufficient_evidence", "unknown_version"}:
                matches.append(_build_cve_match(feed_item, inventory_item, evaluation))
    return matches


def build_cve_feed_summary(
    *,
    feed: dict[str, Any] | None,
    matches: list[dict[str, Any]],
    enabled: bool,
    error: str | None = None,
) -> dict[str, Any]:
    """Build CVE feed fields for the vulnerability intelligence summary."""
    finding_matches = [match for match in matches if match.get("match_status") == "matched"]
    cvss_scores = [_as_float(match.get("cvss_score")) for match in finding_matches]
    cvss_scores = [score for score in cvss_scores if score is not None]
    limitations = [CVE_FEED_LIMITATION, "Local CVE feed data may be incomplete, stale, or demo-only."]
    if error:
        limitations.append(error)
    items_loaded = len((feed or {}).get("items") or [])
    return {
        "cve_feed_enabled": bool(enabled),
        "cve_feed_name": (feed or {}).get("feed_name"),
        "cve_feed_version": (feed or {}).get("feed_version"),
        "cve_feed_items_loaded": items_loaded,
        "cve_feed_items_evaluated": items_loaded if enabled and feed else 0,
        "cve_feed_matches_found": len(finding_matches),
        "cve_feed_insufficient_evidence_count": sum(1 for match in matches if match.get("match_status") == "insufficient_evidence"),
        "cve_feed_unknown_version_count": sum(1 for match in matches if match.get("match_status") == "unknown_version"),
        "cve_feed_highest_cvss": max(cvss_scores) if cvss_scores else None,
        "cve_feed_exploit_available_count": sum(1 for match in finding_matches if match.get("exploit_available") is True),
        "cve_feed_limitations": limitations,
        "cve_feed_matches": matches,
    }


def build_cve_feed_findings(
    matches: list[dict[str, Any]],
    summary: dict[str, Any],
    scan_result: dict[str, Any],
) -> list[Any]:
    """Create standard findings from matched local CVE feed items."""
    findings: list[Any] = []
    if summary.get("cve_feed_enabled") and summary.get("cve_feed_items_loaded"):
        findings.append(
            create_finding(
                title="Local CVE Feed Import Completed",
                severity="Informational",
                category="Vulnerability Intelligence",
                affected_host=str(scan_result.get("host") or ""),
                evidence="Local CVE feed was loaded and evaluated against software inventory.",
                confidence="High",
                impact="Local CVE feed matches can support authorised manual verification and remediation planning.",
                recommendation="Use local CVE feed results to support manual verification and remediation planning.",
                verification="Review the vulnerability_intelligence.cve_feed_matches section in the report.",
                limitation="Local CVE feed data may be incomplete, stale, or demo-only.",
                source="cve_feed",
                evidence_details={
                    "feed_name": summary.get("cve_feed_name"),
                    "feed_version": summary.get("cve_feed_version"),
                    "items_loaded": summary.get("cve_feed_items_loaded"),
                    "matches_found": summary.get("cve_feed_matches_found"),
                    "insufficient_evidence_count": summary.get("cve_feed_insufficient_evidence_count"),
                },
            )
        )
    for match in matches:
        if match.get("match_status") != "matched":
            continue
        item = match.get("matched_inventory_item") or {}
        product = str(match.get("product") or item.get("product") or item.get("service_name") or "unknown")
        version = match.get("version") or item.get("version")
        cve = str(match.get("cve") or "")
        title = str(match.get("title") or "Local CVE feed match")
        fixed_version = match.get("fixed_version")
        recommendation = (
            f"Update product to fixed version {fixed_version} or later according to vendor guidance."
            if fixed_version
            else "Review vendor advisory and apply appropriate remediation."
        )
        findings.append(
            create_finding(
                title=f"{cve} - {title}" if cve else title,
                severity=_safe_severity(match.get("severity")),
                category="Vulnerability Intelligence",
                affected_host=str(item.get("host") or scan_result.get("host") or ""),
                affected_port=_safe_int(item.get("port")),
                service=str(item.get("service_name") or ""),
                evidence=_match_evidence(match, product, version),
                confidence=_safe_confidence(match.get("match_confidence")),
                impact="The local CVE feed item may increase remediation priority, but applicability still requires review.",
                recommendation=recommendation,
                verification="Manually validate product, version, affected version range, configuration, and business context.",
                limitation=CVE_FEED_LIMITATION,
                source="cve_feed",
                evidence_details={
                    "cve": match.get("cve"),
                    "cvss_score": match.get("cvss_score"),
                    "cvss_vector": match.get("cvss_vector"),
                    "epss_score": match.get("epss_score"),
                    "epss_percentile": match.get("epss_percentile"),
                    "epss_source": match.get("epss_source"),
                    "epss_enriched": match.get("epss_enriched"),
                    "exploit_available": match.get("exploit_available"),
                    "exploit_metadata_source": match.get("exploit_metadata_source"),
                    "exploit_reference_label": match.get("exploit_reference_label"),
                    "exploit_reference_url": match.get("exploit_reference_url"),
                    "exploit_maturity": match.get("exploit_maturity"),
                    "active_exploitation_reported": match.get("active_exploitation_reported"),
                    "exploit_metadata_enriched": match.get("exploit_metadata_enriched"),
                    "affected_versions": match.get("affected_versions"),
                    "fixed_version": match.get("fixed_version"),
                    "references": match.get("references") or [],
                    "match_status": match.get("match_status"),
                    "match_confidence": match.get("match_confidence"),
                    "matched_inventory_item": item,
                    "limitation": match.get("limitation"),
                },
            )
        )
    return findings


def _validate_cve_item(item: Any, index: int) -> None:
    if not isinstance(item, dict):
        raise CveFeedError(f"Local CVE feed item {index} must be an object.")
    if not str(item.get("cve") or "").strip():
        raise CveFeedError(f"Local CVE feed item {index} is missing cve.")
    if not any(item.get(field) for field in ("vendor", "product", "cpe", "cpe_prefix", "service_name")):
        raise CveFeedError(f"Local CVE feed item {item.get('cve')} needs vendor/product, CPE, or service_name identity data.")
    cvss_score = _as_float(item.get("cvss_score"))
    if item.get("cvss_score") is not None and (cvss_score is None or cvss_score < 0 or cvss_score > 10):
        raise CveFeedError(f"Local CVE feed item {item.get('cve')} has invalid cvss_score.")
    if item.get("affected_versions") is not None:
        _validate_affected_versions(item.get("affected_versions"), item.get("cve"))
    if item.get("references") is not None and not isinstance(item.get("references"), list):
        raise CveFeedError(f"Local CVE feed item {item.get('cve')} references must be a list.")


def _validate_affected_versions(value: Any, cve: Any) -> None:
    if not isinstance(value, dict) or not value:
        raise CveFeedError(f"Local CVE feed item {cve} has invalid affected_versions.")
    unsupported = set(value) - SUPPORTED_AFFECTED_VERSION_FIELDS
    if unsupported:
        raise CveFeedError(f"Local CVE feed item {cve} has unsupported affected_versions field(s): {', '.join(sorted(unsupported))}.")
    operators = [field for field in SUPPORTED_AFFECTED_VERSION_FIELDS if field in value]
    if len(operators) > 1:
        raise CveFeedError(f"Local CVE feed item {cve} has conflicting affected_versions conditions.")
    operator = operators[0]
    condition_value = value.get(operator)
    if operator == "between":
        if not isinstance(condition_value, list) or len(condition_value) != 2:
            raise CveFeedError(f"Local CVE feed item {cve} affected_versions.between must contain two versions.")
        if _parse_version(condition_value[0]) is None or _parse_version(condition_value[1]) is None:
            raise CveFeedError(f"Local CVE feed item {cve} has malformed affected_versions.between values.")
        return
    if isinstance(condition_value, list) or not str(condition_value or "").strip():
        raise CveFeedError(f"Local CVE feed item {cve} has malformed affected_versions condition.")
    if operator != "exact" and _parse_version(condition_value) is None:
        raise CveFeedError(f"Local CVE feed item {cve} has an unparsable affected version.")


def _normalise_affected_versions(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    return dict(value)


def _identity_match(feed_item: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    item_cpe = normalise_cpe(item.get("cpe") or item.get("cpe_prefix"))
    cpe_prefix = normalise_cpe(feed_item.get("cpe_prefix"))
    if item_cpe and cpe_prefix and item_cpe.startswith(cpe_prefix):
        return {"matched": True, "method": "cpe_prefix", "partial": False}
    feed_cpe = normalise_cpe(feed_item.get("cpe"))
    if item_cpe and feed_cpe and item_cpe == feed_cpe:
        return {"matched": True, "method": "cpe", "partial": False}

    feed_vendor = normalise_vendor(feed_item.get("vendor"))
    feed_product = normalise_product(feed_item.get("product"))
    item_vendor = normalise_vendor(item.get("vendor"))
    item_product = normalise_product(item.get("product"))
    if feed_product and item_product and feed_product == item_product:
        if feed_vendor and item_vendor and feed_vendor == item_vendor:
            return {"matched": True, "method": "vendor_product", "partial": False}
        if not feed_vendor or not item_vendor:
            return {"matched": True, "method": "product", "partial": True}

    feed_service = _lower_or_none(feed_item.get("service_name"))
    item_service = _lower_or_none(item.get("service_name"))
    if feed_service and item_service and feed_service == item_service:
        return {"matched": True, "method": "service_name", "partial": True}
    return {"matched": False, "method": None, "partial": True}


def _evaluate_affected_versions(
    feed_item: dict[str, Any],
    item: dict[str, Any],
    identity: dict[str, Any],
) -> dict[str, Any]:
    affected_versions = feed_item.get("affected_versions")
    condition = _affected_condition(affected_versions)
    if not condition:
        return {
            "match_status": "matched",
            "match_confidence": "Low" if identity.get("partial") else "Medium",
            "affected_condition": None,
            "identity_method": identity.get("method"),
        }
    version = item.get("version")
    if not version:
        return {
            "match_status": "insufficient_evidence",
            "match_confidence": "Low",
            "affected_condition": condition,
            "identity_method": identity.get("method"),
        }
    condition_result = _affected_version_matches(condition, version)
    if condition_result is None:
        return {
            "match_status": "unknown_version",
            "match_confidence": "Low",
            "affected_condition": condition,
            "identity_method": identity.get("method"),
        }
    if not condition_result:
        return {
            "match_status": "not_matched",
            "match_confidence": "Low",
            "affected_condition": condition,
            "identity_method": identity.get("method"),
        }
    return {
        "match_status": "matched",
        "match_confidence": "Medium" if identity.get("partial") else "High",
        "affected_condition": condition,
        "identity_method": identity.get("method"),
    }


def _affected_condition(affected_versions: Any) -> dict[str, Any] | None:
    if not isinstance(affected_versions, dict):
        return None
    for operator in (
        "exact",
        "less_than",
        "less_than_or_equal",
        "greater_than",
        "greater_than_or_equal",
        "between",
    ):
        if operator in affected_versions:
            value = affected_versions[operator]
            return {"operator": operator, "value": value, "display": _condition_display(operator, value)}
    return None


def _affected_version_matches(condition: dict[str, Any], version: Any) -> bool | None:
    operator = condition.get("operator")
    expected = condition.get("value")
    if operator == "exact":
        comparison = _compare_versions(version, expected)
        return comparison == 0 if comparison is not None else _lower(version) == _lower(expected)
    if operator == "between":
        if not isinstance(expected, list) or len(expected) != 2:
            return None
        lower_compare = _compare_versions(version, expected[0])
        upper_compare = _compare_versions(version, expected[1])
        if lower_compare is None or upper_compare is None:
            return None
        return lower_compare >= 0 and upper_compare <= 0
    comparison = _compare_versions(version, expected)
    if comparison is None:
        return None
    if operator == "less_than":
        return comparison < 0
    if operator == "less_than_or_equal":
        return comparison <= 0
    if operator == "greater_than":
        return comparison > 0
    if operator == "greater_than_or_equal":
        return comparison >= 0
    return None


def _build_cve_match(
    feed_item: dict[str, Any],
    item: dict[str, Any],
    evaluation: dict[str, Any],
) -> dict[str, Any]:
    return {
        "cve": feed_item.get("cve"),
        "title": feed_item.get("title") or feed_item.get("cve"),
        "description": feed_item.get("description"),
        "matched_inventory_item": dict(item),
        "vendor": feed_item.get("vendor") or item.get("vendor"),
        "product": feed_item.get("product") or item.get("product"),
        "version": item.get("version"),
        "cpe": item.get("cpe") or item.get("cpe_prefix"),
        "affected_versions": feed_item.get("affected_versions"),
        "affected_condition": evaluation.get("affected_condition"),
        "fixed_version": feed_item.get("fixed_version"),
        "cvss_score": feed_item.get("cvss_score"),
        "cvss_vector": feed_item.get("cvss_vector"),
        "severity": feed_item.get("severity") or "Informational",
        "epss_score": feed_item.get("epss_score"),
        "epss_percentile": feed_item.get("epss_percentile"),
        "exploit_available": bool(feed_item.get("exploit_available")),
        "references": list(feed_item.get("references") or []),
        "match_status": evaluation.get("match_status"),
        "match_confidence": evaluation.get("match_confidence"),
        "identity_method": evaluation.get("identity_method"),
        "evidence": item.get("evidence"),
        "limitation": feed_item.get("limitation") or "Local CVE feed item requires manual validation.",
    }


def _match_evidence(match: dict[str, Any], product: str, version: Any) -> str:
    cve = str(match.get("cve") or "")
    condition = match.get("affected_condition") or {}
    if condition:
        evidence = (
            f"Local CVE feed item {cve} matched product {product} version {version} because affected_versions "
            f"{condition.get('display')}. Matched using local feed metadata."
        )
    else:
        evidence = f"Local CVE feed item {cve} matched product/service identity for {product}. Matched using local feed metadata."
    if match.get("epss_enriched") is True:
        evidence += (
            f" Offline EPSS metadata: score {match.get('epss_score')}, "
            f"percentile {match.get('epss_percentile')}."
        )
    if match.get("exploit_metadata_enriched") is True:
        maturity = match.get("exploit_maturity") or "unknown"
        evidence += (
            f" Offline exploit metadata indicates availability status {match.get('exploit_available')} "
            f"with maturity {maturity}. This does not confirm exploitability."
        )
    return evidence


def _condition_display(operator: str, value: Any) -> str:
    if operator == "between" and isinstance(value, list) and len(value) == 2:
        return f"between {value[0]} and {value[1]}"
    return f"{operator} {value}"


def _parse_version(value: Any) -> tuple[int, ...] | None:
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


def _compare_versions(left: Any, right: Any) -> int | None:
    left_parts = _parse_version(left)
    right_parts = _parse_version(right)
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


def _safe_severity(value: Any) -> str:
    severity = str(value or "Informational").strip()
    if severity in {"Critical", "High", "Medium", "Low", "Informational"}:
        return severity
    return "Informational"


def _safe_confidence(value: Any) -> str:
    confidence = str(value or "Medium").strip()
    if confidence in {"High", "Medium", "Low"}:
        return confidence
    return "Medium"


def _safe_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
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


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _lower_or_none(value: Any) -> str | None:
    lowered = _lower(value)
    return lowered or None
