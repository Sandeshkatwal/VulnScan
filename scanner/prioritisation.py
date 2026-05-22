"""Vulnerability prioritisation helpers for VulScan."""

from __future__ import annotations

from typing import Any


ASSET_CRITICALITY_BOOSTS = {
    "critical": 20,
    "high": 12,
    "medium": 6,
    "low": 0,
    "unknown": 0,
}


def build_prioritisation(
    findings: list[dict[str, Any]],
    asset_context: dict[str, Any] | None = None,
    enabled: bool = False,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Build prioritisation summary and per-finding prioritised records."""
    asset_context = asset_context or {}
    asset_criticality = str(asset_context.get("criticality") or "unknown").lower()
    asset_source = str(asset_context.get("criticality_source") or "default_unknown")
    asset_enabled = bool(enabled and asset_context.get("enabled"))

    prioritised_findings = [
        _prioritise_finding(finding, asset_context, asset_enabled)
        for finding in findings
    ]
    prioritised_findings.sort(
        key=lambda item: (
            -int(item.get("priority_score") or 0),
            str(item.get("priority_label") or ""),
            str(item.get("title") or ""),
        )
    )

    summary = {
        "enabled": bool(enabled),
        "total_prioritised_findings": len(prioritised_findings),
        "asset_criticality_enabled": asset_enabled,
        "asset_criticality": asset_criticality,
        "asset_criticality_source": asset_source,
        "critical_asset_findings_count": _count_by_asset_criticality(prioritised_findings, "critical"),
        "high_asset_findings_count": _count_by_asset_criticality(prioritised_findings, "high"),
        "medium_asset_findings_count": _count_by_asset_criticality(prioritised_findings, "medium"),
        "unknown_asset_findings_count": _count_by_asset_criticality(prioritised_findings, "unknown"),
        "fix_first_count": _count_by_priority(prioritised_findings, "Fix First"),
        "fix_soon_count": _count_by_priority(prioritised_findings, "Fix Soon"),
        "schedule_count": _count_by_priority(prioritised_findings, "Schedule"),
        "monitor_count": _count_by_priority(prioritised_findings, "Monitor"),
        "limitations": [
            "Prioritisation combines local scan signals and local asset context; it does not confirm exploitability.",
            "Asset criticality is not a vulnerability by itself.",
        ],
    }
    return summary, prioritised_findings


def _prioritise_finding(
    finding: dict[str, Any],
    asset_context: dict[str, Any],
    asset_enabled: bool,
) -> dict[str, Any]:
    criticality = str(asset_context.get("criticality") or "unknown").lower()
    base_score = int(finding.get("risk_score") or 0)
    boost = ASSET_CRITICALITY_BOOSTS.get(criticality, 0) if asset_enabled else 0
    priority_score = max(0, min(100, base_score + boost))
    severity = str(finding.get("severity") or "")
    reasons = _base_reasons(finding)

    if asset_enabled:
        reasons.append(_asset_reason(criticality))
    else:
        criticality = "unknown"
        reasons.append("Asset criticality is unknown, no asset criticality boost applied.")

    priority_label = _priority_label(priority_score)
    if severity == "Informational" and not _has_strong_signal(finding):
        priority_label = "Monitor"

    prioritised = dict(finding)
    prioritised.update(
        {
            "priority_score": priority_score,
            "priority_label": priority_label,
            "priority_reasons": reasons,
            "asset_criticality": criticality,
            "asset_environment": asset_context.get("environment") or "",
            "asset_business_owner": asset_context.get("business_owner") or "",
            "asset_tags": list(asset_context.get("tags") or []),
        }
    )
    return prioritised


def _base_reasons(finding: dict[str, Any]) -> list[str]:
    reasons = [f"Base risk score is {int(finding.get('risk_score') or 0)}."]
    severity = str(finding.get("severity") or "")
    if severity in {"Critical", "High"}:
        reasons.append(f"Finding severity is {severity}.")
    evidence_details = finding.get("evidence_details") or {}
    if evidence_details.get("epss_score") is not None:
        reasons.append("EPSS enrichment is available from local metadata.")
    if evidence_details.get("exploit_available") is True:
        reasons.append("Local exploit availability metadata is present; exploitability is not confirmed.")
    if evidence_details.get("active_exploitation_reported") is True:
        reasons.append("Local metadata reports active exploitation; validate applicability before acting.")
    return reasons


def _asset_reason(criticality: str) -> str:
    if criticality == "critical":
        return "Asset criticality is critical, increasing priority."
    if criticality == "high":
        return "Asset criticality is high, increasing priority."
    if criticality == "medium":
        return "Asset criticality is medium, slightly increasing priority."
    if criticality == "unknown":
        return "Asset criticality is unknown, no asset criticality boost applied."
    return "Asset criticality is low, no asset criticality boost applied."


def _has_strong_signal(finding: dict[str, Any]) -> bool:
    severity = str(finding.get("severity") or "")
    if severity != "Informational":
        return True
    evidence_details = finding.get("evidence_details") or {}
    return bool(
        evidence_details.get("active_exploitation_reported") is True
        or evidence_details.get("exploit_available") is True
        or _safe_float(evidence_details.get("cvss_score"), 0.0) >= 9.0
    )


def _priority_label(score: int) -> str:
    if score >= 90:
        return "Fix First"
    if score >= 70:
        return "Fix Soon"
    if score >= 40:
        return "Schedule"
    return "Monitor"


def _count_by_priority(findings: list[dict[str, Any]], priority_label: str) -> int:
    return sum(1 for finding in findings if finding.get("priority_label") == priority_label)


def _count_by_asset_criticality(findings: list[dict[str, Any]], criticality: str) -> int:
    return sum(1 for finding in findings if finding.get("asset_criticality") == criticality)


def _safe_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
