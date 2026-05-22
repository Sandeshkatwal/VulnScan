"""Prioritisation trend tracking for saved VulScan scan history."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from scanner.finding import Finding, create_finding


TREND_DETAIL_LIMIT = 20
PRIORITY_LABELS = {"Fix First", "Fix Soon", "Monitor", "Informational"}


def disabled_prioritisation_trends(target: str) -> dict[str, Any]:
    """Return disabled trend defaults for reports."""
    return {
        "prioritisation_trends": {
            "enabled": False,
            "status": "unavailable",
            "target": str(target or ""),
            "previous_scan_id": "",
            "previous_scan_time": "",
            "current_scan_time": "",
            "previous_findings_count": 0,
            "current_findings_count": 0,
            "new_findings_count": 0,
            "resolved_findings_count": 0,
            "unchanged_findings_count": 0,
            "priority_increased_count": 0,
            "priority_decreased_count": 0,
            "priority_label_changed_count": 0,
            "fix_first_new_count": 0,
            "fix_first_resolved_count": 0,
            "fix_first_persisting_count": 0,
            "previous_average_priority_score": 0.0,
            "current_average_priority_score": 0.0,
            "average_priority_delta": 0.0,
            "previous_highest_priority_score": 0,
            "current_highest_priority_score": 0,
            "highest_priority_delta": 0,
            "risk_trend_label": "Unknown",
            "trend_limitations": ["Prioritisation trend tracking was not enabled."],
        },
        "prioritisation_trend_details": _empty_details(),
    }


def unavailable_prioritisation_trends(target: str, message: str, current_scan_time: str | None = None) -> dict[str, Any]:
    """Return enabled but unavailable trend output for friendly error handling."""
    payload = disabled_prioritisation_trends(target)
    trends = payload["prioritisation_trends"]
    trends.update(
        {
            "enabled": True,
            "status": "unavailable",
            "current_scan_time": current_scan_time or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "risk_trend_label": "Unknown",
            "trend_limitations": [
                message,
                "Trend comparison requires readable local scan history.",
                "Trend analysis is decision support and requires human review.",
            ],
        }
    )
    return payload


def build_prioritisation_trends(
    *,
    target: str,
    current_prioritised_findings: list[dict[str, Any]] | None,
    previous_scan: dict[str, Any] | None,
    current_scan_time: str | None = None,
    detail_limit: int = TREND_DETAIL_LIMIT,
) -> dict[str, Any]:
    """Compare current prioritised findings with the latest previous saved scan."""
    current_time = current_scan_time or datetime.now(timezone.utc).isoformat(timespec="seconds")
    current = [_normalise_finding(finding, target) for finding in (current_prioritised_findings or [])]

    if not previous_scan:
        return _baseline_result(target, current, current_time)

    previous = _previous_findings(previous_scan, target)
    previous_map, previous_duplicates = _dedupe_by_stable_key(previous)
    current_map, current_duplicates = _dedupe_by_stable_key(current)
    previous_keys = set(previous_map)
    current_keys = set(current_map)

    new_items = [_detail_item(current_map[key], None, "new") for key in sorted(current_keys - previous_keys)]
    resolved_items = [_detail_item(None, previous_map[key], "resolved") for key in sorted(previous_keys - current_keys)]
    priority_increased: list[dict[str, Any]] = []
    priority_decreased: list[dict[str, Any]] = []
    label_changed_count = 0
    unchanged_count = 0
    fix_first_persisting: list[dict[str, Any]] = []

    for key in sorted(current_keys & previous_keys):
        current_item = current_map[key]
        previous_item = previous_map[key]
        delta = _safe_int(current_item.get("priority_score")) - _safe_int(previous_item.get("priority_score"))
        current_label = _normalise_priority_label(current_item.get("priority_label"), current_item.get("severity"))
        previous_label = _normalise_priority_label(previous_item.get("priority_label"), previous_item.get("severity"))
        if current_label != previous_label:
            label_changed_count += 1
        if delta > 0:
            priority_increased.append(_detail_item(current_item, previous_item, "priority_increased"))
        elif delta < 0:
            priority_decreased.append(_detail_item(current_item, previous_item, "priority_decreased"))
        elif current_label == previous_label:
            unchanged_count += 1
        if current_label == "Fix First" and previous_label == "Fix First":
            fix_first_persisting.append(_detail_item(current_item, previous_item, "fix_first_persisting"))

    fix_first_new = [item for item in new_items if item.get("current_priority_label") == "Fix First"]
    fix_first_resolved = [item for item in resolved_items if item.get("previous_priority_label") == "Fix First"]
    previous_average = _average_score(previous_map.values())
    current_average = _average_score(current_map.values())
    previous_highest = max((_safe_int(item.get("priority_score")) for item in previous_map.values()), default=0)
    current_highest = max((_safe_int(item.get("priority_score")) for item in current_map.values()), default=0)
    average_delta = round(current_average - previous_average, 2)
    highest_delta = current_highest - previous_highest
    risk_trend = _risk_trend_label(
        fix_first_new_count=len(fix_first_new),
        fix_first_resolved_count=len(fix_first_resolved),
        average_priority_delta=average_delta,
    )
    limitations = [
        "Trend tracking compares current prioritised findings with the most recent saved scan for the same target.",
        "Stable finding keys are derived from local finding metadata and may not perfectly match renamed or reworded findings.",
        "Trend analysis is decision support and requires human review before remediation conclusions are made.",
    ]
    if previous_duplicates or current_duplicates:
        limitations.append("Duplicate stable finding keys were detected; highest-priority duplicates were used for comparison.")

    details = {
        "new_findings": _limit_details(new_items, "current_priority_score", detail_limit),
        "resolved_findings": _limit_details(resolved_items, "previous_priority_score", detail_limit),
        "priority_increased": _limit_details(priority_increased, "score_delta", detail_limit),
        "priority_decreased": _limit_details(priority_decreased, "score_delta_abs", detail_limit),
        "fix_first_new": _limit_details(fix_first_new, "current_priority_score", detail_limit),
        "fix_first_resolved": _limit_details(fix_first_resolved, "previous_priority_score", detail_limit),
        "fix_first_persisting": _limit_details(fix_first_persisting, "current_priority_score", detail_limit),
    }

    return {
        "prioritisation_trends": {
            "enabled": True,
            "status": "compared",
            "target": str(target or ""),
            "previous_scan_id": str(previous_scan.get("scan_id") or ""),
            "previous_scan_time": str(previous_scan.get("scan_start_time") or previous_scan.get("scan_time") or ""),
            "current_scan_time": current_time,
            "previous_findings_count": len(previous_map),
            "current_findings_count": len(current_map),
            "new_findings_count": len(new_items),
            "resolved_findings_count": len(resolved_items),
            "unchanged_findings_count": unchanged_count,
            "priority_increased_count": len(priority_increased),
            "priority_decreased_count": len(priority_decreased),
            "priority_label_changed_count": label_changed_count,
            "fix_first_new_count": len(fix_first_new),
            "fix_first_resolved_count": len(fix_first_resolved),
            "fix_first_persisting_count": len(fix_first_persisting),
            "previous_average_priority_score": previous_average,
            "current_average_priority_score": current_average,
            "average_priority_delta": average_delta,
            "previous_highest_priority_score": previous_highest,
            "current_highest_priority_score": current_highest,
            "highest_priority_delta": highest_delta,
            "risk_trend_label": risk_trend,
            "trend_limitations": limitations,
        },
        "prioritisation_trend_details": details,
    }


def build_finding_stable_key(finding: dict[str, Any], target: str) -> str:
    """Build a stable finding key without volatile timestamps or scan duration."""
    details = finding.get("evidence_details") or {}
    cve = finding.get("cve") or details.get("cve") or details.get("cve_id") or details.get("matched_cve") or ""
    service_or_port = (
        finding.get("service")
        or finding.get("affected_service")
        or finding.get("affected_port")
        or details.get("port")
        or details.get("service")
        or ""
    )
    parts = [
        _normalise_text(target),
        _normalise_text(finding.get("source")),
        _normalise_text(finding.get("category")),
        _normalise_text(finding.get("title")),
        _normalise_text(service_or_port),
        _normalise_text(cve),
        _evidence_fingerprint(finding.get("evidence")),
    ]
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:20]
    return f"vs-priority-{digest}"


def build_trend_finding(status: str) -> Finding:
    """Create the standard informational finding for trend analysis."""
    if status == "baseline":
        return create_finding(
            title="Prioritisation Trend Baseline Created",
            severity="Informational",
            category="Prioritisation",
            evidence="No previous prioritised scan was found, so the current scan is treated as the baseline.",
            confidence="High",
            impact="Trend comparison requires at least two saved scans for the same target.",
            recommendation="Run future scans with --priority-trends and --save-db to track changes.",
            verification="Review the Prioritisation Trends section in terminal, JSON, or HTML output.",
            limitation="Trend comparison requires at least two saved scans.",
            source="prioritisation_trends",
        )
    return create_finding(
        title="Prioritisation Trend Analysis Completed",
        severity="Informational",
        category="Prioritisation",
        evidence="VulScan compared current prioritised findings with previous scan history.",
        confidence="High",
        impact="Trend results can help track remediation progress and identify worsening risk.",
        recommendation="Use trend results to track remediation progress and identify worsening risk.",
        verification="Review the Prioritisation Trends section in terminal, JSON, or HTML output.",
        limitation="Trend accuracy depends on stable finding keys and availability of previous scan data.",
        source="prioritisation_trends",
    )


def _baseline_result(target: str, current: list[dict[str, Any]], current_time: str) -> dict[str, Any]:
    current_average = _average_score(current)
    current_highest = max((_safe_int(item.get("priority_score")) for item in current), default=0)
    return {
        "prioritisation_trends": {
            "enabled": True,
            "status": "baseline",
            "target": str(target or ""),
            "previous_scan_id": "",
            "previous_scan_time": "",
            "current_scan_time": current_time,
            "previous_findings_count": 0,
            "current_findings_count": len(current),
            "new_findings_count": len(current),
            "resolved_findings_count": 0,
            "unchanged_findings_count": 0,
            "priority_increased_count": 0,
            "priority_decreased_count": 0,
            "priority_label_changed_count": 0,
            "fix_first_new_count": sum(1 for item in current if item.get("priority_label") == "Fix First"),
            "fix_first_resolved_count": 0,
            "fix_first_persisting_count": 0,
            "previous_average_priority_score": 0.0,
            "current_average_priority_score": current_average,
            "average_priority_delta": 0.0,
            "previous_highest_priority_score": 0,
            "current_highest_priority_score": current_highest,
            "highest_priority_delta": 0,
            "risk_trend_label": "Baseline",
            "trend_limitations": [
                "No previous saved scan was found for this target.",
                "Use this scan as the baseline for future trend comparisons.",
                "Trend analysis is decision support and requires human review.",
            ],
        },
        "prioritisation_trend_details": {
            **_empty_details(),
            "new_findings": _limit_details([_detail_item(item, None, "new") for item in current], "current_priority_score"),
            "fix_first_new": _limit_details(
                [_detail_item(item, None, "fix_first_new") for item in current if item.get("priority_label") == "Fix First"],
                "current_priority_score",
            ),
        },
    }


def _previous_findings(previous_scan: dict[str, Any], target: str) -> list[dict[str, Any]]:
    candidates = previous_scan.get("prioritised_findings") or previous_scan.get("findings") or []
    return [_normalise_finding(item, target) for item in candidates if isinstance(item, dict)]


def _normalise_finding(finding: dict[str, Any], target: str) -> dict[str, Any]:
    item = dict(finding)
    item["priority_score"] = _safe_int(item.get("priority_score", item.get("risk_score", 0)))
    item["priority_label"] = _normalise_priority_label(item.get("priority_label", item.get("risk_label")), item.get("severity"))
    item["stable_key"] = str(item.get("stable_key") or build_finding_stable_key(item, target))
    return item


def _dedupe_by_stable_key(findings: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], int]:
    result: dict[str, dict[str, Any]] = {}
    duplicate_count = 0
    for finding in findings:
        key = str(finding.get("stable_key") or "")
        if not key:
            continue
        if key in result:
            duplicate_count += 1
            if _safe_int(finding.get("priority_score")) <= _safe_int(result[key].get("priority_score")):
                continue
        result[key] = finding
    return result, duplicate_count


def _detail_item(
    current: dict[str, Any] | None,
    previous: dict[str, Any] | None,
    status: str,
) -> dict[str, Any]:
    source = current or previous or {}
    previous_score = _safe_int(previous.get("priority_score")) if previous else None
    current_score = _safe_int(current.get("priority_score")) if current else None
    delta = None if previous_score is None or current_score is None else current_score - previous_score
    previous_label = _normalise_priority_label(previous.get("priority_label"), previous.get("severity")) if previous else ""
    current_label = _normalise_priority_label(current.get("priority_label"), current.get("severity")) if current else ""
    reason = _reason_summary(status, delta, previous_label, current_label)
    return {
        "stable_key": str(source.get("stable_key") or ""),
        "title": str(source.get("title") or ""),
        "source": str(source.get("source") or ""),
        "category": str(source.get("category") or ""),
        "previous_priority_score": previous_score,
        "current_priority_score": current_score,
        "previous_priority_label": previous_label,
        "current_priority_label": current_label,
        "score_delta": delta,
        "trend_status": status,
        "reason_summary": reason,
        "score_delta_abs": abs(delta or 0),
    }


def _risk_trend_label(
    *,
    fix_first_new_count: int,
    fix_first_resolved_count: int,
    average_priority_delta: float,
) -> str:
    if fix_first_new_count > 0 or average_priority_delta >= 5:
        return "Worsened"
    if fix_first_resolved_count > 0 and average_priority_delta < 0:
        return "Improved"
    if abs(average_priority_delta) < 5:
        return "Stable"
    if average_priority_delta <= -5:
        return "Improved"
    return "Unknown"


def _reason_summary(status: str, delta: int | None, previous_label: str, current_label: str) -> str:
    if status == "new":
        return "Finding is present in the current scan and was not matched in the previous saved scan."
    if status == "resolved":
        return "Finding was present in the previous saved scan and was not matched in the current scan."
    if status == "fix_first_persisting":
        return "Finding remains Fix First across both scans."
    if delta is not None and delta > 0:
        return f"Priority score increased by {delta}."
    if delta is not None and delta < 0:
        return f"Priority score decreased by {abs(delta)}."
    if previous_label != current_label:
        return f"Priority label changed from {previous_label or 'unknown'} to {current_label or 'unknown'}."
    return "Finding priority is unchanged."


def _limit_details(items: list[dict[str, Any]], sort_key: str, limit: int = TREND_DETAIL_LIMIT) -> list[dict[str, Any]]:
    return sorted(items, key=lambda item: (_safe_int(item.get(sort_key)), str(item.get("title") or "")), reverse=True)[: max(0, limit)]


def _average_score(findings: Any) -> float:
    items = list(findings)
    if not items:
        return 0.0
    return round(sum(_safe_int(item.get("priority_score")) for item in items) / len(items), 2)


def _normalise_priority_label(value: Any, severity: Any = None) -> str:
    label = str(value or "").strip()
    if label == "Fix First":
        return "Fix First"
    if label in {"Fix Soon", "Schedule"}:
        return "Fix Soon"
    if label == "Informational" or str(severity or "") == "Informational":
        return "Informational"
    return "Monitor"


def _evidence_fingerprint(value: Any) -> str:
    text = _normalise_text(value)
    if not text:
        return ""
    words = text.split(" ")[:12]
    return " ".join(words)


def _normalise_text(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"\d{4}-\d{2}-\d{2}[t\s]\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2})?", "", text)
    text = re.sub(r"\s+", " ", text)
    return text


def _empty_details() -> dict[str, list[dict[str, Any]]]:
    return {
        "new_findings": [],
        "resolved_findings": [],
        "priority_increased": [],
        "priority_decreased": [],
        "fix_first_new": [],
        "fix_first_resolved": [],
        "fix_first_persisting": [],
    }


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
