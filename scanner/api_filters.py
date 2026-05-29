"""Reusable API filtering, sorting, and pagination helpers."""

from __future__ import annotations

from typing import Any


DEFAULT_LIMIT = 20
MAX_LIMIT = 100
SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
}
COMPACT_FINDING_FIELDS = (
    "title",
    "severity",
    "source",
    "category",
    "risk_score",
    "priority_score",
    "priority_label",
    "recommendation",
    "finding_key",
    "remediation_status",
    "remediation_owner",
    "remediation_due_date",
)


def normalize_pagination(limit: int = DEFAULT_LIMIT, offset: int = 0) -> tuple[int, int]:
    safe_limit = int(limit)
    safe_offset = int(offset)
    if safe_limit < 1 or safe_limit > MAX_LIMIT:
        raise ValueError("limit must be between 1 and 100.")
    if safe_offset < 0:
        raise ValueError("offset must be greater than or equal to 0.")
    return safe_limit, safe_offset


def validate_sort_order(sort_order: str = "desc") -> str:
    normalized = str(sort_order or "desc").strip().lower()
    if normalized not in {"asc", "desc"}:
        raise ValueError("sort_order must be asc or desc.")
    return normalized


def validate_sort_by(sort_by: str | None, allowed: set[str]) -> str | None:
    if sort_by is None or str(sort_by).strip() == "":
        return None
    normalized = str(sort_by).strip().lower()
    if normalized not in allowed:
        allowed_values = ", ".join(sorted(allowed))
        raise ValueError(f"Unsupported sort_by value. Allowed values: {allowed_values}.")
    return normalized


def paginate_items(items: list[Any], limit: int = DEFAULT_LIMIT, offset: int = 0) -> tuple[list[Any], dict[str, Any]]:
    safe_limit, safe_offset = normalize_pagination(limit, offset)
    total = len(items)
    page = items[safe_offset : safe_offset + safe_limit]
    next_offset = safe_offset + safe_limit if safe_offset + safe_limit < total else None
    previous_offset = max(0, safe_offset - safe_limit) if safe_offset > 0 else None
    return page, {
        "limit": safe_limit,
        "offset": safe_offset,
        "returned": len(page),
        "total": total,
        "has_next": next_offset is not None,
        "has_previous": previous_offset is not None,
        "next_offset": next_offset,
        "previous_offset": previous_offset,
    }


def pagination_metadata(total: int, returned: int, limit: int, offset: int) -> dict[str, Any]:
    safe_limit, safe_offset = normalize_pagination(limit, offset)
    safe_total = max(0, int(total or 0))
    next_offset = safe_offset + safe_limit if safe_offset + safe_limit < safe_total else None
    previous_offset = max(0, safe_offset - safe_limit) if safe_offset > 0 else None
    return {
        "limit": safe_limit,
        "offset": safe_offset,
        "returned": int(returned or 0),
        "total": safe_total,
        "has_next": next_offset is not None,
        "has_previous": previous_offset is not None,
        "next_offset": next_offset,
        "previous_offset": previous_offset,
    }


def filter_findings(findings: list[dict[str, Any]], filters: dict[str, Any]) -> list[dict[str, Any]]:
    result = list(findings)
    for field in ("severity", "source", "category", "priority_label"):
        expected = filters.get(field)
        if expected:
            result = [finding for finding in result if _casefold(finding.get(field)) == _casefold(expected)]
    if filters.get("min_priority_score") is not None:
        minimum = _float_or_none(filters.get("min_priority_score"))
        if minimum is not None:
            result = [finding for finding in result if (_float_or_none(finding.get("priority_score")) or 0.0) >= minimum]
    if filters.get("min_risk_score") is not None:
        minimum = _float_or_none(filters.get("min_risk_score"))
        if minimum is not None:
            result = [finding for finding in result if (_float_or_none(finding.get("risk_score")) or 0.0) >= minimum]
    if filters.get("cve"):
        cve = _casefold(filters.get("cve"))
        result = [finding for finding in result if _finding_matches_cve(finding, cve)]
    return result


def sort_findings(findings: list[dict[str, Any]], sort_by: str | None, sort_order: str = "desc") -> list[dict[str, Any]]:
    normalized_sort = validate_sort_by(
        sort_by,
        {"severity", "risk_score", "priority_score", "title", "source", "category"},
    )
    order = validate_sort_order(sort_order)
    if not normalized_sort:
        return list(findings)
    reverse = order == "desc"
    if normalized_sort == "severity":
        return sorted(findings, key=lambda item: SEVERITY_RANK.get(_casefold(item.get("severity")), 0), reverse=reverse)
    if normalized_sort in {"risk_score", "priority_score"}:
        return sorted(findings, key=lambda item: _float_or_none(item.get(normalized_sort)) or 0.0, reverse=reverse)
    return sorted(findings, key=lambda item: _casefold(item.get(normalized_sort)), reverse=reverse)


def compact_findings(findings: list[dict[str, Any]], compact: bool = False) -> list[dict[str, Any]]:
    if not compact:
        return findings
    return [{field: finding.get(field) for field in COMPACT_FINDING_FIELDS} for finding in findings]


def active_filters(**filters: Any) -> dict[str, Any]:
    return {key: value for key, value in filters.items() if value is not None and value != ""}


def _finding_matches_cve(finding: dict[str, Any], cve: str) -> bool:
    direct = _casefold(finding.get("cve"))
    if direct and direct == cve:
        return True
    for field in ("title", "evidence"):
        if cve in _casefold(finding.get(field)):
            return True
    for key in ("cves", "cve_ids"):
        values = finding.get(key) or []
        if isinstance(values, list) and any(_casefold(value) == cve for value in values):
            return True
    return False


def _casefold(value: Any) -> str:
    return str(value or "").strip().casefold()


def _float_or_none(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
