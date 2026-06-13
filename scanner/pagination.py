"""Page-based pagination helpers for large local datasets."""

from __future__ import annotations

import math
from typing import Any


DEFAULT_PAGE = 1
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100


class PaginationError(ValueError):
    """Raised when pagination input cannot be handled safely."""


def normalise_pagination(
    page: int = DEFAULT_PAGE,
    page_size: int = DEFAULT_PAGE_SIZE,
    max_page_size: int = MAX_PAGE_SIZE,
) -> tuple[int, int, bool]:
    """Return safe page settings and whether page_size was capped."""
    try:
        safe_page = int(page)
        requested_page_size = int(page_size)
        safe_max = int(max_page_size)
    except (TypeError, ValueError) as exc:
        raise PaginationError("page and page_size must be integers.") from exc
    if safe_page < 1:
        raise PaginationError("page must be greater than or equal to 1.")
    if requested_page_size < 1:
        raise PaginationError("page_size must be greater than or equal to 1.")
    if safe_max < 1:
        raise PaginationError("max_page_size must be greater than or equal to 1.")
    capped = requested_page_size > safe_max
    return safe_page, min(requested_page_size, safe_max), capped


def paginate_items(
    items: list[Any],
    page: int = DEFAULT_PAGE,
    page_size: int = DEFAULT_PAGE_SIZE,
    max_page_size: int = MAX_PAGE_SIZE,
) -> dict[str, Any]:
    """Return a standard paginated_response object."""
    safe_page, safe_page_size, capped = normalise_pagination(page, page_size, max_page_size)
    total = len(items)
    total_pages = max(1, math.ceil(total / safe_page_size)) if total else 0
    start = (safe_page - 1) * safe_page_size
    end = start + safe_page_size
    page_items = items[start:end] if start < total else []
    has_next = safe_page < total_pages
    has_previous = safe_page > 1 and total_pages > 0
    response = {
        "items": page_items,
        "total": total,
        "page": safe_page,
        "page_size": safe_page_size,
        "total_pages": total_pages,
        "has_next": has_next,
        "has_previous": has_previous,
        "next_page": safe_page + 1 if has_next else None,
        "previous_page": safe_page - 1 if has_previous else None,
        "sort_by": None,
        "sort_direction": None,
        "filters_applied": {},
    }
    if capped:
        response["page_size_capped"] = True
        response["requested_page_size"] = int(page_size)
        response["max_page_size"] = int(max_page_size)
    return response


def apply_sort(
    items: list[dict[str, Any]],
    sort_by: str | None,
    sort_direction: str = "asc",
) -> list[dict[str, Any]]:
    """Sort dictionaries by a common field, keeping missing values stable."""
    if not sort_by:
        return list(items)
    direction = str(sort_direction or "asc").strip().lower()
    if direction not in {"asc", "desc"}:
        raise PaginationError("sort_direction must be asc or desc.")
    reverse = direction == "desc"
    return sorted(items, key=lambda item: _sort_value(item.get(sort_by)), reverse=reverse)


def apply_filters(items: list[dict[str, Any]], filters: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Apply common exact-match and search filters to list records."""
    active = {key: value for key, value in (filters or {}).items() if value not in (None, "")}
    if not active:
        return list(items)
    result = list(items)
    search = str(active.pop("search", "") or "").strip().casefold()
    for key, expected in active.items():
        expected_text = str(expected).strip().casefold()
        result = [item for item in result if _record_value_matches(item, key, expected_text)]
    if search:
        result = [item for item in result if search in _searchable_text(item)]
    return result


def build_paginated_response(
    items: list[dict[str, Any]],
    page: int = DEFAULT_PAGE,
    page_size: int = DEFAULT_PAGE_SIZE,
    sort_by: str | None = None,
    sort_direction: str = "asc",
    filters: dict[str, Any] | None = None,
    max_page_size: int = MAX_PAGE_SIZE,
) -> dict[str, Any]:
    """Filter, sort, and paginate records with the Version 22.2 model."""
    active_filters = {key: value for key, value in (filters or {}).items() if value not in (None, "")}
    filtered = apply_filters(items, active_filters)
    sorted_items = apply_sort(filtered, sort_by, sort_direction)
    response = paginate_items(sorted_items, page=page, page_size=page_size, max_page_size=max_page_size)
    response["sort_by"] = sort_by
    response["sort_direction"] = str(sort_direction or "asc").strip().lower()
    response["filters_applied"] = active_filters
    return response


def pagination_error_response(message: str) -> dict[str, Any]:
    """Return a structured safe error payload for invalid pagination."""
    return {
        "error": "invalid_pagination",
        "detail": message,
        "defaults": {
            "page": DEFAULT_PAGE,
            "page_size": DEFAULT_PAGE_SIZE,
            "max_page_size": MAX_PAGE_SIZE,
        },
    }


def _sort_value(value: Any) -> tuple[int, str]:
    if value is None:
        return (1, "")
    return (0, str(value).casefold())


def _record_value_matches(item: dict[str, Any], key: str, expected: str) -> bool:
    aliases = {
        "owasp_category": ("owasp_category", "category", "related_owasp_categories", "owasp_categories"),
        "source_module": ("source_module", "source_modules", "source"),
        "status": ("status", "validation_status", "retest_status"),
    }
    keys = aliases.get(key, (key,))
    for candidate in keys:
        value = item.get(candidate)
        if isinstance(value, list):
            if any(expected == str(entry).strip().casefold() for entry in value):
                return True
            if any(expected in str(entry).strip().casefold() for entry in value):
                return True
        elif str(value or "").strip().casefold() == expected:
            return True
    return False


def _searchable_text(item: dict[str, Any]) -> str:
    fields = (
        "finding_id",
        "evidence_id",
        "report_id",
        "title",
        "safe_summary",
        "technical_summary",
        "status",
        "severity",
        "category",
        "source_module",
        "filename",
    )
    return " ".join(str(item.get(field) or "") for field in fields).casefold()
