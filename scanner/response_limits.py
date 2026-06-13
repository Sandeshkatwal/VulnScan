"""Response size limits for Version 22.2 list endpoints."""

from __future__ import annotations

from typing import Any

from scanner.pagination import DEFAULT_PAGE, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE


SUMMARY_TEXT_LIMIT = 240
LATEST_RECORD_LIMIT = 5


def compact_record(record: dict[str, Any], allowed_fields: tuple[str, ...]) -> dict[str, Any]:
    """Return a response-friendly record containing only allowed fields."""
    return {field: record.get(field) for field in allowed_fields if field in record}


def truncate_text(value: Any, limit: int = SUMMARY_TEXT_LIMIT) -> str:
    text = str(value or "")
    return text if len(text) <= limit else f"{text[:limit].rstrip()}..."


def response_limit_defaults() -> dict[str, int]:
    return {
        "page": DEFAULT_PAGE,
        "page_size": DEFAULT_PAGE_SIZE,
        "max_page_size": MAX_PAGE_SIZE,
        "summary_text_limit": SUMMARY_TEXT_LIMIT,
    }
