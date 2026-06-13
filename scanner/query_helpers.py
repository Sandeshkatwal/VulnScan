"""Small query and file-list helpers for performance-focused endpoints."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


COMMON_INDEXES = (
    ("idx_findings_finding_id", "findings", "finding_id"),
    ("idx_findings_created_at", "findings", "created_at"),
    ("idx_findings_severity", "findings", "severity"),
    ("idx_findings_category", "findings", "category"),
    ("idx_findings_source", "findings", "source"),
    ("idx_scans_created_at", "scans", "created_at"),
)


def ensure_common_indexes(connection: sqlite3.Connection) -> None:
    """Create practical indexes for common dashboard list queries."""
    for index_name, table, column in COMMON_INDEXES:
        connection.execute(f"CREATE INDEX IF NOT EXISTS {index_name} ON {table} ({column})")


def limit_offset(page: int, page_size: int) -> tuple[int, int]:
    safe_page = max(1, int(page))
    safe_page_size = max(1, int(page_size))
    return safe_page_size, (safe_page - 1) * safe_page_size


def directory_size_bytes(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        return path.stat().st_size
    total = 0
    for candidate in path.rglob("*"):
        if candidate.is_file():
            try:
                total += candidate.stat().st_size
            except OSError:
                continue
    return total


def count_json_records(payload: Any) -> int:
    if isinstance(payload, list):
        return len(payload)
    if isinstance(payload, dict):
        for key in ("items", "findings", "evidence_items", "reports", "plans"):
            value = payload.get(key)
            if isinstance(value, list):
                return len(value)
    return 0
