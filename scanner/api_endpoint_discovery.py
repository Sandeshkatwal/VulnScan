"""Local API helpers for endpoint discovery reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scanner.endpoint_discovery import ENDPOINT_INPUT_DIR, ENDPOINT_REPORTS_DIR


def resolve_endpoint_input_file(path: str) -> Path:
    base = ENDPOINT_INPUT_DIR.resolve()
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path(path)
    resolved = candidate.resolve()
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise ValueError("Endpoint URL files must be under data/bug_bounty/endpoints.") from exc
    return resolved


def list_endpoint_reports(reports_dir: Path | str = ENDPOINT_REPORTS_DIR) -> list[dict[str, Any]]:
    directory = Path(reports_dir)
    if not directory.exists():
        return []
    reports: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        metadata = endpoint_report_metadata(path)
        if metadata:
            reports.append(metadata)
    return reports


def endpoint_report_metadata(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    summary = payload.get("endpoint_discovery") or {}
    return {
        "endpoint_report_id": path.stem,
        "filename": path.name,
        "created_at": summary.get("started_at") or "",
        "program_id": summary.get("program_id") or "",
        "program_name": summary.get("program_name") or "",
        "input_urls_count": summary.get("input_urls_count") or 0,
        "interesting_parameters_count": summary.get("interesting_parameters_count") or 0,
        "high_interest_count": summary.get("high_interest_count") or 0,
        "skipped_urls_count": summary.get("skipped_urls_count") or 0,
    }
