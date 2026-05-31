"""Local API helpers for bug bounty recon reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scanner.bug_bounty_recon import RECON_REPORTS_DIR


def list_recon_reports(reports_dir: Path | str = RECON_REPORTS_DIR) -> list[dict[str, Any]]:
    directory = Path(reports_dir)
    if not directory.exists():
        return []
    reports: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        metadata = recon_report_metadata(path)
        if metadata:
            reports.append(metadata)
    return reports


def load_recon_report(recon_id: str, reports_dir: Path | str = RECON_REPORTS_DIR) -> dict[str, Any] | None:
    directory = Path(reports_dir).resolve()
    candidate = (directory / f"{recon_id}.json").resolve()
    try:
        candidate.relative_to(directory)
    except ValueError:
        return None
    if not candidate.exists() or candidate.suffix.lower() != ".json":
        return None
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def recon_report_metadata(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    summary = payload.get("bug_bounty_recon") or {}
    return {
        "recon_id": path.stem,
        "filename": path.name,
        "created_at": payload.get("scan_start_time") or summary.get("started_at") or "",
        "program_id": summary.get("program_id") or "",
        "program_name": summary.get("program_name") or "",
        "input_targets_count": summary.get("input_targets_count") or 0,
        "live_count": summary.get("live_count") or 0,
        "skipped_count": summary.get("skipped_count") or 0,
        "error_count": summary.get("error_count") or 0,
    }
