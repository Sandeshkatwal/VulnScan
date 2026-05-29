"""Safe local report listing and serving helpers for the VulScan API."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.report_json import REPORTS_DIR


ALLOWED_REPORT_SUFFIXES = {".json", ".html"}


def reports_root(reports_dir: Path | str = REPORTS_DIR) -> Path:
    return Path(reports_dir).resolve()


def encode_report_id(path: Path, reports_dir: Path | str = REPORTS_DIR) -> str | None:
    root = reports_root(reports_dir)
    try:
        resolved = path.resolve()
        if not _is_inside_reports(resolved, root) or resolved.suffix.lower() not in ALLOWED_REPORT_SUFFIXES:
            return None
        relative = resolved.relative_to(root).as_posix()
    except (OSError, ValueError):
        return None
    return base64.urlsafe_b64encode(relative.encode("utf-8")).decode("ascii").rstrip("=")


def decode_report_id(report_id: str, reports_dir: Path | str = REPORTS_DIR) -> Path | None:
    if not report_id or any(token in report_id for token in {"/", "\\", ".."}):
        return None
    padded = report_id + "=" * (-len(report_id) % 4)
    try:
        relative_text = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    relative_path = Path(relative_text)
    if relative_path.is_absolute() or any(part in {"", ".", ".."} for part in relative_path.parts):
        return None
    root = reports_root(reports_dir)
    candidate = (root / relative_path).resolve()
    if not _is_inside_reports(candidate, root) or candidate.suffix.lower() not in ALLOWED_REPORT_SUFFIXES:
        return None
    return candidate


def report_metadata(path: Path, reports_dir: Path | str = REPORTS_DIR) -> dict[str, Any] | None:
    report_id = encode_report_id(path, reports_dir)
    if not report_id:
        return None
    try:
        stat = path.stat()
    except OSError:
        return None
    report_type = path.suffix.lower().lstrip(".")
    return {
        "report_id": report_id,
        "filename": path.name,
        "type": report_type,
        "target": _guess_target(path),
        "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(timespec="seconds"),
        "size_bytes": stat.st_size,
        "download_url": f"/reports/{report_id}/download",
        "view_url": f"/reports/{report_id}/view",
    }


def list_report_metadata(
    *,
    reports_dir: Path | str = REPORTS_DIR,
    report_type: str = "all",
    target: str | None = None,
) -> list[dict[str, Any]]:
    root = reports_root(reports_dir)
    if not root.exists() or not root.is_dir():
        return []
    normalized_type = str(report_type or "all").lower()
    allowed_suffixes = ALLOWED_REPORT_SUFFIXES
    if normalized_type in {"json", "html"}:
        allowed_suffixes = {f".{normalized_type}"}
    reports: list[dict[str, Any]] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in allowed_suffixes:
            continue
        metadata = report_metadata(path, root)
        if not metadata:
            continue
        if target and target.lower() not in str(metadata.get("target") or "").lower() and target.lower() not in path.name.lower():
            continue
        reports.append(metadata)
    reports.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return reports


def report_urls_for_path(path_value: Any, reports_dir: Path | str = REPORTS_DIR) -> dict[str, str | None]:
    path_text = str(path_value or "").strip()
    if not path_text:
        return {"download_url": None, "view_url": None}
    path = Path(path_text)
    if not path.is_absolute():
        path = Path.cwd() / path
    report_id = encode_report_id(path, reports_dir)
    if not report_id:
        return {"download_url": None, "view_url": None}
    return {"download_url": f"/reports/{report_id}/download", "view_url": f"/reports/{report_id}/view"}


def load_json_report(path: Path) -> dict[str, Any] | None:
    if path.suffix.lower() != ".json":
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _guess_target(path: Path) -> str:
    if path.suffix.lower() == ".json":
        payload = load_json_report(path)
        if payload:
            value = payload.get("target") or payload.get("host") or payload.get("resolved_ip")
            if value:
                return str(value)
    stem = path.stem
    return stem.rsplit("_", 2)[0] if "_" in stem else stem


def _is_inside_reports(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
