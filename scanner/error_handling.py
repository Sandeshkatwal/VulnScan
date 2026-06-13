"""Shared safe error handling helpers for VulScan."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class VulScanUserError(Exception):
    """User-facing error with an optional safe hint."""

    def __init__(self, message: str, *, hint: str | None = None, exit_code: int = 1) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint
        self.exit_code = exit_code


def validate_existing_file(path: str | Path, label: str) -> Path:
    """Return an existing file path or raise a user-facing error."""
    resolved = Path(path)
    if not resolved.is_file():
        raise VulScanUserError(
            f"{label} not found: {path}",
            hint="Check the path or run the relevant demo/sample generation command first.",
        )
    return resolved


def validate_json_file(path: str | Path, label: str) -> dict[str, Any] | list[Any]:
    """Load JSON with a clear error for missing or malformed files."""
    resolved = validate_existing_file(path, label)
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise VulScanUserError(
            f"{label} is not valid JSON: {path}",
            hint=f"Fix the JSON near line {exc.lineno}, column {exc.colno}.",
        ) from exc
    if not isinstance(payload, (dict, list)):
        raise VulScanUserError(f"{label} must contain a JSON object or array: {path}")
    return payload


def safe_path_join(base_dir: str | Path, user_path: str | Path) -> Path:
    """Join a user path under a base directory and block traversal."""
    root = Path(base_dir).resolve()
    candidate = (root / Path(user_path)).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise VulScanUserError("Unsafe path was blocked.", hint=f"Path must stay under {root}.") from exc
    return candidate


def handle_missing_sample_file(path: str | Path, command_hint: str) -> None:
    """Raise a clear missing-sample error."""
    raise VulScanUserError(f"Sample file not found: {path}", hint=command_hint)
