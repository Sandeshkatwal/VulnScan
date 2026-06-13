"""CLI formatting helpers for friendly VulScan errors."""

from __future__ import annotations

from scanner.error_handling import VulScanUserError


def user_friendly_error(message: str, hint: str | None = None, exit_code: int = 1) -> VulScanUserError:
    return VulScanUserError(message, hint=hint, exit_code=exit_code)


def format_cli_warning(message: str) -> str:
    return f"Warning: {message}"


def format_cli_success(message: str) -> str:
    return f"OK: {message}"


def format_user_error(error: VulScanUserError) -> str:
    lines = [f"Error: {error.message}"]
    if error.hint:
        lines.append(f"Hint: {error.hint}")
    return "\n".join(lines)
