"""Safe evidence helpers for credentialed audit findings."""

from __future__ import annotations

import re
from typing import Any


SUMMARY_MAX_CHARS = 300
STDERR_MAX_CHARS = 200
SAMPLE_MAX_ITEMS = 10
REDACTION_TOKEN = "[REDACTED]"

_PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN (?:OPENSSH|RSA|DSA|EC)? ?PRIVATE KEY-----.*?-----END (?:OPENSSH|RSA|DSA|EC)? ?PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_ASSIGNMENT_SECRET_RE = re.compile(
    r"\b(password|passwd|token|api_key|apikey|secret)\s*=\s*([^\s;&]+)",
    re.IGNORECASE,
)
_SECRET_LINE_RE = re.compile(
    r"^.*(?:BEGIN OPENSSH PRIVATE KEY|BEGIN RSA PRIVATE KEY|SECRET|Authorization:).*$",
    re.IGNORECASE | re.MULTILINE,
)


def redact_secrets(value: Any) -> tuple[str, bool]:
    """Redact obvious credential-like values from evidence text."""
    text = "" if value is None else str(value)
    redacted = False

    updated = _PRIVATE_KEY_BLOCK_RE.sub(REDACTION_TOKEN, text)
    if updated != text:
        redacted = True
    text = updated

    updated = _ASSIGNMENT_SECRET_RE.sub(lambda match: f"{match.group(1)}={REDACTION_TOKEN}", text)
    if updated != text:
        redacted = True
    text = updated

    updated = _SECRET_LINE_RE.sub(REDACTION_TOKEN, text)
    if updated != text:
        redacted = True
    text = updated

    return text, redacted


def safe_truncate(value: Any, max_chars: int = SUMMARY_MAX_CHARS) -> str:
    """Redact and shorten text for reports."""
    text, _ = redact_secrets(value)
    cleaned = " ".join(text.split())
    if len(cleaned) <= max_chars:
        return cleaned
    return cleaned[: max_chars - 15].rstrip() + " ... [truncated]"


def limited_sample(values: list[Any] | tuple[Any, ...], limit: int = SAMPLE_MAX_ITEMS) -> list[str]:
    """Return a redacted sample list with a fixed maximum size."""
    return [safe_truncate(value, max_chars=80) for value in list(values)[:limit]]


def build_evidence(
    summary: str,
    source: str,
    command_name: str | None = None,
    command_used_safe_label: str | None = None,
    observed_value: Any | None = None,
    expected_value: Any | None = None,
    sample: list[Any] | tuple[Any, ...] | None = None,
    confidence_reason: str | None = None,
    limitation: str | None = None,
    raw_output_included: bool = False,
    max_summary_chars: int = SUMMARY_MAX_CHARS,
) -> dict[str, Any]:
    """Build a compact report-safe evidence details dictionary."""
    safe_summary, redacted = redact_secrets(summary)
    details: dict[str, Any] = {
        "summary": safe_truncate(safe_summary, max_chars=max_summary_chars),
        "source": source,
        "command_name": command_name or "",
        "command_used_safe_label": command_used_safe_label or command_name or "",
        "observed_value": "",
        "expected_value": "",
        "sample": [],
        "confidence_reason": confidence_reason or "",
        "raw_output_included": raw_output_included,
        "redacted": redacted,
        "limitation": limitation or "",
    }

    if observed_value is not None:
        observed, observed_redacted = redact_secrets(observed_value)
        details["observed_value"] = safe_truncate(observed, max_chars=160)
        details["redacted"] = bool(details["redacted"] or observed_redacted)
    if expected_value is not None:
        expected, expected_redacted = redact_secrets(expected_value)
        details["expected_value"] = safe_truncate(expected, max_chars=160)
        details["redacted"] = bool(details["redacted"] or expected_redacted)
    if sample:
        details["sample"] = limited_sample(sample)

    return details


def evidence_summary(details: dict[str, Any]) -> str:
    """Return the backward-compatible short evidence string."""
    return str(details.get("summary") or "")
