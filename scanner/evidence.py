"""Safe evidence helpers for credentialed audit findings."""

from __future__ import annotations

import re
from typing import Any


SUMMARY_MAX_CHARS = 300
STDERR_MAX_CHARS = 200
SAMPLE_MAX_ITEMS = 10
WINDOWS_SAMPLE_MAX_ITEMS = 5
OBSERVED_MAX_CHARS = 150
EXPECTED_MAX_CHARS = 150
SAFE_DETAIL_MAX_CHARS = 300
REDACTION_TOKEN = "[REDACTED]"

_PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN (?:OPENSSH|RSA|DSA|EC)? ?PRIVATE KEY-----.*?-----END (?:OPENSSH|RSA|DSA|EC)? ?PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_ASSIGNMENT_SECRET_RE = re.compile(
    r"\b(password|passwd|pwd|token|api_key|apikey|secret|auth|session|sessionid|access_token|refresh_token|accesstoken|refreshtoken)\s*=\s*([^\s;&]+)",
    re.IGNORECASE,
)
_SET_COOKIE_RE = re.compile(r"\b(Set-Cookie\s*:\s*[^=;\s]+)=([^;\r\n]+)", re.IGNORECASE)
_AUTH_HEADER_RE = re.compile(
    r"\b(Authorization\s*:\s*)(Bearer|Basic|NTLM)\s+[^\s;&]+",
    re.IGNORECASE,
)
_AUTH_SCHEME_RE = re.compile(r"\b(Bearer|Basic|NTLM)\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_JWT_LIKE_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
    re.IGNORECASE,
)
_POWERSHELL_SECRET_RE = re.compile(
    r"^.*(?:SecureString|PSCredential|ConvertTo-SecureString).*$",
    re.IGNORECASE | re.MULTILINE,
)
_CREDENTIAL_VALUE_RE = re.compile(r"\b(Credential\s*[:=]\s*)([^\r\n]+)", re.IGNORECASE)
_HASH_VALUE_RE = re.compile(r"\b(LMHASH|NTHASH)\s*[:=]\s*([A-Fa-f0-9]{32,})", re.IGNORECASE)
_NTLM_HASH_PAIR_RE = re.compile(r"\b[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}\b")
_SECRET_LINE_RE = re.compile(
    r"^.*(?:BEGIN OPENSSH PRIVATE KEY|BEGIN RSA PRIVATE KEY|PRIVATE KEY).*$",
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

    updated = _AUTH_HEADER_RE.sub(lambda match: f"{match.group(1)}{match.group(2)} {REDACTION_TOKEN}", text)
    if updated != text:
        redacted = True
    text = updated

    updated = _SET_COOKIE_RE.sub(lambda match: f"{match.group(1)}={REDACTION_TOKEN}", text)
    if updated != text:
        redacted = True
    text = updated

    updated = _AUTH_SCHEME_RE.sub(lambda match: f"{match.group(1)} {REDACTION_TOKEN}", text)
    if updated != text:
        redacted = True
    text = updated

    updated = _JWT_LIKE_RE.sub(REDACTION_TOKEN, text)
    if updated != text:
        redacted = True
    text = updated

    updated = _ASSIGNMENT_SECRET_RE.sub(lambda match: f"{match.group(1)}={REDACTION_TOKEN}", text)
    if updated != text:
        redacted = True
    text = updated

    updated = _CREDENTIAL_VALUE_RE.sub(lambda match: f"{match.group(1)}{REDACTION_TOKEN}", text)
    if updated != text:
        redacted = True
    text = updated

    updated = _HASH_VALUE_RE.sub(lambda match: f"{match.group(1)}={REDACTION_TOKEN}", text)
    if updated != text:
        redacted = True
    text = updated

    updated = _NTLM_HASH_PAIR_RE.sub(REDACTION_TOKEN, text)
    if updated != text:
        redacted = True
    text = updated

    updated = _POWERSHELL_SECRET_RE.sub(REDACTION_TOKEN, text)
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
    suffix = " ... [truncated]"
    return cleaned[: max_chars - len(suffix)].rstrip() + suffix


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
    sample_limit: int = SAMPLE_MAX_ITEMS,
) -> dict[str, Any]:
    """Build a compact report-safe evidence details dictionary."""
    safe_summary, redacted = redact_secrets(summary)
    safe_source, source_redacted = redact_secrets(source)
    safe_command_name, command_name_redacted = redact_secrets(command_name or "")
    safe_command_label, command_label_redacted = redact_secrets(command_used_safe_label or command_name or "")
    details: dict[str, Any] = {
        "summary": safe_truncate(safe_summary, max_chars=max_summary_chars),
        "source": safe_truncate(safe_source, max_chars=SAFE_DETAIL_MAX_CHARS),
        "command_name": safe_truncate(safe_command_name, max_chars=SAFE_DETAIL_MAX_CHARS),
        "command_used_safe_label": safe_truncate(safe_command_label, max_chars=SAFE_DETAIL_MAX_CHARS),
        "observed_value": "",
        "expected_value": "",
        "sample": [],
        "confidence_reason": safe_truncate(confidence_reason or "", max_chars=SAFE_DETAIL_MAX_CHARS),
        "raw_output_included": raw_output_included,
        "redacted": bool(redacted or source_redacted or command_name_redacted or command_label_redacted),
        "limitation": safe_truncate(limitation or "", max_chars=SAFE_DETAIL_MAX_CHARS),
    }

    if observed_value is not None:
        observed, observed_redacted = redact_secrets(observed_value)
        details["observed_value"] = safe_truncate(observed, max_chars=OBSERVED_MAX_CHARS)
        details["redacted"] = bool(details["redacted"] or observed_redacted)
    if expected_value is not None:
        expected, expected_redacted = redact_secrets(expected_value)
        details["expected_value"] = safe_truncate(expected, max_chars=EXPECTED_MAX_CHARS)
        details["redacted"] = bool(details["redacted"] or expected_redacted)
    if sample:
        details["sample"] = limited_sample(sample, limit=sample_limit)

    return details


def evidence_summary(details: dict[str, Any]) -> str:
    """Return the backward-compatible short evidence string."""
    return str(details.get("summary") or "")


def redact_nested(value: Any) -> Any:
    """Recursively redact strings inside report/export containers."""
    if isinstance(value, dict):
        return {key: redact_nested(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_nested(item) for item in value]
    if isinstance(value, tuple):
        return [redact_nested(item) for item in value]
    if isinstance(value, str):
        return redact_secrets(value)[0]
    return value
