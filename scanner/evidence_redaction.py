"""Secret Detection and redaction helpers for Evidence Vault records."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class SecretMatch:
    secret_type: str
    pattern_name: str
    start: int
    end: int
    sample: str


SECRET_PATTERNS: tuple[tuple[str, str, re.Pattern[str], str], ...] = (
    ("bearer", "Authorization bearer header", re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/=-]+"), "Authorization: Bearer [REDACTED-BEARER]"),
    ("basic", "Basic auth header", re.compile(r"(?i)\bAuthorization\s*:\s*Basic\s+[A-Za-z0-9+/=._-]+"), "Authorization: Basic [REDACTED-BASIC]"),
    ("cookie", "Cookie header", re.compile(r"(?i)\bCookie\s*:\s*[^\r\n]+"), "Cookie: [REDACTED-COOKIE]"),
    ("cookie", "Set-Cookie header", re.compile(r"(?i)\bSet-Cookie\s*:\s*[^\r\n]+"), "Set-Cookie: [REDACTED-COOKIE]"),
    ("session", "session token", re.compile(r"(?i)\b(sessionid|session_id|session|sid)=([A-Za-z0-9._~+/=-]{6,})"), r"\1=[REDACTED-SESSION]"),
    ("csrf", "CSRF token", re.compile(r"(?i)\b(csrf|csrftoken|csrf_token|xsrf|state|nonce)=([A-Za-z0-9._~+/=-]{6,})"), r"\1=[REDACTED-CSRF]"),
    ("api_key", "API key", re.compile(r"(?i)\b(x-api-key|api[_-]?key)\s*[:=]\s*[A-Za-z0-9._~+/=-]{8,}"), r"\1=[REDACTED-API-KEY]"),
    ("token", "access token", re.compile(r"(?i)\b(access_token|refresh_token|id_token|token)\s*[:=]\s*[A-Za-z0-9._~+/=-]{8,}"), r"\1=[REDACTED-TOKEN]"),
    ("jwt", "JWT-like string", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED-JWT]"),
    ("aws_key", "AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED-API-KEY]"),
    ("private_key", "private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL), "[REDACTED-PRIVATE-KEY]"),
    ("password", "password field", re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*[^\s&;,]{4,}"), r"\1=[REDACTED-PASSWORD]"),
    ("secret", "secret field", re.compile(r"(?i)\b(secret)\s*[:=]\s*[^\s&;,]{6,}"), r"\1=[REDACTED-SECRET]"),
    ("credential_pair", "email/password pair", re.compile(r"(?is)\bemail\s*[:=]\s*[^&\s;,]+.{0,80}\bpassword\s*[:=]\s*[^\s&;,]+"), "email=[REDACTED] password=[REDACTED-PASSWORD]"),
    ("random", "long random string", re.compile(r"\b(?=[A-Za-z0-9+/=_-]{32,}\b)(?=.*[A-Z])(?=.*[a-z])(?=.*\d)[A-Za-z0-9+/=_-]{32,}\b"), "[REDACTED-SECRET]"),
)


def detect_secret_patterns(text: str | None) -> list[dict[str, str | int]]:
    """Return Secret Detection matches without exposing full matched values."""
    if not text:
        return []
    matches: list[dict[str, str | int]] = []
    for secret_type, pattern_name, pattern, _replacement in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if "[REDACTED-" in value:
                continue
            sample = value[:12] + "..." if len(value) > 12 else value
            matches.append({"secret_type": secret_type, "pattern_name": pattern_name, "start": match.start(), "end": match.end(), "sample": sample})
    return matches


def redact_secrets(text: str | None) -> str:
    """Redact known secret patterns while preserving useful field context."""
    redacted = text or ""
    for _secret_type, _pattern_name, pattern, replacement in SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def validate_redaction(text: str | None) -> dict[str, object]:
    matches = detect_secret_patterns(text)
    return {
        "passed": not matches,
        "secret_detection_status": "passed" if not matches else "failed",
        "matches": matches,
        "warnings": [] if not matches else ["Secret Detection found patterns that must be redacted before save or export."],
    }


def redact_mapping_values(value: object, sensitive_names: Iterable[str] = ("authorization", "cookie", "set-cookie", "password", "token", "secret", "api_key")) -> object:
    if isinstance(value, dict):
        output = {}
        for key, item in value.items():
            key_text = str(key).lower()
            if any(name in key_text for name in sensitive_names):
                output[key] = redact_secrets(f"{key}={item}").split("=", 1)[-1]
            else:
                output[key] = redact_mapping_values(item, sensitive_names)
        return output
    if isinstance(value, list):
        return [redact_mapping_values(item, sensitive_names) for item in value]
    if isinstance(value, str):
        return redact_secrets(value)
    return value
