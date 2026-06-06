"""Redaction helpers for Authenticated Web Assessment context."""

from __future__ import annotations

import re
from typing import Any


JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
LONG_RANDOM_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_-]{32,}(?![A-Za-z0-9])")
SECRET_WORD_RE = re.compile(r"(?i)(password|passwd|secret|token|sessionid|session_id|api[-_]?key|authorization|bearer)\s*[:=]\s*([^\s,;]+)")


def redact_auth_header(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    if text.lower().startswith("bearer "):
        return "Bearer [REDACTED]"
    if text.lower().startswith("basic "):
        return "Basic [REDACTED]"
    return redact_secret_text(text)


def redact_cookie_value(value: Any) -> str:
    return "[REDACTED]" if str(value or "") else ""


def redact_secret_text(value: Any) -> str:
    text = str(value or "")
    text = JWT_RE.sub("[REDACTED-JWT]", text)
    text = SECRET_WORD_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = LONG_RANDOM_RE.sub("[REDACTED]", text)
    return text


def detect_secret_like_auth_material(text: Any) -> bool:
    value = str(text or "")
    if not value:
        return False
    if JWT_RE.search(value) or LONG_RANDOM_RE.search(value) or SECRET_WORD_RE.search(value):
        return True
    lowered = value.lower()
    return lowered.startswith("bearer ") or lowered.startswith("basic ")


def redact_session_profile(profile: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(profile or {})
    redacted["cookies"] = {str(name): redact_cookie_value(value) for name, value in dict(redacted.get("cookies") or {}).items()}
    redacted["headers"] = {str(name): _redact_header_value(str(name), value) for name, value in dict(redacted.get("headers") or {}).items()}
    for field in ("notes", "permission_notes", "expiry_hint"):
        if field in redacted:
            redacted[field] = redact_secret_text(redacted[field])
    redacted["cookies_redacted"] = bool(redacted.get("cookies"))
    redacted["headers_redacted"] = bool(redacted.get("headers"))
    redacted["redaction_status"] = "redacted"
    redacted["local_only"] = True
    return redacted


def safe_profile_summary(profile: dict[str, Any]) -> dict[str, Any]:
    redacted = redact_session_profile(profile)
    headers = dict(redacted.get("headers") or {})
    cookies = dict(redacted.get("cookies") or {})
    auth_header_names = [name for name in headers if _is_auth_header_name(name)]
    return {
        "profile_id": redacted.get("profile_id") or _safe_profile_id(redacted),
        "profile_name": redacted.get("profile_name") or "Unnamed Session Profile",
        "target_base_url": redacted.get("target_base_url") or "",
        "created_at": redacted.get("created_at") or "",
        "updated_at": redacted.get("updated_at") or redacted.get("created_at") or "",
        "auth_type": redacted.get("auth_type") or "manual",
        "redaction_status": redacted.get("redaction_status") or "redacted",
        "safe_display_name": redacted.get("safe_display_name") or redacted.get("profile_name") or "Session Profile",
        "cookies_redacted": bool(cookies),
        "headers_redacted": bool(headers),
        "auth_headers_present": bool(auth_header_names),
        "cookie_names": sorted(cookies),
        "header_names": sorted(headers),
        "role_label": redacted.get("role_label") or "",
        "permission_notes": redact_secret_text(redacted.get("permission_notes") or ""),
        "expiry_hint": redact_secret_text(redacted.get("expiry_hint") or ""),
        "scope_file": redacted.get("scope_file") or "",
        "allowed_hosts": list(redacted.get("allowed_hosts") or []),
        "allowed_paths": list(redacted.get("allowed_paths") or []),
        "blocked_paths": list(redacted.get("blocked_paths") or []),
        "notes": redact_secret_text(redacted.get("notes") or ""),
        "local_only": True,
    }


def _redact_header_value(name: str, value: Any) -> str:
    if _is_auth_header_name(name):
        return redact_auth_header(value) if name.lower() == "authorization" else "[REDACTED]"
    return redact_secret_text(value)


def _is_auth_header_name(name: str) -> bool:
    lowered = name.lower()
    return lowered in {"authorization", "x-api-key", "api-key"} or "token" in lowered or "secret" in lowered


def _safe_profile_id(profile: dict[str, Any]) -> str:
    source = f"{profile.get('profile_name', '')}|{profile.get('target_base_url', '')}|{profile.get('role_label', '')}"
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", source).strip("_").lower()
    return safe[:80] or "session_profile"
