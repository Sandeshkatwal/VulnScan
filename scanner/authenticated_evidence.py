"""Redacted Authenticated Evidence helpers."""

from __future__ import annotations

from typing import Any

from scanner.auth_redaction import redact_secret_text


SAFE_REQUEST_HEADER_NAMES = {"user-agent", "accept", "accept-language", "content-type"}


def redact_request_for_logs(request: dict[str, Any]) -> dict[str, Any]:
    safe = {
        "method": str(request.get("method") or "GET").upper(),
        "url": str(request.get("url") or ""),
        "headers": {},
        "cookies": {},
    }
    for name, value in dict(request.get("headers") or {}).items():
        header_name = str(name)
        if header_name.lower() in {"authorization", "cookie"} or "key" in header_name.lower():
            safe["headers"][header_name] = "[REDACTED]"
        elif header_name.lower() in SAFE_REQUEST_HEADER_NAMES:
            safe["headers"][header_name] = redact_secret_text(value)
        else:
            safe["headers"][header_name] = "[REDACTED]"
    for name in dict(request.get("cookies") or {}):
        safe["cookies"][str(name)] = "[REDACTED]"
    return safe


def redact_response_for_storage(response: dict[str, Any]) -> dict[str, Any]:
    headers = {}
    for name, value in dict(response.get("headers") or {}).items():
        header_name = str(name)
        if header_name.lower() in {"set-cookie", "authorization", "cookie"}:
            headers[header_name] = "[REDACTED]"
        else:
            headers[header_name] = redact_secret_text(value)
    return {
        "url": response.get("url") or "",
        "status_code": int(response.get("status_code") or 0),
        "content_type": str(response.get("content_type") or ""),
        "headers": headers,
        "snippet": redact_secret_text(str(response.get("snippet") or "")[:1000]),
    }


def build_redacted_evidence_summary(*, status_code: int, title: str, content_type: str, indicators: list[str] | None = None) -> str:
    parts = [f"status={int(status_code or 0)}"]
    if content_type:
        parts.append(f"content_type={redact_secret_text(content_type)}")
    if title:
        parts.append(f"title={redact_secret_text(title)[:120]}")
    if indicators:
        parts.append("indicators=" + ", ".join(redact_secret_text(item) for item in indicators[:5]))
    return "; ".join(parts)
