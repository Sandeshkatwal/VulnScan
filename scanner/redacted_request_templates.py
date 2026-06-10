"""Redacted Request Template helpers for Safe Authenticated Parameter Replay Planner."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from scanner.evidence import redact_nested


REDACTED_VALUE = "{ORIGINAL_VALUE_REDACTED}"
MANUAL_TEST_VALUE = "{TEST_VALUE_APPROVED_MANUAL_ONLY}"
SECRET_HEADER_NAMES = {"authorization", "proxy-authorization", "x-api-key", "x-auth-token"}
SECRET_FIELD_TOKENS = ("password", "passwd", "secret", "bearer", "session", "csrf", "token", "nonce", "state")


@dataclass
class RedactedRequestTemplate:
    template_id: str
    title: str
    method: str
    url_template: str
    normalised_url: str
    headers_redacted: dict[str, str] = field(default_factory=dict)
    cookies_redacted: list[str] = field(default_factory=list)
    query_parameters: dict[str, list[str]] = field(default_factory=dict)
    path_parameters: dict[str, str] = field(default_factory=dict)
    form_fields: dict[str, str] = field(default_factory=dict)
    json_body_schema: dict[str, Any] = field(default_factory=dict)
    sensitive_fields_redacted: list[str] = field(default_factory=list)
    auth_context_summary: dict[str, Any] = field(default_factory=dict)
    boundary_status: str = "unknown"
    blocked_by_default: bool = False
    state_changing: bool = False
    destructive: bool = False
    safe_to_review_manually: bool = True
    warnings: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def new_template_id() -> str:
    return f"template_{uuid4().hex[:12]}"


def redact_headers(headers: dict[str, Any] | None) -> tuple[dict[str, str], list[str]]:
    redacted: dict[str, str] = {}
    sensitive: list[str] = []
    for key in sorted((headers or {}).keys(), key=str.lower):
        name = str(key)
        if name.lower() in SECRET_HEADER_NAMES or any(token in name.lower() for token in SECRET_FIELD_TOKENS):
            sensitive.append(name)
        redacted[name] = REDACTED_VALUE
    return redacted, sensitive


def redact_cookies(cookies: dict[str, Any] | list[Any] | str | None) -> tuple[list[str], list[str]]:
    names: list[str] = []
    if isinstance(cookies, dict):
        names = [str(key) for key in cookies.keys()]
    elif isinstance(cookies, list):
        names = [str(item.get("name") if isinstance(item, dict) else item) for item in cookies]
    elif isinstance(cookies, str):
        for chunk in cookies.split(";"):
            if "=" in chunk:
                names.append(chunk.split("=", 1)[0].strip())
    sensitive = [name for name in names if any(token in name.lower() for token in SECRET_FIELD_TOKENS)]
    return sorted(set(filter(None, names))), sensitive


def redact_fields(fields: dict[str, Any] | list[Any] | None) -> tuple[dict[str, str], list[str]]:
    if isinstance(fields, list):
        field_names = [str(item.get("name") if isinstance(item, dict) else item) for item in fields]
    else:
        field_names = [str(key) for key in (fields or {}).keys()]
    redacted = {name: REDACTED_VALUE for name in sorted(set(filter(None, field_names)))}
    sensitive = [name for name in redacted if any(token in name.lower() for token in SECRET_FIELD_TOKENS)]
    return redacted, sensitive


def redact_json_schema(body: Any) -> tuple[dict[str, Any], list[str]]:
    sensitive: list[str] = []

    def schema(value: Any, path: str = "") -> Any:
        if isinstance(value, dict):
            output: dict[str, Any] = {}
            for key, nested in value.items():
                name = str(key)
                current = f"{path}.{name}" if path else name
                if any(token in name.lower() for token in SECRET_FIELD_TOKENS):
                    sensitive.append(current)
                output[name] = schema(nested, current)
            return output
        if isinstance(value, list):
            return [schema(value[0], path)] if value else []
        return type(value).__name__ if value is not None else "null"

    if not isinstance(body, (dict, list)):
        return {}, sensitive
    result = schema(body)
    return (result if isinstance(result, dict) else {"items": result}), sensitive


def redact_request_template(template: dict[str, Any]) -> dict[str, Any]:
    """Apply final redaction to a request template-like mapping."""
    redacted = dict(template)
    headers, header_sensitive = redact_headers(redacted.get("headers_redacted") or redacted.get("headers") or {})
    cookies, cookie_sensitive = redact_cookies(redacted.get("cookies_redacted") or redacted.get("cookies") or {})
    form, form_sensitive = redact_fields(redacted.get("form_fields") or {})
    schema, json_sensitive = redact_json_schema(redacted.get("json_body") or redacted.get("json_body_schema") or {})
    redacted["headers_redacted"] = headers
    redacted["cookies_redacted"] = cookies
    redacted["form_fields"] = form
    redacted["json_body_schema"] = schema
    redacted["sensitive_fields_redacted"] = sorted(set((redacted.get("sensitive_fields_redacted") or []) + header_sensitive + cookie_sensitive + form_sensitive + json_sensitive))
    redacted.pop("headers", None)
    redacted.pop("cookies", None)
    redacted.pop("json_body", None)
    return redact_nested(redacted)
