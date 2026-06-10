"""Build Redacted Request Templates for manual parameter review."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from scanner.redacted_request_templates import MANUAL_TEST_VALUE, REDACTED_VALUE, RedactedRequestTemplate, new_template_id, redact_headers, redact_cookies, redact_fields, redact_json_schema, redact_request_template


STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
DESTRUCTIVE_TOKENS = ("delete", "remove", "destroy", "purge", "payment", "checkout", "transfer", "admin")


def build_redacted_request_template(
    endpoint_result: dict[str, Any] | None,
    parameter_result: dict[str, Any] | None,
    auth_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    endpoint = endpoint_result or {}
    parameter = parameter_result or {}
    raw_url = str(endpoint.get("url") or endpoint.get("affected_url") or parameter.get("url") or parameter.get("affected_url") or "")
    method = str(endpoint.get("method") or parameter.get("method") or "GET").upper()
    query_parameters = _query_placeholders(raw_url)
    name = str(parameter.get("parameter_name") or parameter.get("name") or parameter.get("parameter") or "")
    if name and _parameter_location(name, raw_url, parameter) == "query":
        query_parameters.setdefault(name, [REDACTED_VALUE, MANUAL_TEST_VALUE])
    normalised_url = normalise_url_path_ids(raw_url)
    state_changing = detect_state_changing_request({"method": method})
    destructive = detect_destructive_template({"method": method, "url_template": normalised_url})
    headers, header_sensitive = redact_headers(endpoint.get("headers") or endpoint.get("request_headers") or {})
    cookies, cookie_sensitive = redact_cookies(endpoint.get("cookies") or endpoint.get("request_cookies") or endpoint.get("cookie_header") or "")
    form_fields, form_sensitive = redact_fields(endpoint.get("form_fields") or endpoint.get("fields") or {})
    json_schema, json_sensitive = redact_json_schema(endpoint.get("json_body") or endpoint.get("json_body_schema") or {})
    path_parameters = _path_parameters(raw_url)
    warnings = [
        "No Automatic Replay.",
        "Authorised Test Accounts Only.",
        "Header values, cookie values, tokens, and credentials are redacted.",
    ]
    if state_changing:
        warnings.append("State-changing method requires explicit manual approval before any live use.")
    if destructive:
        warnings.append("Destructive or administrative endpoint is blocked by default.")
    template = RedactedRequestTemplate(
        template_id=str(parameter.get("safe_request_template_id") or endpoint.get("safe_request_template_id") or new_template_id()),
        title=f"Redacted Request Template: {method} {normalised_url or raw_url}",
        method=method,
        url_template=_url_with_redacted_query(raw_url, query_parameters),
        normalised_url=normalised_url,
        headers_redacted=headers,
        cookies_redacted=cookies,
        query_parameters=query_parameters,
        path_parameters=path_parameters,
        form_fields=form_fields,
        json_body_schema=json_schema,
        sensitive_fields_redacted=sorted(set(header_sensitive + cookie_sensitive + form_sensitive + json_sensitive)),
        auth_context_summary=_safe_auth_context(auth_context),
        boundary_status=str(endpoint.get("boundary_status") or endpoint.get("auth_boundary_status") or "unknown"),
        blocked_by_default=destructive or state_changing,
        state_changing=state_changing,
        destructive=destructive,
        safe_to_review_manually=not state_changing and not destructive,
        warnings=warnings,
    )
    return redact_request_template(template.to_dict())


def detect_state_changing_request(template: dict[str, Any]) -> bool:
    return str(template.get("method") or "GET").upper() in STATE_CHANGING_METHODS


def detect_destructive_template(template: dict[str, Any]) -> bool:
    text = f"{template.get('method', '')} {template.get('url_template', '')} {template.get('normalised_url', '')}".lower()
    return str(template.get("method") or "").upper() == "DELETE" or any(token in text for token in DESTRUCTIVE_TOKENS)


def normalise_url_path_ids(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    segments = []
    previous = ""
    for segment in parsed.path.split("/"):
        lowered_previous = previous.lower()
        if re.fullmatch(r"\d+", segment) or re.fullmatch(r"[0-9a-fA-F-]{8,}", segment):
            if lowered_previous in {"users", "user"}:
                segments.append("{id}")
            elif lowered_previous in {"tenants", "tenant", "orgs", "organizations", "workspaces"}:
                segments.append("{tenant_id}")
            elif lowered_previous in {"orders", "invoices", "documents", "files", "reports", "exports"}:
                segments.append("{id}")
            else:
                segments.append("{id}")
        else:
            segments.append(segment)
        if segment:
            previous = segment
    return urlunsplit((parsed.scheme, parsed.netloc, "/".join(segments), "", ""))


def _query_placeholders(url: str) -> dict[str, list[str]]:
    parsed = urlsplit(str(url or ""))
    query = parse_qs(parsed.query, keep_blank_values=True)
    return {str(key): [REDACTED_VALUE, MANUAL_TEST_VALUE] for key in sorted(query.keys())}


def _url_with_redacted_query(url: str, query_parameters: dict[str, list[str]]) -> str:
    parsed = urlsplit(str(url or ""))
    query = urlencode({key: REDACTED_VALUE for key in query_parameters.keys()})
    return urlunsplit((parsed.scheme, parsed.netloc, normalise_url_path_ids(urlsplit(url).path), query, ""))


def _path_parameters(url: str) -> dict[str, str]:
    normalised = normalise_url_path_ids(url)
    params: dict[str, str] = {}
    for name in re.findall(r"\{([^}]+)\}", normalised):
        params[name] = REDACTED_VALUE
    return params


def _parameter_location(name: str, url: str, parameter: dict[str, Any]) -> str:
    explicit = str(parameter.get("parameter_location") or parameter.get("location") or "")
    if explicit:
        return explicit
    return "query" if name in parse_qs(urlsplit(url).query, keep_blank_values=True) else "unknown"


def _safe_auth_context(auth_context: dict[str, Any] | None) -> dict[str, Any]:
    context = auth_context or {}
    return {
        "enabled": bool(context),
        "role_label": context.get("role_label") or (context.get("session_profile") or {}).get("role_label") or "",
        "redaction_status": context.get("redaction_status") or (context.get("session_profile") or {}).get("redaction_status") or "redacted",
        "auth_context_type": context.get("auth_type") or (context.get("session_profile") or {}).get("auth_type") or "",
        "summary": "Redacted Auth Context. Raw credentials, cookies, tokens, and Authorization headers are not stored.",
    }
