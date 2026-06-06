"""API helpers for Authenticated Web Assessment context."""

from __future__ import annotations

from typing import Any

from scanner.auth_context import build_auth_context
from scanner.authenticated_scope import classify_auth_boundary, classify_auth_required_endpoints
from scanner.session_profiles import list_session_profiles, validate_session_profile


def api_list_auth_profiles() -> dict[str, Any]:
    return {"profiles": list_session_profiles()}


def api_validate_auth_profile(profile: dict[str, Any]) -> dict[str, Any]:
    validation = validate_session_profile(profile)
    return {**validation, "auth_context_summary": build_auth_context(profile) if validation.get("valid") else {}}


def api_check_auth_boundary(profile: dict[str, Any], url: str) -> dict[str, Any]:
    return classify_auth_boundary(url, profile)


def api_classify_auth_endpoints(profile: dict[str, Any], endpoint_results: list[dict[str, Any]]) -> dict[str, Any]:
    return classify_auth_required_endpoints(endpoint_results, profile)
