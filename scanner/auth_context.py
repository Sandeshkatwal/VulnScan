"""Authenticated Web Assessment context helpers."""

from __future__ import annotations

from typing import Any

from scanner.auth_redaction import safe_profile_summary
from scanner.authenticated_scope import classify_auth_boundary
from scanner.session_profiles import validate_session_profile


def build_auth_context(profile: dict[str, Any]) -> dict[str, Any]:
    validation = validate_session_profile(profile)
    summary = safe_profile_summary(profile)
    return {
        "enabled": True,
        "session_profile": summary,
        "profile_id": summary.get("profile_id"),
        "profile_name": summary.get("profile_name"),
        "target_base_url": summary.get("target_base_url"),
        "auth_type": summary.get("auth_type"),
        "role_label": summary.get("role_label"),
        "cookie_names": summary.get("cookie_names", []),
        "header_names": summary.get("header_names", []),
        "redaction_status": summary.get("redaction_status"),
        "warnings": validation.get("warnings", []),
        "limitations": [
            "Authenticated Web Assessment context is local-only and redacted.",
            "No login automation, unauthorised authentication testing, automated credential testing, or cross-account testing is performed.",
        ],
    }


def validate_auth_context_scope(profile: dict[str, Any], target_url: str) -> dict[str, Any]:
    return classify_auth_boundary(target_url, profile)
