"""FastAPI-safe Role and Permission Mapping handlers."""

from __future__ import annotations

from typing import Any

from scanner.permission_matrix import load_permission_matrix
from scanner.role_mapping_assistant import build_manual_plan, build_role_mapping, validate_role_mapping_inputs
from scanner.role_profiles import load_role_profiles


def api_list_roles() -> dict[str, Any]:
    roles = load_role_profiles()
    return {
        "roles": roles,
        "role_count": len(roles),
        "safety_notes": [
            "Role Profiles are safe labels only.",
            "No usernames, passwords, session cookies, bearer tokens, or Authorization headers are returned.",
        ],
    }


def api_validate_role_mapping(roles: list[dict[str, Any]], permission_matrix: dict[str, Any]) -> dict[str, Any]:
    return validate_role_mapping_inputs(roles, permission_matrix)


def api_map_role_endpoints(roles: list[dict[str, Any]], permission_matrix: dict[str, Any], endpoint_results: list[dict[str, Any]]) -> dict[str, Any]:
    return build_role_mapping(roles, permission_matrix, endpoint_results)


def api_manual_plan(role: dict[str, Any], endpoint: dict[str, Any] | str, expected_permission: str) -> dict[str, Any]:
    return build_manual_plan(role, endpoint, expected_permission)


def api_default_matrix() -> dict[str, Any]:
    matrix = load_permission_matrix()
    return {"permission_matrix": matrix}
