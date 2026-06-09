"""Role and Permission Mapping Assistant orchestration."""

from __future__ import annotations

from typing import Any

from scanner.access_control_matrix import build_access_control_matrix_package, build_role_manual_validation_plan, infer_action_from_endpoint
from scanner.evidence import redact_nested
from scanner.permission_matrix import load_permission_matrix, validate_permission_matrix
from scanner.role_profiles import load_role_profiles, validate_no_credential_fields, validate_role_profiles


def validate_role_mapping_inputs(roles: list[dict[str, Any]], permission_matrix: dict[str, Any]) -> dict[str, Any]:
    validate_no_credential_fields({"roles": roles, "permission_matrix": permission_matrix})
    role_validation = validate_role_profiles(roles)
    matrix_validation = validate_permission_matrix(permission_matrix)
    return redact_nested(
        {
            "valid": bool(role_validation["valid"] and matrix_validation["valid"]),
            "role_validation": role_validation,
            "permission_matrix_validation": matrix_validation,
            "safety_notes": [
                "Authorised Test Accounts Only.",
                "Planning and documentation only; no live requests are performed.",
            ],
        }
    )


def build_role_mapping_from_files(
    roles_file: str,
    matrix_file: str,
    endpoint_results: list[dict[str, Any]],
) -> dict[str, Any]:
    roles = load_role_profiles(roles_file)
    matrix = load_permission_matrix(matrix_file)
    return build_role_mapping(roles, matrix, endpoint_results)


def build_role_mapping(
    roles: list[dict[str, Any]],
    permission_matrix: dict[str, Any],
    endpoint_results: list[dict[str, Any]],
) -> dict[str, Any]:
    validation = validate_role_mapping_inputs(roles, permission_matrix)
    if not validation["valid"]:
        return {"valid": False, "errors": validation, "role_mapping_summary": {"enabled": False}}
    normalised_roles = validation["role_validation"]["roles"]
    normalised_matrix = validation["permission_matrix_validation"]["permission_matrix"]
    package = build_access_control_matrix_package(normalised_roles, normalised_matrix, endpoint_results)
    package["valid"] = True
    return redact_nested(package)


def build_manual_plan(role: dict[str, Any], endpoint: dict[str, Any] | str, expected_permission: str) -> dict[str, Any]:
    validate_no_credential_fields({"role": role, "endpoint": endpoint})
    endpoint_payload = {"url": endpoint} if isinstance(endpoint, str) else dict(endpoint or {})
    inferred = infer_action_from_endpoint(endpoint_payload)
    return {"manual_validation_plan": build_role_manual_validation_plan(role, inferred, expected_permission), "inferred_action": inferred}
