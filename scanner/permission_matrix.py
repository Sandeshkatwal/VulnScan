"""Permission Action and Permission Matrix helpers for Version 21.2."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from scanner.evidence import redact_nested
from scanner.role_profiles import ROLES_DIR, RoleProfileError, validate_no_credential_fields


ACTION_TYPES = {
    "view",
    "create",
    "edit",
    "delete",
    "export",
    "import",
    "upload",
    "download",
    "approve",
    "reject",
    "manage_users",
    "manage_roles",
    "billing",
    "admin",
    "authentication",
    "custom",
}
SENSITIVITY_LEVELS = {"low", "medium", "high", "critical"}
EXPECTED_PERMISSIONS = {"allowed", "denied", "conditional", "unknown"}
VALIDATION_STATUSES = {"not_tested", "manually_verified_allowed", "manually_verified_denied", "needs_review", "not_applicable"}
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class PermissionMatrixError(ValueError):
    """Raised when Permission Matrix data is invalid."""


@dataclass
class PermissionAction:
    action_id: str
    action_name: str
    action_type: str
    description: str = ""
    endpoint_pattern: str = ""
    http_method: str = ""
    sensitivity: str = "medium"
    state_changing: bool = False
    destructive: bool = False
    requires_manual_validation: bool = True
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RoleActionRule:
    role_id: str
    action_id: str
    expected_permission: str = "unknown"
    validation_status: str = "not_tested"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PermissionMatrix:
    matrix_id: str
    matrix_name: str
    target: str
    roles: list[dict[str, Any]] = field(default_factory=list)
    actions: list[dict[str, Any]] = field(default_factory=list)
    role_action_rules: list[dict[str, Any]] = field(default_factory=list)
    endpoint_mappings: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def default_permission_actions() -> list[dict[str, Any]]:
    return [
        _action("view", "View", "view", "View pages or records.", "GET", "low"),
        _action("create", "Create", "create", "Create records or resources.", "POST", "high", state_changing=True),
        _action("edit", "Edit", "edit", "Change settings or records.", "POST", "high", state_changing=True),
        _action("delete", "Delete", "delete", "Delete or remove resources.", "DELETE", "critical", state_changing=True, destructive=True),
        _action("export", "Export", "export", "Export reports or data.", "GET", "high"),
        _action("import", "Import", "import", "Import data.", "POST", "high", state_changing=True),
        _action("upload", "Upload", "upload", "Upload files or data.", "POST", "high", state_changing=True),
        _action("download", "Download", "download", "Download files or data.", "GET", "medium"),
        _action("approve", "Approve", "approve", "Approve workflow items.", "POST", "high", state_changing=True),
        _action("reject", "Reject", "reject", "Reject workflow items.", "POST", "high", state_changing=True),
        _action("manage_users", "Manage Users", "manage_users", "Manage user accounts.", "POST", "critical", state_changing=True),
        _action("manage_roles", "Manage Roles", "manage_roles", "Manage role assignments.", "POST", "critical", state_changing=True),
        _action("billing", "Billing", "billing", "Access billing workflows.", "", "critical", state_changing=True),
        _action("admin", "Admin", "admin", "Administrative functionality.", "", "critical", state_changing=True),
        _action("authentication", "Authentication", "authentication", "Login, logout, and session workflows.", "", "medium"),
    ]


def normalise_permission_action(payload: dict[str, Any]) -> dict[str, Any]:
    validate_no_credential_fields(payload)
    action_type = str(payload.get("action_type") or payload.get("action_id") or "custom").strip()
    if action_type not in ACTION_TYPES:
        raise PermissionMatrixError(f"Unsupported action_type: {action_type}")
    sensitivity = str(payload.get("sensitivity") or "medium").strip()
    if sensitivity not in SENSITIVITY_LEVELS:
        raise PermissionMatrixError(f"Unsupported sensitivity: {sensitivity}")
    method = str(payload.get("http_method") or "").upper()
    state_changing = bool(payload.get("state_changing")) or method in STATE_CHANGING_METHODS
    destructive = bool(payload.get("destructive")) or action_type == "delete" or method == "DELETE"
    action = PermissionAction(
        action_id=str(payload.get("action_id") or action_type or f"action_{uuid4().hex[:8]}"),
        action_name=str(payload.get("action_name") or action_type.replace("_", " ").title()),
        action_type=action_type,
        description=str(payload.get("description") or ""),
        endpoint_pattern=str(payload.get("endpoint_pattern") or ""),
        http_method=method,
        sensitivity=sensitivity,
        state_changing=state_changing,
        destructive=destructive,
        requires_manual_validation=bool(payload.get("requires_manual_validation", True)) or state_changing or destructive,
        notes=str(payload.get("notes") or ""),
    )
    return redact_nested(action.to_dict())


def normalise_role_action_rule(payload: dict[str, Any]) -> dict[str, Any]:
    validate_no_credential_fields(payload)
    expected = str(payload.get("expected_permission") or "unknown")
    status = str(payload.get("validation_status") or "not_tested")
    if expected not in EXPECTED_PERMISSIONS:
        raise PermissionMatrixError(f"Unsupported expected_permission: {expected}")
    if status not in VALIDATION_STATUSES:
        raise PermissionMatrixError(f"Unsupported validation_status: {status}")
    rule = RoleActionRule(
        role_id=str(payload.get("role_id") or ""),
        action_id=str(payload.get("action_id") or ""),
        expected_permission=expected,
        validation_status=status,
        notes=str(payload.get("notes") or ""),
    )
    if not rule.role_id or not rule.action_id:
        raise PermissionMatrixError("role_action_rule requires role_id and action_id.")
    return redact_nested(rule.to_dict())


def validate_permission_matrix(payload: dict[str, Any]) -> dict[str, Any]:
    validate_no_credential_fields(payload)
    errors: list[str] = []
    actions: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    for index, item in enumerate(payload.get("actions") or []):
        try:
            actions.append(normalise_permission_action(dict(item or {})))
        except (PermissionMatrixError, RoleProfileError) as exc:
            errors.append(f"actions[{index}]: {exc}")
    if not actions:
        actions = default_permission_actions()
    for index, item in enumerate(payload.get("role_action_rules") or []):
        try:
            rules.append(normalise_role_action_rule(dict(item or {})))
        except (PermissionMatrixError, RoleProfileError) as exc:
            errors.append(f"role_action_rules[{index}]: {exc}")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    matrix = PermissionMatrix(
        matrix_id=str(payload.get("matrix_id") or f"matrix_{uuid4().hex[:8]}"),
        matrix_name=str(payload.get("matrix_name") or "Access-Control Matrix"),
        target=str(payload.get("target") or "local-demo"),
        roles=[redact_nested(dict(item or {})) if isinstance(item, dict) else str(item) for item in payload.get("roles") or []],
        actions=actions,
        role_action_rules=rules,
        endpoint_mappings=[redact_nested(dict(item or {})) for item in payload.get("endpoint_mappings") or []],
        created_at=str(payload.get("created_at") or now),
        updated_at=str(payload.get("updated_at") or now),
    )
    return {
        "valid": not errors,
        "errors": errors,
        "permission_matrix": redact_nested(matrix.to_dict()),
        "summary": permission_matrix_summary(matrix.to_dict()),
    }


def load_permission_matrix(path: str | Path = ROLES_DIR / "sample_permission_matrix.json") -> dict[str, Any]:
    matrix_path = _resolve_matrix_path(path)
    try:
        payload = json.loads(matrix_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PermissionMatrixError(f"Permission Matrix file was not found: {matrix_path}") from exc
    except json.JSONDecodeError as exc:
        raise PermissionMatrixError(f"Permission Matrix file is not valid JSON: {matrix_path}") from exc
    if not isinstance(payload, dict):
        raise PermissionMatrixError("Permission Matrix file must be a JSON object.")
    validation = validate_permission_matrix(payload)
    if not validation["valid"]:
        raise PermissionMatrixError("; ".join(validation["errors"]))
    return validation["permission_matrix"]


def permission_matrix_summary(matrix: dict[str, Any]) -> dict[str, Any]:
    actions = matrix.get("actions") or []
    rules = matrix.get("role_action_rules") or []
    return {
        "enabled": True,
        "matrix_id": matrix.get("matrix_id"),
        "matrix_name": matrix.get("matrix_name"),
        "target": matrix.get("target"),
        "role_count": len(matrix.get("roles") or []),
        "action_count": len(actions),
        "rule_count": len(rules),
        "manual_validation_required_count": sum(1 for action in actions if action.get("requires_manual_validation")),
        "destructive_action_count": sum(1 for action in actions if action.get("destructive")),
        "state_changing_action_count": sum(1 for action in actions if action.get("state_changing")),
        "limitations": ["Documentation and planning only. VulScan does not automatically test permissions."],
    }


def expected_permission_for(role_id: str, action_id: str, matrix: dict[str, Any]) -> tuple[str, str, str]:
    for rule in matrix.get("role_action_rules") or []:
        if str(rule.get("role_id")) == str(role_id) and str(rule.get("action_id")) == str(action_id):
            return str(rule.get("expected_permission") or "unknown"), str(rule.get("validation_status") or "not_tested"), str(rule.get("notes") or "")
    return "unknown", "not_tested", ""


def action_by_type_or_id(action_type: str, actions: list[dict[str, Any]]) -> dict[str, Any]:
    for action in actions or []:
        if str(action.get("action_type")) == action_type or str(action.get("action_id")) == action_type:
            return action
    return normalise_permission_action({"action_id": action_type, "action_type": action_type if action_type in ACTION_TYPES else "custom"})


def _action(action_id: str, name: str, action_type: str, description: str, method: str, sensitivity: str, state_changing: bool = False, destructive: bool = False) -> dict[str, Any]:
    return PermissionAction(
        action_id=action_id,
        action_name=name,
        action_type=action_type,
        description=description,
        http_method=method,
        sensitivity=sensitivity,
        state_changing=state_changing,
        destructive=destructive,
        requires_manual_validation=True,
    ).to_dict()


def _resolve_matrix_path(path: str | Path) -> Path:
    candidate = Path(path)
    resolved = candidate if candidate.is_absolute() else Path.cwd() / candidate
    root = (Path.cwd() / ROLES_DIR).resolve()
    resolved = resolved.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise PermissionMatrixError("Permission Matrix files must be under data/roles.") from exc
    return resolved
