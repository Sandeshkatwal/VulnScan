"""Role Profile loading and validation for Role and Permission Mapping.

Version 21.2 stores safe role labels and planning metadata only. It rejects
credential-like fields and does not retain raw session material.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from scanner.auth_redaction import safe_profile_summary
from scanner.evidence import redact_nested


ROLES_DIR = Path("data") / "roles"
ROLE_REPORTS_DIR = Path("reports") / "roles"
SUPPORTED_USER_TYPES = {
    "anonymous",
    "standard_user",
    "read_only_user",
    "power_user",
    "admin_user",
    "support_user",
    "tenant_user",
    "service_account",
    "custom",
}
CREDENTIAL_FIELD_TOKENS = (
    "password",
    "passwd",
    "secret",
    "token",
    "bearer",
    "cookie",
    "credential",
    "authorization",
    "auth_header",
    "api_key",
    "apikey",
)


class RoleProfileError(ValueError):
    """Raised when a Role Profile is invalid or unsafe."""


@dataclass
class RoleProfile:
    role_id: str
    role_name: str
    role_label: str
    description: str = ""
    linked_session_profile_id: str | None = None
    linked_session_profile_name: str | None = None
    test_account_label: str | None = None
    tenant_label: str | None = None
    user_type: str = "custom"
    expected_access_level: str = "unknown"
    allowed_actions: list[str] = field(default_factory=list)
    disallowed_actions: list[str] = field(default_factory=list)
    sensitive_actions: list[str] = field(default_factory=list)
    notes: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def ensure_role_dirs() -> None:
    ROLES_DIR.mkdir(parents=True, exist_ok=True)
    ROLE_REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def credential_field_errors(payload: Any, path: str = "") -> list[str]:
    errors: list[str] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_text = str(key).lower()
            current = f"{path}.{key}" if path else str(key)
            if any(token in key_text for token in CREDENTIAL_FIELD_TOKENS):
                errors.append(f"Credential-like field is not allowed in Role and Permission Mapping: {current}")
            errors.extend(credential_field_errors(value, current))
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            errors.extend(credential_field_errors(item, f"{path}[{index}]"))
    return errors


def validate_no_credential_fields(payload: Any) -> None:
    errors = credential_field_errors(payload)
    if errors:
        raise RoleProfileError("; ".join(errors))


def normalise_role_profile(payload: dict[str, Any], session_profiles: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    validate_no_credential_fields(payload)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    role_name = str(payload.get("role_name") or payload.get("role_id") or "").strip()
    role_id = str(payload.get("role_id") or role_name or f"role_{uuid4().hex[:8]}").strip()
    role_label = str(payload.get("role_label") or role_name or role_id).strip()
    user_type = str(payload.get("user_type") or "custom").strip()
    if not role_id or not role_name or not role_label:
        raise RoleProfileError("Role Profile requires role_id, role_name, and role_label.")
    if user_type not in SUPPORTED_USER_TYPES:
        raise RoleProfileError(f"Unsupported user_type: {user_type}")
    linked_id = payload.get("linked_session_profile_id")
    linked_summary = None
    if linked_id and session_profiles:
        linked_summary = safe_profile_summary(session_profiles.get(str(linked_id), {}))
    profile = RoleProfile(
        role_id=role_id,
        role_name=role_name,
        role_label=role_label,
        description=str(payload.get("description") or ""),
        linked_session_profile_id=str(linked_id) if linked_id else None,
        linked_session_profile_name=str(payload.get("linked_session_profile_name") or (linked_summary or {}).get("profile_name") or "") or None,
        test_account_label=str(payload.get("test_account_label") or "") or None,
        tenant_label=str(payload.get("tenant_label") or "") or None,
        user_type=user_type,
        expected_access_level=str(payload.get("expected_access_level") or "unknown"),
        allowed_actions=[str(item) for item in payload.get("allowed_actions") or []],
        disallowed_actions=[str(item) for item in payload.get("disallowed_actions") or []],
        sensitive_actions=[str(item) for item in payload.get("sensitive_actions") or []],
        notes=str(payload.get("notes") or ""),
        created_at=str(payload.get("created_at") or now),
        updated_at=str(payload.get("updated_at") or now),
    )
    return redact_nested(profile.to_dict())


def validate_role_profiles(roles: list[dict[str, Any]], session_profiles: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    normalised: list[dict[str, Any]] = []
    errors: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(roles or []):
        try:
            role = normalise_role_profile(dict(item or {}), session_profiles=session_profiles)
            if role["role_id"] in seen:
                raise RoleProfileError(f"Duplicate role_id: {role['role_id']}")
            seen.add(role["role_id"])
            normalised.append(role)
        except RoleProfileError as exc:
            errors.append(f"roles[{index}]: {exc}")
    return {
        "valid": not errors,
        "errors": errors,
        "roles": normalised,
        "role_count": len(normalised),
        "limitations": [
            "Role Profiles are planning metadata only.",
            "Do not store usernames, passwords, session cookies, bearer tokens, or Authorization headers.",
        ],
    }


def load_role_profiles(path: str | Path = ROLES_DIR / "sample_roles.json") -> list[dict[str, Any]]:
    role_path = _resolve_role_path(path)
    try:
        payload = json.loads(role_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RoleProfileError(f"Role Profile file was not found: {role_path}") from exc
    except json.JSONDecodeError as exc:
        raise RoleProfileError(f"Role Profile file is not valid JSON: {role_path}") from exc
    roles = payload.get("roles") if isinstance(payload, dict) else payload
    if not isinstance(roles, list):
        raise RoleProfileError("Role Profile file must contain a roles list.")
    validation = validate_role_profiles(roles)
    if not validation["valid"]:
        raise RoleProfileError("; ".join(validation["errors"]))
    return validation["roles"]


def role_profiles_summary(roles: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "enabled": True,
        "role_count": len(roles or []),
        "roles": [
            {
                "role_id": role.get("role_id"),
                "role_label": role.get("role_label"),
                "user_type": role.get("user_type"),
                "tenant_label": role.get("tenant_label"),
                "linked_session_profile_name": role.get("linked_session_profile_name"),
                "expected_access_level": role.get("expected_access_level"),
            }
            for role in roles or []
        ],
        "safety_notes": [
            "Authorised Test Accounts Only.",
            "Linked Session Profiles must be redacted summaries only.",
        ],
    }


def find_role(roles: list[dict[str, Any]], role: str) -> dict[str, Any]:
    needle = str(role or "").lower()
    for item in roles or []:
        if needle in {str(item.get("role_id") or "").lower(), str(item.get("role_name") or "").lower(), str(item.get("role_label") or "").lower()}:
            return item
    raise RoleProfileError(f"Role was not found: {role}")


def _resolve_role_path(path: str | Path) -> Path:
    candidate = Path(path)
    resolved = candidate if candidate.is_absolute() else Path.cwd() / candidate
    root = (Path.cwd() / ROLES_DIR).resolve()
    resolved = resolved.resolve()
    if not _inside(resolved, root):
        raise RoleProfileError("Role files must be under data/roles.")
    return resolved


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
