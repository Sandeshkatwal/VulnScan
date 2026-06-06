"""Local redacted session profile loading and validation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from scanner.auth_redaction import detect_secret_like_auth_material, redact_session_profile, safe_profile_summary


AUTH_PROFILES_DIR = Path("data") / "auth_profiles"
SUPPORTED_AUTH_TYPES = {"cookie", "bearer_token", "custom_header", "basic_auth_placeholder", "manual", "none"}


class SessionProfileError(ValueError):
    """Raised when a session profile is invalid or unsafe."""


def ensure_auth_profile_dirs() -> None:
    AUTH_PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    (Path("reports") / "authenticated").mkdir(parents=True, exist_ok=True)


def load_session_profile(path: str | Path) -> dict[str, Any]:
    profile_path = _resolve_profile_path(path)
    try:
        payload = json.loads(profile_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SessionProfileError(f"Session Profile was not found: {profile_path}") from exc
    except json.JSONDecodeError as exc:
        raise SessionProfileError("Session Profile JSON is invalid.") from exc
    if not isinstance(payload, dict):
        raise SessionProfileError("Session Profile must be a JSON object.")
    payload.setdefault("profile_id", profile_path.stem)
    payload.setdefault("created_at", datetime.now(timezone.utc).isoformat(timespec="seconds"))
    payload.setdefault("updated_at", payload["created_at"])
    return payload


def validate_session_profile(profile: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    if str(profile.get("auth_type") or "manual") not in SUPPORTED_AUTH_TYPES:
        errors.append("Unsupported auth_type.")
    target = str(profile.get("target_base_url") or "")
    parsed = urlsplit(target)
    if not parsed.scheme or not parsed.netloc:
        errors.append("target_base_url must be an absolute HTTP or HTTPS URL.")
    allowed_hosts = [str(host).lower() for host in profile.get("allowed_hosts") or [] if str(host)]
    if not allowed_hosts and parsed.hostname:
        warnings.append("allowed_hosts was empty; target host will be used for the Authentication Context only.")
    for value in list(dict(profile.get("cookies") or {}).values()) + list(dict(profile.get("headers") or {}).values()):
        if detect_secret_like_auth_material(value) and "[REDACTED" not in str(value):
            warnings.append("Profile appears to contain raw-looking auth material. It will be redacted in summaries and reports.")
            break
    summary = safe_profile_summary(profile)
    return {"valid": not errors, "errors": errors, "warnings": warnings, "session_profile": summary, "redaction_status": summary["redaction_status"]}


def get_redacted_session_profile(profile: dict[str, Any]) -> dict[str, Any]:
    return redact_session_profile(profile)


def list_session_profiles(directory: Path | str = AUTH_PROFILES_DIR) -> list[dict[str, Any]]:
    root = Path(directory)
    if not root.exists():
        return []
    profiles: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.json")):
        if path.name.endswith((".local.json", ".secret.json", ".private.json")) or "real" in path.name.lower():
            continue
        try:
            profiles.append(safe_profile_summary(load_session_profile(path)))
        except SessionProfileError:
            continue
    return profiles


def _resolve_profile_path(path: str | Path) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        resolved = (Path.cwd() / candidate).resolve()
        if not resolved.exists():
            package_root = Path(__file__).resolve().parent.parent
            fallback = (package_root / candidate).resolve()
            if fallback.exists():
                resolved = fallback
    root = (Path.cwd() / AUTH_PROFILES_DIR).resolve()
    package_root = (Path(__file__).resolve().parent.parent / AUTH_PROFILES_DIR).resolve()
    if not _inside(resolved, root) and not _inside(resolved, package_root):
        raise SessionProfileError("Session Profile path must be under data/auth_profiles.")
    return resolved


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
