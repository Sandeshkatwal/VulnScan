"""Credentialed SSH audit profile definitions."""

from __future__ import annotations

from dataclasses import dataclass


CHECK_LABELS = {
    "collect_os_info": "OS information collection",
    "ssh_hardening": "SSH hardening review",
    "package_checks": "Package and patch indicators",
    "firewall_checks": "Firewall status indicators",
    "logging_checks": "Logging service indicators",
    "password_policy_checks": "Password policy indicators",
    "temp_directory_checks": "Temporary directory sticky bit checks",
    "cleartext_service_checks": "Cleartext service exposure indicators",
}


@dataclass(frozen=True)
class AuditProfile:
    """Read-only credentialed audit profile settings."""

    name: str
    description: str
    checks: dict[str, bool]
    default_audit_timeout_seconds: float

    @property
    def checks_enabled(self) -> list[str]:
        return [CHECK_LABELS[key] for key, enabled in self.checks.items() if enabled]

    @property
    def checks_skipped(self) -> list[str]:
        return [CHECK_LABELS[key] for key, enabled in self.checks.items() if not enabled]


AUDIT_PROFILES = {
    "basic": AuditProfile(
        name="basic",
        description="Fast credentialed verification and SSH configuration review.",
        default_audit_timeout_seconds=30.0,
        checks={
            "collect_os_info": True,
            "ssh_hardening": True,
            "package_checks": False,
            "firewall_checks": False,
            "logging_checks": False,
            "password_policy_checks": False,
            "temp_directory_checks": False,
            "cleartext_service_checks": False,
        },
    ),
    "standard": AuditProfile(
        name="standard",
        description="Recommended default for normal read-only credentialed audits.",
        default_audit_timeout_seconds=60.0,
        checks={
            "collect_os_info": True,
            "ssh_hardening": True,
            "package_checks": True,
            "firewall_checks": True,
            "logging_checks": True,
            "password_policy_checks": False,
            "temp_directory_checks": False,
            "cleartext_service_checks": False,
        },
    ),
    "detailed": AuditProfile(
        name="detailed",
        description="Deeper read-only host configuration audit with additional Linux indicators.",
        default_audit_timeout_seconds=90.0,
        checks={
            "collect_os_info": True,
            "ssh_hardening": True,
            "package_checks": True,
            "firewall_checks": True,
            "logging_checks": True,
            "password_policy_checks": True,
            "temp_directory_checks": True,
            "cleartext_service_checks": True,
        },
    ),
}

DEFAULT_AUDIT_PROFILE = "standard"
ERROR_PROFILE_INVALID = "SSH_PROFILE_INVALID"


class AuditProfileError(ValueError):
    """Raised when an audit profile name is not supported."""

    def __init__(self, message: str, error_code: str = ERROR_PROFILE_INVALID) -> None:
        super().__init__(message)
        self.error_code = error_code


def get_audit_profile(name: str | None) -> AuditProfile:
    """Return an audit profile by name with friendly validation."""
    normalized = (name or DEFAULT_AUDIT_PROFILE).strip().lower()
    profile = AUDIT_PROFILES.get(normalized)
    if profile is None:
        allowed = ", ".join(sorted(AUDIT_PROFILES))
        raise AuditProfileError(f"Unsupported audit profile '{name}'. Allowed values: {allowed}.")
    return profile
