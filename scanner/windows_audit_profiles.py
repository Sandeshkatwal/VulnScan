"""Windows audit profile definitions and resolution."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


WINDOWS_AUDIT_PROFILE_NAMES = ("foundation", "standard", "detailed")
WINRM_ONLY_SECTIONS = {
    "winrm_authentication",
    "windows_host_info",
    "windows_security_status",
    "windows_policy_status",
    "windows_registry_audit",
}
SECTION_LABELS = {
    "windows_service_reachability": "service reachability",
    "winrm_authentication": "WinRM auth",
    "windows_host_info": "host info",
    "windows_security_status": "security status",
    "windows_patch_status": "patch status",
    "windows_policy_status": "policy status",
    "windows_registry_audit": "registry audit",
}


class WindowsAuditProfileError(ValueError):
    """Raised when a Windows audit profile value is invalid."""


@dataclass(frozen=True)
class WindowsAuditProfile:
    profile_name: str
    profile_description: str
    service_reachability: bool
    winrm_authentication: bool
    host_information: bool
    security_status: bool
    patch_status: bool
    policy_status: bool
    registry_audit: bool
    default_audit_timeout_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


WINDOWS_AUDIT_PROFILES: dict[str, WindowsAuditProfile] = {
    "foundation": WindowsAuditProfile(
        profile_name="foundation",
        profile_description="Fast Windows service reachability and optional WinRM authentication validation.",
        service_reachability=True,
        winrm_authentication=True,
        host_information=False,
        security_status=False,
        patch_status=False,
        policy_status=False,
        registry_audit=False,
        default_audit_timeout_seconds=45.0,
    ),
    "standard": WindowsAuditProfile(
        profile_name="standard",
        profile_description="Read-only Windows baseline with host information, Firewall/Defender status, and patch indicators when WinRM is available.",
        service_reachability=True,
        winrm_authentication=True,
        host_information=True,
        security_status=True,
        patch_status=True,
        policy_status=False,
        registry_audit=False,
        default_audit_timeout_seconds=120.0,
    ),
    "detailed": WindowsAuditProfile(
        profile_name="detailed",
        profile_description="Read-only Windows baseline plus local security policy indicators and narrow registry audit template checks.",
        service_reachability=True,
        winrm_authentication=True,
        host_information=True,
        security_status=True,
        patch_status=True,
        policy_status=True,
        registry_audit=True,
        default_audit_timeout_seconds=180.0,
    ),
}


def get_windows_audit_profile(profile_name: str | None) -> WindowsAuditProfile:
    name = (profile_name or "standard").strip().lower()
    try:
        return WINDOWS_AUDIT_PROFILES[name]
    except KeyError as exc:
        allowed = ", ".join(WINDOWS_AUDIT_PROFILE_NAMES)
        raise WindowsAuditProfileError(
            f"Unsupported Windows audit profile '{profile_name}'. Allowed values: {allowed}."
        ) from exc


def resolve_windows_audit_profile(
    *,
    profile_name: str | None,
    auth_method: str,
    manual_host_info: bool = False,
    manual_security_status: bool = False,
    manual_patch_status: bool = False,
    manual_policy_status: bool = False,
    manual_registry_audit: bool = False,
) -> dict[str, Any]:
    """Resolve profile defaults and additive manual flags into effective section choices."""
    profile = get_windows_audit_profile(profile_name)
    auth_is_winrm = (auth_method or "none").strip().lower() == "winrm"
    profile_sections = _profile_section_ids(profile)
    manual_sections = {
        section_id
        for section_id, enabled in {
            "windows_host_info": manual_host_info,
            "windows_security_status": manual_security_status,
            "windows_patch_status": manual_patch_status,
            "windows_policy_status": manual_policy_status,
            "windows_registry_audit": manual_registry_audit,
        }.items()
        if enabled
    }

    enabled_by_profile = set(profile_sections)
    effective_sections = {"windows_service_reachability"}
    if auth_is_winrm:
        effective_sections.add("winrm_authentication")
    for section_id in profile_sections:
        if section_id in WINRM_ONLY_SECTIONS and not auth_is_winrm:
            continue
        effective_sections.add(section_id)
    effective_sections.update(manual_sections)

    skipped_sections = []
    skipped_reasons: dict[str, str] = {}
    for section_id in SECTION_LABELS:
        if section_id in effective_sections:
            continue
        reason = "not enabled by selected profile"
        if section_id in enabled_by_profile and section_id in WINRM_ONLY_SECTIONS and not auth_is_winrm:
            reason = "requires --windows-auth-method winrm and credentials"
        elif section_id == "winrm_authentication" and not auth_is_winrm:
            reason = "requires --windows-auth-method winrm and credentials"
        skipped_sections.append(section_id)
        skipped_reasons[section_id] = reason

    manual_overrides = sorted(manual_sections)
    return {
        "profile": profile,
        "profile_name": profile.profile_name,
        "profile_description": profile.profile_description,
        "profile_enabled_sections": sorted(effective_sections),
        "profile_skipped_sections": skipped_sections,
        "profile_manual_overrides": manual_overrides,
        "profile_default_timeout_seconds": profile.default_audit_timeout_seconds,
        "enabled_by_profile": {section_id: section_id in enabled_by_profile for section_id in SECTION_LABELS},
        "enabled_by_manual_flag": {section_id: section_id in manual_sections for section_id in SECTION_LABELS},
        "skipped_reasons": skipped_reasons,
        "section_labels": SECTION_LABELS,
        "collect_host_info": "windows_host_info" in effective_sections,
        "collect_security_status": "windows_security_status" in effective_sections,
        "collect_patch_status": "windows_patch_status" in effective_sections,
        "collect_policy_status": "windows_policy_status" in effective_sections,
        "collect_registry_audit": "windows_registry_audit" in effective_sections,
    }


def _profile_section_ids(profile: WindowsAuditProfile) -> set[str]:
    sections = {"windows_service_reachability"}
    if profile.winrm_authentication:
        sections.add("winrm_authentication")
    if profile.host_information:
        sections.add("windows_host_info")
    if profile.security_status:
        sections.add("windows_security_status")
    if profile.patch_status:
        sections.add("windows_patch_status")
    if profile.policy_status:
        sections.add("windows_policy_status")
    if profile.registry_audit:
        sections.add("windows_registry_audit")
    return sections
