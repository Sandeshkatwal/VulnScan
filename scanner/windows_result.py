"""Normalised Windows audit section and check result models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from scanner.evidence import REDACTION_TOKEN, redact_nested
from scanner.finding import finding_to_dict, findings_to_dicts


WINDOWS_SECTION_STATUSES = {"success", "failed", "skipped", "partial"}
WINDOWS_CHECK_STATUSES = {"success", "failed", "skipped", "timeout", "partial", "unknown"}
WINDOWS_ERROR_CODES = {
    "WINDOWS_AUTH_FAILED",
    "WINDOWS_COMMAND_TIMEOUT",
    "WINDOWS_COMMAND_FAILED",
    "WINDOWS_WINRM_CONNECTION_FAILED",
    "WINDOWS_TEMPLATE_INVALID",
    "WINDOWS_REGISTRY_VALUE_NOT_FOUND",
    "WINDOWS_AUDIT_TIME_BUDGET_EXCEEDED",
}

SECTION_DEFINITIONS: dict[str, dict[str, str]] = {
    "windows_service_reachability": {
        "section_name": "Windows Service Reachability",
        "source": "windows_audit",
        "legacy_key": "service_reachability",
    },
    "winrm_authentication": {
        "section_name": "WinRM Authentication",
        "source": "windows_audit",
        "legacy_key": "winrm_authentication",
    },
    "windows_host_info": {
        "section_name": "Windows Host Information",
        "source": "windows_audit",
        "legacy_key": "host_information",
    },
    "windows_security_status": {
        "section_name": "Windows Security Status",
        "source": "windows_security_audit",
        "legacy_key": "security_status",
    },
    "windows_patch_status": {
        "section_name": "Windows Patch Status",
        "source": "windows_patch_audit",
        "legacy_key": "patch_status",
    },
    "windows_policy_status": {
        "section_name": "Windows Local Security Policy",
        "source": "windows_policy_audit",
        "legacy_key": "local_security_policy",
    },
    "windows_registry_audit": {
        "section_name": "Windows Registry Audit",
        "source": "windows_registry_audit",
        "legacy_key": "registry_audit",
    },
}


@dataclass(frozen=True)
class WindowsAuditError:
    """Safe normalised Windows audit error metadata."""

    error_code: str
    message: str
    severity: str
    safe_detail: str
    source: str
    section_id: str
    check_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _redact_windows(asdict(self))


@dataclass(frozen=True)
class WindowsCheckResult:
    """Normalised result for one Windows audit check."""

    check_id: str
    check_name: str
    source: str
    status: str
    command_name: str = ""
    command_used_safe_label: str = ""
    duration_seconds: float = 0.0
    observed_value: Any = None
    expected_value: Any = None
    evidence_summary: str = ""
    findings_count: int = 0
    error_code: str = ""
    error_message: str = ""
    skipped_reason: str = ""
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if data["status"] not in WINDOWS_CHECK_STATUSES:
            data["status"] = "unknown"
        return _redact_windows(_drop_empty(data))


@dataclass(frozen=True)
class WindowsAuditSectionResult:
    """Normalised result for one Windows audit section."""

    section_id: str
    section_name: str
    source: str
    status: str
    started_at: str = ""
    ended_at: str = ""
    duration_seconds: float = 0.0
    checks_planned: int = 0
    checks_completed: int = 0
    checks_failed: int = 0
    checks_skipped: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    errors: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    performance: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    enabled_by_profile: bool = False
    enabled_by_manual_flag: bool = False
    skipped_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if data["status"] not in WINDOWS_SECTION_STATUSES:
            data["status"] = "failed"
        data["findings"] = findings_to_dicts(data.get("findings", []))
        return _redact_windows(data)


def build_windows_audit_sections(
    *,
    windows_result: dict[str, Any],
    windows_findings: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Build stable Windows audit sections from the existing audit result shape."""
    if not windows_result.get("enabled"):
        return []

    summary = dict(windows_result.get("summary") or {})
    legacy_sections = dict(summary.get("sections") or {})
    started_at = str(windows_result.get("started_at") or summary.get("started_at") or "")
    ended_at = str(windows_result.get("ended_at") or summary.get("ended_at") or "")
    raw_findings = windows_findings if windows_findings is not None else windows_result.get("findings", [])
    findings = [finding_to_dict(item) for item in (raw_findings or [])]
    errors = [_normalise_error(error) for error in windows_result.get("errors", []) or []]

    results: list[dict[str, Any]] = []
    enabled_by_profile = dict(summary.get("profile_section_enabled_by_profile") or {})
    enabled_by_manual_flag = dict(summary.get("profile_section_enabled_by_manual_flag") or {})
    skipped_reasons = dict(summary.get("profile_section_skipped_reasons") or {})
    for section_id, definition in SECTION_DEFINITIONS.items():
        legacy = dict(legacy_sections.get(definition["legacy_key"], {}))
        section_findings = _findings_for_section(section_id, findings)
        section_errors = _errors_for_section(section_id, errors, definition["source"], legacy)
        status = _section_status(legacy.get("status"), section_errors)
        skipped_reason = str(skipped_reasons.get(section_id) or "")
        if status == "skipped" and not skipped_reason:
            skipped_reason = str(legacy.get("limitation") or "")
        result = WindowsAuditSectionResult(
            section_id=section_id,
            section_name=definition["section_name"],
            source=definition["source"],
            status=status,
            started_at=started_at,
            ended_at=ended_at,
            duration_seconds=float(legacy.get("duration_seconds") or 0.0),
            checks_planned=int(legacy.get("checks_planned") or 0),
            checks_completed=int(legacy.get("checks_completed") or 0),
            checks_failed=int(legacy.get("checks_failed") or len(section_errors)),
            checks_skipped=int(legacy.get("checks_skipped") or 0),
            findings=section_findings,
            summary=_section_summary(section_id, summary),
            errors=section_errors,
            limitations=_section_limitations(section_id, legacy, summary),
            performance={
                "duration_seconds": float(legacy.get("duration_seconds") or 0.0),
                "timed_out_commands": int(summary.get("timed_out_commands") or 0) if section_id == "winrm_authentication" else 0,
            },
            metadata={"legacy_section_key": definition["legacy_key"]},
            enabled_by_profile=bool(enabled_by_profile.get(section_id)),
            enabled_by_manual_flag=bool(enabled_by_manual_flag.get(section_id)),
            skipped_reason=skipped_reason,
        )
        results.append(result.to_dict())
    return results


def build_windows_consolidated_summary(
    *,
    sections: list[dict[str, Any]],
    windows_findings: list[dict[str, Any]] | None = None,
    base_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the consolidated Windows summary from normalised sections."""
    base = dict(base_summary or {})
    if not sections:
        base.update(
            {
                "enabled": False,
                "status": "skipped",
                "sections_completed": 0,
                "sections_failed": 0,
                "sections_skipped": 0,
                "sections_partial": 0,
                "total_windows_findings": 0,
                "highest_windows_risk_score": 0,
                "highest_windows_risk_label": "Informational",
                "checks_completed": 0,
                "checks_failed": 0,
                "checks_skipped": 0,
            }
        )
        return _redact_windows(base)

    findings = list(windows_findings or [])
    highest = max(findings, key=lambda item: int(item.get("risk_score") or 0), default={})
    counts = {status: sum(1 for section in sections if section.get("status") == status) for status in WINDOWS_SECTION_STATUSES}
    checks_completed = sum(int(section.get("checks_completed") or 0) for section in sections)
    checks_failed = sum(int(section.get("checks_failed") or 0) for section in sections)
    checks_skipped = sum(int(section.get("checks_skipped") or 0) for section in sections)
    status = _consolidated_status(sections)
    base.update(
        {
            "enabled": True,
            "status": status,
            "sections_completed": counts["success"],
            "sections_failed": counts["failed"],
            "sections_skipped": counts["skipped"],
            "sections_partial": counts["partial"],
            "total_windows_findings": len(findings),
            "highest_windows_risk_score": int(highest.get("risk_score") or base.get("highest_windows_risk_score") or 0),
            "highest_windows_risk_label": str(highest.get("risk_label") or base.get("highest_windows_risk_label") or "Informational"),
            "checks_completed": checks_completed,
            "checks_failed": checks_failed,
            "checks_skipped": checks_skipped,
            "windows_audit_sections": sections,
        }
    )
    return _redact_windows(base)


def build_windows_error(
    *,
    error_code: str | None,
    message: str,
    source: str,
    section_id: str,
    check_name: str = "",
    severity: str = "error",
    safe_detail: str = "",
) -> dict[str, Any] | None:
    """Build a safe Windows audit error dictionary."""
    if not error_code and not message:
        return None
    normalised = _normalise_error_code(str(error_code or "WINDOWS_COMMAND_FAILED"))
    return WindowsAuditError(
        error_code=normalised,
        message=str(message or normalised),
        severity=severity,
        safe_detail=safe_detail,
        source=source,
        section_id=section_id,
        check_name=check_name,
    ).to_dict()


def _consolidated_status(sections: list[dict[str, Any]]) -> str:
    statuses = [str(section.get("status") or "skipped") for section in sections]
    requested = [
        section
        for section in sections
        if int(section.get("checks_planned") or 0) > 0 or section.get("section_id") == "windows_service_reachability"
    ]
    requested_statuses = [str(section.get("status") or "skipped") for section in requested]
    useful_completed = any(
        section.get("status") in {"success", "partial"} and int(section.get("checks_completed") or 0) > 0
        for section in sections
        if section.get("section_id") not in {"windows_service_reachability", "winrm_authentication"}
    )
    auth_failed = any(
        section.get("section_id") == "winrm_authentication" and section.get("status") == "failed"
        for section in sections
    )
    if auth_failed and not useful_completed:
        return "failed"
    if all(status == "skipped" for status in statuses):
        return "skipped"
    if requested_statuses and all(status == "success" for status in requested_statuses):
        return "success"
    if any(status in {"failed", "partial", "skipped"} for status in requested_statuses) and any(status == "success" for status in requested_statuses):
        return "partial"
    if any(status == "failed" for status in requested_statuses):
        return "failed"
    return "partial"


def _section_status(raw_status: Any, errors: list[dict[str, Any]]) -> str:
    status = str(raw_status or "skipped")
    if status not in WINDOWS_SECTION_STATUSES:
        status = "failed" if errors else "skipped"
    return status


def _normalise_error(error: dict[str, Any]) -> dict[str, Any]:
    code = _normalise_error_code(str(error.get("error_code") or "WINDOWS_COMMAND_FAILED"))
    return _redact_windows(
        {
            "error_code": code,
            "message": str(error.get("message") or code),
            "severity": str(error.get("severity") or "error"),
            "safe_detail": str(error.get("safe_detail") or ""),
            "source": str(error.get("source") or "windows_audit"),
            "section_id": str(error.get("section_id") or ""),
            "check_name": str(error.get("check_name") or ""),
        }
    )


def _normalise_error_code(error_code: str) -> str:
    mapping = {
        "WINRM_AUTH_FAILED": "WINDOWS_AUTH_FAILED",
        "WINRM_TIMEOUT": "WINDOWS_COMMAND_TIMEOUT",
        "WINRM_CONNECTION_FAILED": "WINDOWS_WINRM_CONNECTION_FAILED",
        "WINDOWS_REGISTRY_TEMPLATE_INVALID": "WINDOWS_TEMPLATE_INVALID",
        "WINDOWS_REGISTRY_TEMPLATE_INVALID_JSON": "WINDOWS_TEMPLATE_INVALID",
        "WINDOWS_REGISTRY_VALUE_NOT_FOUND": "WINDOWS_REGISTRY_VALUE_NOT_FOUND",
    }
    normalised = mapping.get(error_code, error_code)
    return normalised if normalised in WINDOWS_ERROR_CODES or normalised.startswith("WINDOWS_") else "WINDOWS_COMMAND_FAILED"


def _errors_for_section(
    section_id: str,
    errors: list[dict[str, Any]],
    source: str,
    legacy: dict[str, Any],
) -> list[dict[str, Any]]:
    direct = [
        error
        for error in errors
        if error.get("section_id") == section_id
        or (not error.get("section_id") and error.get("source") == source and _check_matches_section(section_id, str(error.get("check_name") or "")))
    ]
    if direct:
        return direct
    if legacy.get("error_code"):
        built = build_windows_error(
            error_code=str(legacy.get("error_code") or ""),
            message=str(legacy.get("error_message") or legacy.get("error_code") or "Windows audit section failed."),
            source=source,
            section_id=section_id,
            safe_detail=str(legacy.get("safe_detail") or ""),
        )
        return [built] if built else []
    return []


def _check_matches_section(section_id: str, check_name: str) -> bool:
    text = check_name.lower()
    tokens = {
        "windows_service_reachability": ("reachability", "smb", "rdp"),
        "winrm_authentication": ("winrm", "authentication"),
        "windows_host_info": ("host", "information"),
        "windows_security_status": ("security", "defender", "firewall"),
        "windows_policy_status": ("policy", "accounts"),
        "windows_registry_audit": ("registry",),
    }.get(section_id, ())
    return any(token in text for token in tokens)


def _findings_for_section(section_id: str, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [finding for finding in findings if _finding_matches_section(section_id, finding)]


def _finding_matches_section(section_id: str, finding: dict[str, Any]) -> bool:
    source = str(finding.get("source") or "")
    text = f"{finding.get('category') or ''} {finding.get('title') or ''}".lower()
    if section_id == "windows_service_reachability":
        return source == "windows_audit" and any(token in text for token in ("reachability", "service", "smb", "rdp"))
    if section_id == "winrm_authentication":
        return source == "windows_audit" and "authentication" in text
    if section_id == "windows_host_info":
        return source == "windows_audit" and "host information" in text
    if section_id == "windows_security_status":
        return source == "windows_security_audit"
    if section_id == "windows_policy_status":
        return source == "windows_policy_audit"
    if section_id == "windows_registry_audit":
        return source == "windows_registry_audit"
    return False


def _section_summary(section_id: str, summary: dict[str, Any]) -> dict[str, Any]:
    if section_id == "windows_service_reachability":
        return {"service_statuses": summary.get("service_statuses") or []}
    if section_id == "winrm_authentication":
        return {
            "attempted": bool(summary.get("winrm_auth_attempted")),
            "authenticated": bool(summary.get("winrm_authenticated")),
            "endpoint_used": summary.get("winrm_endpoint_used") or "",
            "transport": summary.get("winrm_transport") or "",
            "validation_result_summary": summary.get("validation_result_summary") or "",
        }
    if section_id == "windows_host_info":
        return {"host_info": summary.get("windows_host_info") or {}}
    if section_id == "windows_security_status":
        return {"security_status": summary.get("windows_security_status") or {}}
    if section_id == "windows_patch_status":
        return {"patch_status": summary.get("windows_patch_status") or {}}
    if section_id == "windows_policy_status":
        return {"policy_status": summary.get("windows_policy_status") or {}}
    if section_id == "windows_registry_audit":
        return {"registry_audit": summary.get("windows_registry_audit") or {}}
    return {}


def _section_limitations(section_id: str, legacy: dict[str, Any], summary: dict[str, Any]) -> list[str]:
    limitations: list[str] = []
    if legacy.get("limitation"):
        limitations.append(str(legacy["limitation"]))
    section_summary = _section_summary(section_id, summary)
    for value in section_summary.values():
        if isinstance(value, dict):
            limitations.extend(str(item) for item in value.get("limitations", []) or [])
            limitations.extend(str(item) for item in value.get("security_status_limitations", []) or [])
    if not limitations and section_id == "windows_patch_status":
        limitations.append("Patch status flag is reserved in this build.")
    return limitations


def _drop_empty(data: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in data.items()
        if value not in (None, "", [], {})
    }


def _redact_windows(value: Any) -> Any:
    redacted = redact_nested(value)
    if isinstance(redacted, dict):
        cleaned: dict[str, Any] = {}
        for key, item in redacted.items():
            key_text = str(key).lower()
            if isinstance(item, str) and any(token in key_text for token in ("password", "secret", "token", "private_key")):
                cleaned[key] = REDACTION_TOKEN if item else ""
            elif isinstance(item, str) and key_text in {"message", "safe_detail", "error_message"} and any(
                token in item.lower()
                for token in ("password=", "password ", "passwd=", "pwd=", "secret=", "token=", "api_key=", "authorization:")
            ):
                cleaned[key] = REDACTION_TOKEN
            else:
                cleaned[key] = _redact_windows(item)
        return cleaned
    if isinstance(redacted, list):
        return [_redact_windows(item) for item in redacted]
    return redacted


def utc_now_seconds() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
