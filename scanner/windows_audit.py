"""Windows SMB/WinRM audit foundation checks."""

from __future__ import annotations

import importlib
import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

from scanner.credentialed_result import (
    CredentialedAuditResult,
    CredentialedCheckResult,
    build_error,
)
from scanner.evidence import build_evidence, evidence_summary, redact_nested
from scanner.finding import Finding, create_finding, finding_to_dict
from scanner.windows_policy_audit import (
    EMPTY_WINDOWS_POLICY_STATUS,
    NET_ACCOUNTS_COMMAND,
    SOURCE as POLICY_SOURCE,
    build_windows_policy_findings,
    parse_net_accounts_output,
)
from scanner.windows_registry_audit import (
    DEFAULT_WINDOWS_REGISTRY_TEMPLATE,
    SOURCE as REGISTRY_SOURCE,
    WindowsRegistryTemplateError,
    build_registry_findings,
    build_registry_query_command,
    empty_registry_audit,
    evaluate_registry_audit,
    load_registry_template,
)


SOURCE = "windows_audit"
SECURITY_SOURCE = "windows_security_audit"
MODULE_NAME = "Windows WinRM Authentication Check"
FOUNDATION_MODULE_NAME = "Windows SMB/WinRM Audit Foundation"
PROFILE = "foundation"
ALLOWED_AUTH_METHODS = {"none", "smb", "winrm"}
DEFAULT_TIMEOUT_SECONDS = 2.0
DEFAULT_WINDOWS_TIMEOUT_SECONDS = 10.0
DEFAULT_WINDOWS_COMMAND_TIMEOUT_SECONDS = 15.0
DEFAULT_WINDOWS_AUDIT_TIMEOUT_SECONDS = 120.0
SAFE_WINRM_VALIDATION_COMMAND = "hostname"
WINDOWS_HOST_INFO_COMMANDS = {
    "hostname": "hostname",
    "current_identity": "whoami",
    "powershell_version": "$PSVersionTable.PSVersion.ToString()",
    "os_information": (
        "Get-CimInstance Win32_OperatingSystem | "
        "Select-Object Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime, InstallDate | "
        "ConvertTo-Json -Compress"
    ),
    "computer_system": (
        "Get-CimInstance Win32_ComputerSystem | "
        "Select-Object Domain, Workgroup, PartOfDomain, Manufacturer, Model | "
        "ConvertTo-Json -Compress"
    ),
    "timezone": "Get-TimeZone | Select-Object Id, DisplayName | ConvertTo-Json -Compress",
}
WINDOWS_SECURITY_STATUS_COMMANDS = {
    "firewall_profiles": (
        "Get-NetFirewallProfile | "
        "Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | "
        "ConvertTo-Json -Compress"
    ),
    "defender_service": "Get-Service WinDefend | Select-Object Name, Status, StartType | ConvertTo-Json -Compress",
    "defender_status": (
        "Get-MpComputerStatus | "
        "Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled, "
        "BehaviorMonitorEnabled, IoavProtectionEnabled, NISEnabled, AntivirusSignatureLastUpdated, "
        "AntispywareSignatureLastUpdated | ConvertTo-Json -Compress"
    ),
}
EMPTY_WINDOWS_HOST_INFO = {
    "hostname": "",
    "current_identity": "",
    "powershell_version": "",
    "os_caption": "",
    "os_version": "",
    "os_build": "",
    "os_architecture": "",
    "last_boot_time": "",
    "install_date": "",
    "domain": "",
    "workgroup": "",
    "part_of_domain": "",
    "manufacturer": "",
    "model": "",
    "timezone_id": "",
    "timezone_display_name": "",
}
EMPTY_WINDOWS_SECURITY_STATUS = {
    "firewall_profiles": [],
    "defender_service": {"status": "", "start_type": ""},
    "defender_status": {
        "am_service_enabled": "",
        "antispyware_enabled": "",
        "antivirus_enabled": "",
        "real_time_protection_enabled": "",
        "behavior_monitor_enabled": "",
        "ioav_protection_enabled": "",
        "nis_enabled": "",
        "antivirus_signature_last_updated": "",
        "antispyware_signature_last_updated": "",
    },
    "security_status_limitations": [],
}

ERROR_INVALID_AUTH_METHOD = "WINDOWS_AUTH_METHOD_INVALID"
ERROR_PASSWORD_WITHOUT_USERNAME = "WINDOWS_PASSWORD_WITHOUT_USERNAME"
ERROR_WINRM_CREDENTIALS_MISSING = "WINRM_CREDENTIALS_MISSING"
ERROR_WINDOWS_HOST_INFO_PREREQUISITES = "WINDOWS_HOST_INFO_PREREQUISITES_MISSING"
ERROR_WINDOWS_SECURITY_STATUS_PREREQUISITES = "WINDOWS_SECURITY_STATUS_PREREQUISITES_MISSING"
ERROR_WINDOWS_POLICY_STATUS_PREREQUISITES = "WINDOWS_POLICY_STATUS_PREREQUISITES_MISSING"
ERROR_WINDOWS_REGISTRY_AUDIT_PREREQUISITES = "WINDOWS_REGISTRY_AUDIT_PREREQUISITES_MISSING"
ERROR_WINDOWS_REGISTRY_TEMPLATE_WITHOUT_AUDIT = "WINDOWS_REGISTRY_TEMPLATE_WITHOUT_AUDIT"
ERROR_SERVICE_CHECK_FAILED = "WINDOWS_AUDIT_SERVICE_CHECK_FAILED"
ERROR_WINDOWS_HOST_INFO_FAILED = "WINDOWS_HOST_INFO_FAILED"
ERROR_WINDOWS_HOST_INFO_TIMEOUT = "WINDOWS_HOST_INFO_TIMEOUT"
ERROR_WINDOWS_SECURITY_STATUS_FAILED = "WINDOWS_SECURITY_STATUS_FAILED"
ERROR_WINDOWS_SECURITY_STATUS_TIMEOUT = "WINDOWS_SECURITY_STATUS_TIMEOUT"
ERROR_WINDOWS_POLICY_STATUS_FAILED = "WINDOWS_POLICY_STATUS_FAILED"
ERROR_WINDOWS_POLICY_STATUS_TIMEOUT = "WINDOWS_POLICY_STATUS_TIMEOUT"
ERROR_WINDOWS_REGISTRY_AUDIT_FAILED = "WINDOWS_REGISTRY_AUDIT_FAILED"
ERROR_WINDOWS_REGISTRY_AUDIT_TIMEOUT = "WINDOWS_REGISTRY_AUDIT_TIMEOUT"
ERROR_WINDOWS_TIMEOUT_INVALID = "WINDOWS_TIMEOUT_INVALID"
ERROR_WINDOWS_COMMAND_TIMEOUT_INVALID = "WINDOWS_COMMAND_TIMEOUT_INVALID"
ERROR_WINDOWS_AUDIT_TIMEOUT_INVALID = "WINDOWS_AUDIT_TIMEOUT_INVALID"
WINDOWS_COMMAND_TIMEOUT = "WINDOWS_COMMAND_TIMEOUT"
WINDOWS_COMMAND_FAILED = "WINDOWS_COMMAND_FAILED"
WINDOWS_COMMAND_UNAVAILABLE = "WINDOWS_COMMAND_UNAVAILABLE"
WINDOWS_WINRM_TIMEOUT = "WINDOWS_WINRM_TIMEOUT"
WINDOWS_WINRM_CONNECTION_FAILED = "WINDOWS_WINRM_CONNECTION_FAILED"
WINDOWS_AUTH_FAILED = "WINDOWS_AUTH_FAILED"
WINDOWS_AUDIT_TIME_BUDGET_EXCEEDED = "WINDOWS_AUDIT_TIME_BUDGET_EXCEEDED"
WINDOWS_UNKNOWN_ERROR = "WINDOWS_UNKNOWN_ERROR"
WINRM_AUTH_SUCCESS = "WINRM_AUTH_SUCCESS"
WINRM_AUTH_FAILED = "WINRM_AUTH_FAILED"
WINRM_NOT_REACHABLE = "WINRM_NOT_REACHABLE"
WINRM_TIMEOUT = "WINRM_TIMEOUT"
WINRM_DEPENDENCY_MISSING = "WINRM_DEPENDENCY_MISSING"
WINRM_CONNECTION_FAILED = "WINRM_CONNECTION_FAILED"
WINRM_UNKNOWN_ERROR = "WINRM_UNKNOWN_ERROR"

WINDOWS_SERVICE_CHECKS = (
    {
        "port": 445,
        "service": "SMB",
        "key": "smb_reachable",
        "recommendation": "Ensure SMB is required and restricted to trusted networks.",
        "limitation": "SMB reachability does not confirm a vulnerability or successful authentication.",
    },
    {
        "port": 139,
        "service": "NetBIOS/SMB",
        "key": "netbios_smb_reachable",
        "recommendation": "Disable legacy NetBIOS/SMB exposure where it is not required.",
        "limitation": "NetBIOS/SMB reachability does not confirm a vulnerability or successful authentication.",
    },
    {
        "port": 5985,
        "service": "WinRM HTTP",
        "key": "winrm_http_reachable",
        "recommendation": "Ensure WinRM is required, restricted to trusted networks, and configured securely.",
        "limitation": "Reachability does not confirm insecure WinRM configuration.",
    },
    {
        "port": 5986,
        "service": "WinRM HTTPS",
        "key": "winrm_https_reachable",
        "recommendation": "Validate the WinRM HTTPS certificate and restrict access to trusted networks.",
        "limitation": "Reachability does not confirm insecure WinRM configuration.",
    },
    {
        "port": 3389,
        "service": "RDP",
        "key": "rdp_reachable",
        "recommendation": "Restrict RDP using firewall rules, VPN, or trusted IPs.",
        "limitation": "Open RDP does not confirm weak authentication or a vulnerability.",
    },
)


class WindowsAuditConfigurationError(ValueError):
    """Raised when Windows audit options are invalid."""

    def __init__(self, message: str, error_code: str) -> None:
        super().__init__(message)
        self.error_code = error_code


class WindowsCommandError(RuntimeError):
    """Raised internally for normalised Windows command failures."""

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code


class WindowsAuditBudget:
    """Track the overall Windows audit time budget."""

    def __init__(self, timeout_seconds: float) -> None:
        self.timeout_seconds = float(timeout_seconds)
        self.started = perf_counter()
        self.exceeded = False

    def elapsed(self) -> float:
        return perf_counter() - self.started

    def remaining(self) -> float:
        return max(0.0, self.timeout_seconds - self.elapsed())

    def has_time(self) -> bool:
        if self.remaining() <= 0:
            self.exceeded = True
            return False
        return True


def validate_windows_audit_options(
    *,
    windows_audit: bool,
    windows_user: str | None,
    windows_password: str | None,
    windows_auth_method: str,
    windows_host_info: bool = False,
    windows_security_status: bool = False,
    windows_policy_status: bool = False,
    windows_registry_audit: bool = False,
    windows_registry_template: str | Path | None = None,
    windows_timeout: float = DEFAULT_WINDOWS_TIMEOUT_SECONDS,
    windows_command_timeout: float = DEFAULT_WINDOWS_COMMAND_TIMEOUT_SECONDS,
    windows_audit_timeout: float = DEFAULT_WINDOWS_AUDIT_TIMEOUT_SECONDS,
) -> str:
    """Validate Windows audit options without exposing credential values."""
    normalized_method = (windows_auth_method or "none").strip().lower()
    if normalized_method not in ALLOWED_AUTH_METHODS:
        allowed = ", ".join(sorted(ALLOWED_AUTH_METHODS))
        raise WindowsAuditConfigurationError(
            f"Unsupported Windows auth method '{windows_auth_method}'. Allowed values: {allowed}.",
            ERROR_INVALID_AUTH_METHOD,
        )
    _validate_timeout_value(
        value=windows_timeout,
        option_name="--windows-timeout",
        maximum=60,
        error_code=ERROR_WINDOWS_TIMEOUT_INVALID,
    )
    _validate_timeout_value(
        value=windows_command_timeout,
        option_name="--windows-command-timeout",
        maximum=180,
        error_code=ERROR_WINDOWS_COMMAND_TIMEOUT_INVALID,
    )
    _validate_timeout_value(
        value=windows_audit_timeout,
        option_name="--windows-audit-timeout",
        maximum=900,
        error_code=ERROR_WINDOWS_AUDIT_TIMEOUT_INVALID,
    )
    if not windows_audit:
        if windows_host_info:
            raise WindowsAuditConfigurationError(
                "--windows-host-info requires --windows-audit.",
                ERROR_WINDOWS_HOST_INFO_PREREQUISITES,
            )
        if windows_security_status:
            raise WindowsAuditConfigurationError(
                "--windows-security-status requires --windows-audit.",
                ERROR_WINDOWS_SECURITY_STATUS_PREREQUISITES,
            )
        if windows_policy_status:
            raise WindowsAuditConfigurationError(
                "--windows-policy-status requires --windows-audit.",
                ERROR_WINDOWS_POLICY_STATUS_PREREQUISITES,
            )
        if windows_registry_audit:
            raise WindowsAuditConfigurationError(
                "--windows-registry-audit requires --windows-audit.",
                ERROR_WINDOWS_REGISTRY_AUDIT_PREREQUISITES,
            )
        if windows_registry_template:
            raise WindowsAuditConfigurationError(
                "--windows-registry-template applies only when --windows-registry-audit is enabled.",
                ERROR_WINDOWS_REGISTRY_TEMPLATE_WITHOUT_AUDIT,
            )
        return normalized_method
    if windows_password and not (windows_user and windows_user.strip()):
        raise WindowsAuditConfigurationError(
            "Windows password was provided without --windows-user.",
            ERROR_PASSWORD_WITHOUT_USERNAME,
        )
    if normalized_method == "winrm" and (
        not (windows_user and windows_user.strip()) or not windows_password
    ):
        raise WindowsAuditConfigurationError(
            "--windows-auth-method winrm requires both --windows-user and --windows-password.",
            ERROR_WINRM_CREDENTIALS_MISSING,
        )
    if windows_host_info and normalized_method != "winrm":
        raise WindowsAuditConfigurationError(
            "--windows-host-info requires --windows-auth-method winrm.",
            ERROR_WINDOWS_HOST_INFO_PREREQUISITES,
        )
    if windows_security_status and normalized_method != "winrm":
        raise WindowsAuditConfigurationError(
            "--windows-security-status requires --windows-auth-method winrm.",
            ERROR_WINDOWS_SECURITY_STATUS_PREREQUISITES,
        )
    if windows_policy_status and normalized_method != "winrm":
        raise WindowsAuditConfigurationError(
            "--windows-policy-status requires --windows-auth-method winrm.",
            ERROR_WINDOWS_POLICY_STATUS_PREREQUISITES,
        )
    if windows_registry_audit and normalized_method != "winrm":
        raise WindowsAuditConfigurationError(
            "--windows-registry-audit requires --windows-auth-method winrm.",
            ERROR_WINDOWS_REGISTRY_AUDIT_PREREQUISITES,
        )
    if windows_registry_template and not windows_registry_audit:
        raise WindowsAuditConfigurationError(
            "--windows-registry-template applies only when --windows-registry-audit is enabled.",
            ERROR_WINDOWS_REGISTRY_TEMPLATE_WITHOUT_AUDIT,
        )
    if windows_registry_audit:
        effective_template = Path(windows_registry_template or DEFAULT_WINDOWS_REGISTRY_TEMPLATE)
        if not effective_template.exists():
            raise WindowsAuditConfigurationError(
                f"Windows registry template was not found: {effective_template}",
                "WINDOWS_REGISTRY_TEMPLATE_NOT_FOUND",
            )
    return normalized_method


def _validate_timeout_value(*, value: float, option_name: str, maximum: float, error_code: str) -> None:
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise WindowsAuditConfigurationError(
            f"{option_name} must be a number greater than 0 and no more than {maximum:g}.",
            error_code,
        ) from exc
    if numeric <= 0 or numeric > maximum:
        raise WindowsAuditConfigurationError(
            f"{option_name} must be greater than 0 and no more than {maximum:g}.",
            error_code,
        )


def audit_windows_host(
    *,
    target: str,
    resolved_ip: str,
    username: str | None = None,
    password: str | None = None,
    domain: str | None = None,
    auth_method: str = "none",
    collect_host_info: bool = False,
    collect_security_status: bool = False,
    collect_policy_status: bool = False,
    collect_registry_audit: bool = False,
    registry_template_path: str | Path | None = None,
    timeout: float = DEFAULT_WINDOWS_TIMEOUT_SECONDS,
    command_timeout: float = DEFAULT_WINDOWS_COMMAND_TIMEOUT_SECONDS,
    audit_timeout: float = DEFAULT_WINDOWS_AUDIT_TIMEOUT_SECONDS,
    progress_callback: Any | None = None,
) -> dict[str, Any]:
    """Run safe Windows service reachability checks and optional single WinRM auth validation."""
    started = perf_counter()
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    normalized_method = validate_windows_audit_options(
        windows_audit=True,
        windows_user=username,
        windows_password=password,
        windows_auth_method=auth_method,
        windows_host_info=collect_host_info,
        windows_security_status=collect_security_status,
        windows_policy_status=collect_policy_status,
        windows_registry_audit=collect_registry_audit,
        windows_registry_template=registry_template_path,
        windows_timeout=timeout,
        windows_command_timeout=command_timeout,
        windows_audit_timeout=audit_timeout,
    )
    budget = WindowsAuditBudget(audit_timeout)
    _windows_progress(progress_callback, "Checking SMB, WinRM, and RDP reachability...")

    service_statuses = [
        _check_service(resolved_ip, check, timeout=timeout) for check in WINDOWS_SERVICE_CHECKS
    ]
    winrm_auth = _initial_winrm_auth_result()
    if normalized_method == "winrm":
        _windows_progress(progress_callback, "Connecting to WinRM...")
        winrm_auth = _perform_winrm_auth_check(
            target=target,
            username=str(username or ""),
            password=str(password or ""),
            domain=domain,
            service_statuses=service_statuses,
            collect_host_info=collect_host_info,
            collect_security_status=collect_security_status,
            collect_policy_status=collect_policy_status,
            collect_registry_audit=collect_registry_audit,
            registry_template_path=registry_template_path,
            timeout=timeout,
            command_timeout=command_timeout,
            budget=budget,
            progress_callback=progress_callback,
        )
        if winrm_auth.get("authenticated"):
            _windows_progress(progress_callback, "WinRM authentication succeeded.")
    findings = _build_windows_findings(target, service_statuses)
    if normalized_method == "winrm":
        findings.append(_winrm_auth_finding(target, winrm_auth))
    if collect_host_info:
        findings.extend(_host_info_findings(target, winrm_auth))
    if collect_security_status:
        findings.extend(_security_status_findings(target, winrm_auth))
    if collect_policy_status and winrm_auth.get("authenticated"):
        findings.extend(build_windows_policy_findings(target, winrm_auth.get("policy_status") or {}))
    if collect_registry_audit and winrm_auth.get("authenticated"):
        findings.extend(build_registry_findings(target, winrm_auth.get("registry_audit") or {}))
    findings.append(_completed_finding(target, service_statuses, winrm_auth, normalized_method))
    if _has_partial_windows_results(winrm_auth):
        findings.append(_partial_results_finding(target, winrm_auth))
    checks_failed = sum(1 for status in service_statuses if status.get("error_code"))
    if winrm_auth["attempted"] and winrm_auth["status"] != "authenticated":
        checks_failed += 1
    if collect_host_info and winrm_auth.get("host_info_status") == "failed":
        checks_failed += 1
    if collect_security_status and winrm_auth.get("security_status_status") in {"failed", "partial"}:
        checks_failed += 1
    if collect_policy_status and winrm_auth.get("policy_status_status") in {"failed", "partial"}:
        checks_failed += 1
    if collect_registry_audit and winrm_auth.get("registry_audit_status") in {"failed", "partial"}:
        checks_failed += 1
    status = (
        "partial"
        if (
            winrm_auth.get("authenticated")
            and (
                (collect_host_info and winrm_auth.get("host_info_status") == "failed")
                or (collect_security_status and winrm_auth.get("security_status_status") in {"failed", "partial"})
                or (collect_policy_status and winrm_auth.get("policy_status_status") in {"failed", "partial"})
                or (collect_registry_audit and winrm_auth.get("registry_audit_status") in {"failed", "partial"})
                or (collect_host_info and winrm_auth.get("host_info_status") == "skipped")
                or (collect_security_status and winrm_auth.get("security_status_status") == "skipped")
                or (collect_policy_status and winrm_auth.get("policy_status_status") == "skipped")
                or (collect_registry_audit and winrm_auth.get("registry_audit_status") == "skipped")
            )
        )
        else _audit_status(checks_failed=checks_failed)
    )
    if normalized_method == "winrm" and _has_partial_windows_results(winrm_auth):
        status = "partial"
    duration = round(perf_counter() - started, 3)
    ended_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    errors = [
        error
        for error in (
            build_error(
                error_code=item.get("error_code"),
                message=str(item.get("error_message") or ""),
                source=SOURCE,
                check_name=str(item.get("service") or ""),
                safe_detail=str(item.get("safe_detail") or ""),
            )
            for item in service_statuses
        )
        if error
    ]
    if winrm_auth.get("attempted") and winrm_auth.get("status") != "authenticated":
        winrm_error = build_error(
            error_code=winrm_auth.get("error_code"),
            message=str(winrm_auth.get("message") or ""),
            source=SOURCE,
            check_name="WinRM authentication",
            severity="error",
            safe_detail=str(winrm_auth.get("safe_detail") or ""),
        )
        if winrm_error:
            errors.append(winrm_error)
    if collect_host_info and winrm_auth.get("host_info_status") == "failed":
        host_info_error = build_error(
            error_code=winrm_auth.get("host_info_error_code") or ERROR_WINDOWS_HOST_INFO_FAILED,
            message=str(winrm_auth.get("host_info_error_message") or "Windows host information collection failed."),
            source=SOURCE,
            check_name="Windows host information",
            severity="error",
            safe_detail=str(winrm_auth.get("host_info_safe_detail") or ""),
        )
        if host_info_error:
            errors.append(host_info_error)
    if collect_security_status and winrm_auth.get("security_status_status") in {"failed", "partial"}:
        security_status_error = build_error(
            error_code=winrm_auth.get("security_status_error_code") or ERROR_WINDOWS_SECURITY_STATUS_FAILED,
            message=str(
                winrm_auth.get("security_status_error_message")
                or "Windows security status collection failed."
            ),
            source=SECURITY_SOURCE,
            check_name="Windows security status",
            severity="error",
            safe_detail=str(winrm_auth.get("security_status_safe_detail") or ""),
        )
        if security_status_error:
            errors.append(security_status_error)
    if collect_policy_status and winrm_auth.get("policy_status_status") in {"failed", "partial"}:
        policy_status_error = build_error(
            error_code=winrm_auth.get("policy_status_error_code") or ERROR_WINDOWS_POLICY_STATUS_FAILED,
            message=str(
                winrm_auth.get("policy_status_error_message")
                or "Windows local security policy indicator collection failed."
            ),
            source=POLICY_SOURCE,
            check_name="Windows local security policy indicators",
            severity="error",
            safe_detail=str(winrm_auth.get("policy_status_safe_detail") or ""),
        )
        if policy_status_error:
            errors.append(policy_status_error)
    if collect_registry_audit and winrm_auth.get("registry_audit_status") in {"failed", "partial"}:
        registry_error = build_error(
            error_code=winrm_auth.get("registry_audit_error_code") or ERROR_WINDOWS_REGISTRY_AUDIT_FAILED,
            message=str(winrm_auth.get("registry_audit_error_message") or "Windows registry audit failed."),
            source=REGISTRY_SOURCE,
            check_name="Windows registry audit",
            severity="error",
            safe_detail=str(winrm_auth.get("registry_audit_safe_detail") or ""),
        )
        if registry_error:
            errors.append(registry_error)
    summary = _build_summary(
        target=target,
        username=username,
        domain=domain,
        auth_method=normalized_method,
        service_statuses=service_statuses,
        status=status,
        checks_failed=checks_failed,
        findings_count=len(findings),
        winrm_auth=winrm_auth,
        connection_timeout=timeout,
        command_timeout=command_timeout,
        audit_timeout=audit_timeout,
        total_duration=duration,
    )
    credentialed_audit = _build_credentialed_audit(
        target=target,
        username=username,
        domain=domain,
        auth_method=normalized_method,
        started_at=started_at,
        ended_at=ended_at,
        duration_seconds=duration,
        status=status,
        service_statuses=service_statuses,
        findings=findings,
        errors=errors,
        summary=summary,
    )

    _windows_progress(progress_callback, f"Windows audit completed with status: {status}.")
    return {
        "enabled": True,
        "source": SOURCE,
        "module_name": MODULE_NAME if normalized_method == "winrm" else FOUNDATION_MODULE_NAME,
        "status": status,
        "target": target,
        "authenticated": summary["winrm_authenticated"],
        "auth_method": normalized_method,
        "domain": domain or "",
        "username_used": username or "",
        "service_statuses": service_statuses,
        "checks_completed": summary["checks_completed"],
        "checks_failed": checks_failed,
        "checks_skipped": summary.get("checks_skipped") or 0,
        "findings": findings,
        "summary": summary,
        "credentialed_audit": credentialed_audit,
        "errors": errors,
        "duration_seconds": duration,
    }


def _check_service(
    resolved_ip: str,
    check: dict[str, Any],
    *,
    timeout: float,
) -> dict[str, Any]:
    port = int(check["port"])
    service = str(check["service"])
    started = perf_counter()
    try:
        with socket.create_connection((resolved_ip, port), timeout=timeout):
            duration = round(perf_counter() - started, 3)
            return {
                "port": port,
                "service": service,
                "reachable": True,
                "evidence": f"TCP connection to {port} succeeded.",
                "recommendation": check["recommendation"],
                "limitation": check["limitation"],
                "duration_seconds": duration,
                "error_code": None,
                "error_message": "",
            }
    except (ConnectionRefusedError, TimeoutError, socket.timeout, OSError) as exc:
        duration = round(perf_counter() - started, 3)
        return {
            "port": port,
            "service": service,
            "reachable": False,
            "evidence": f"TCP connection to {port} did not succeed.",
            "recommendation": check["recommendation"],
            "limitation": check["limitation"],
            "duration_seconds": duration,
            "error_code": None,
            "error_message": "",
            "safe_detail": exc.__class__.__name__,
        }


def _build_windows_findings(target: str, service_statuses: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for status in service_statuses:
        if not status.get("reachable"):
            continue
        port = int(status["port"])
        if port == 445:
            findings.append(_service_finding(target, status, "SMB Service Reachable", "Low", "Windows Service Exposure"))
        elif port == 5985:
            findings.append(_service_finding(target, status, "WinRM HTTP Reachable", "Low", "Windows Remote Management"))
        elif port == 5986:
            findings.append(_service_finding(target, status, "WinRM HTTPS Reachable", "Informational", "Windows Remote Management"))
        elif port == 3389:
            findings.append(_service_finding(target, status, "RDP Service Reachable", "Medium", "Windows Remote Access"))
    return findings


def _initial_winrm_auth_result() -> dict[str, Any]:
    return {
        "attempted": False,
        "status": "skipped",
        "error_code": "",
        "message": "",
        "endpoint_used": "",
        "transport": "",
        "authenticated": False,
        "safe_validation_command": "",
        "validation_result_summary": "",
        "limitations": "WinRM authentication was not requested.",
        "safe_detail": "",
        "duration_seconds": 0.0,
        "host_info_requested": False,
        "host_info_status": "skipped",
        "host_info_error_code": "",
        "host_info_error_message": "",
        "host_info_safe_detail": "",
        "host_info": dict(EMPTY_WINDOWS_HOST_INFO),
        "host_info_commands_completed": 0,
        "security_status_requested": False,
        "security_status_status": "skipped",
        "security_status_error_code": "",
        "security_status_error_message": "",
        "security_status_safe_detail": "",
        "security_status": dict(EMPTY_WINDOWS_SECURITY_STATUS),
        "security_status_commands_completed": 0,
        "policy_status_requested": False,
        "policy_status_status": "skipped",
        "policy_status_error_code": "",
        "policy_status_error_message": "",
        "policy_status_safe_detail": "",
        "policy_status": dict(EMPTY_WINDOWS_POLICY_STATUS),
        "policy_status_commands_completed": 0,
        "registry_audit_requested": False,
        "registry_audit_status": "skipped",
        "registry_audit_error_code": "",
        "registry_audit_error_message": "",
        "registry_audit_safe_detail": "",
        "registry_audit": empty_registry_audit(),
        "registry_audit_commands_completed": 0,
        "command_results": [],
    }


def _perform_winrm_auth_check(
    *,
    target: str,
    username: str,
    password: str,
    domain: str | None,
    service_statuses: list[dict[str, Any]],
    collect_host_info: bool,
    collect_security_status: bool,
    collect_policy_status: bool,
    collect_registry_audit: bool,
    registry_template_path: str | Path | None,
    timeout: float,
    command_timeout: float,
    budget: "WindowsAuditBudget",
    progress_callback: Any | None = None,
) -> dict[str, Any]:
    started = perf_counter()
    endpoint = _select_winrm_endpoint(target, service_statuses)
    if not endpoint:
        return _winrm_auth_result(
            started=started,
            status="not_reachable",
            error_code=WINRM_NOT_REACHABLE,
            message="WinRM authentication was requested, but ports 5985 and 5986 were not reachable.",
            limitations="WinRM may be disabled, filtered by a firewall, or intentionally unavailable.",
            host_info_requested=collect_host_info,
            security_status_requested=collect_security_status,
            policy_status_requested=collect_policy_status,
            registry_audit_requested=collect_registry_audit,
            registry_audit_template_path=registry_template_path,
        )

    try:
        winrm_module = importlib.import_module("winrm")
    except ImportError:
        return _winrm_auth_result(
            started=started,
            status="dependency_missing",
            error_code=WINRM_DEPENDENCY_MISSING,
            message="pywinrm is required for WinRM authentication checks.",
            endpoint_used=endpoint["url"],
            transport="ntlm",
            limitations="Install pywinrm in the VulScan virtual environment to enable this check.",
            host_info_requested=collect_host_info,
            security_status_requested=collect_security_status,
            policy_status_requested=collect_policy_status,
            registry_audit_requested=collect_registry_audit,
            registry_audit_template_path=registry_template_path,
        )

    endpoint_url = str(endpoint["url"])
    cert_validation = "ignore" if endpoint.get("scheme") == "https" else "validate"
    limitations = (
        "WinRM authentication validates access only with a single safe read-only command. "
        "For HTTPS lab endpoints, certificate validation may be relaxed to support self-signed certificates."
    )
    try:
        session = winrm_module.Session(
            endpoint_url,
            auth=(_winrm_username(username, domain), password),
            transport="ntlm",
            server_cert_validation=cert_validation,
            operation_timeout_sec=max(1, int(command_timeout)),
            read_timeout_sec=max(2, int(command_timeout) + 1),
        )
        command_result = execute_windows_command(
            session,
            command_name=SAFE_WINRM_VALIDATION_COMMAND,
            command_used_safe_label=SAFE_WINRM_VALIDATION_COMMAND,
            command_type="cmd",
            command=SAFE_WINRM_VALIDATION_COMMAND,
            command_timeout=command_timeout,
            budget=budget,
        )
        if not command_result["success"]:
            error_code = str(command_result.get("error_code") or WINRM_AUTH_FAILED)
            if error_code == WINDOWS_COMMAND_TIMEOUT:
                error_code = WINRM_TIMEOUT
            raise WindowsCommandError(error_code, str(command_result.get("error_message") or "WinRM authentication failed."))
    except TimeoutError as exc:
        return _winrm_auth_result(
            started=started,
            status="timeout",
            error_code=WINRM_TIMEOUT,
            message="WinRM authentication check timed out.",
            endpoint_used=endpoint_url,
            transport="ntlm",
            safe_detail=exc.__class__.__name__,
            limitations=limitations,
            host_info_requested=collect_host_info,
            security_status_requested=collect_security_status,
            policy_status_requested=collect_policy_status,
            registry_audit_requested=collect_registry_audit,
            registry_audit_template_path=registry_template_path,
        )
    except WindowsCommandError as exc:
        error_code = WINRM_TIMEOUT if exc.error_code in {WINDOWS_COMMAND_TIMEOUT, WINDOWS_AUDIT_TIME_BUDGET_EXCEEDED} else WINRM_AUTH_FAILED
        return _winrm_auth_result(
            started=started,
            status=_winrm_status_from_error_code(error_code),
            error_code=error_code,
            message=_winrm_error_message(error_code),
            endpoint_used=endpoint_url,
            transport="ntlm",
            safe_detail=exc.error_code,
            limitations=limitations,
            host_info_requested=collect_host_info,
            security_status_requested=collect_security_status,
            policy_status_requested=collect_policy_status,
            registry_audit_requested=collect_registry_audit,
            registry_audit_template_path=registry_template_path,
            command_results=[command_result] if "command_result" in locals() else [],
        )
    except Exception as exc:  # pywinrm exposes transport/auth failures through several exception classes.
        error_code = _classify_winrm_exception(exc)
        return _winrm_auth_result(
            started=started,
            status=_winrm_status_from_error_code(error_code),
            error_code=error_code,
            message=_winrm_error_message(error_code),
            endpoint_used=endpoint_url,
            transport="ntlm",
            safe_detail=exc.__class__.__name__,
            limitations=limitations,
            host_info_requested=collect_host_info,
            security_status_requested=collect_security_status,
            policy_status_requested=collect_policy_status,
            registry_audit_requested=collect_registry_audit,
            registry_audit_template_path=registry_template_path,
        )

    status_code = int(command_result.get("exit_status") if command_result.get("exit_status") is not None else 1)
    if status_code == 0:
        command_history = [command_result]
        host_info_result = (
            _run_windows_section(
                "host_information",
                collect_host_info,
                "Collecting host information...",
                progress_callback,
                command_timeout,
                budget,
                _collect_windows_host_info,
                session,
            )
            if collect_host_info
            else _initial_host_info_result(False)
        )
        if collect_host_info:
            command_history.extend(host_info_result.get("command_results") or [])
        security_status_result = (
            _run_windows_section(
                "security_status",
                collect_security_status,
                "Checking Firewall and Defender status...",
                progress_callback,
                command_timeout,
                budget,
                _collect_windows_security_status,
                session,
            )
            if collect_security_status
            else _initial_security_status_result(False)
        )
        if collect_security_status:
            command_history.extend(security_status_result.get("command_results") or [])
        policy_status_result = (
            _run_windows_section(
                "local_security_policy",
                collect_policy_status,
                "Checking local security policy indicators...",
                progress_callback,
                command_timeout,
                budget,
                _collect_windows_policy_status,
                session,
            )
            if collect_policy_status
            else _initial_policy_status_result(False)
        )
        if collect_policy_status:
            command_history.extend(policy_status_result.get("command_results") or [])
        registry_audit_result = (
            _run_windows_section(
                "registry_audit",
                collect_registry_audit,
                "Running registry audit template...",
                progress_callback,
                command_timeout,
                budget,
                _collect_windows_registry_audit,
                session,
                registry_template_path,
            )
            if collect_registry_audit
            else _initial_registry_audit_result(False, registry_template_path)
        )
        if collect_registry_audit:
            command_history.extend(registry_audit_result.get("command_results") or [])
        return _winrm_auth_result(
            started=started,
            status="authenticated",
            error_code=WINRM_AUTH_SUCCESS,
            message="WinRM authentication succeeded and a safe validation command completed.",
            endpoint_used=endpoint_url,
            transport="ntlm",
            authenticated=True,
            validation_result_summary=_safe_command_summary(command_result.get("stdout") or ""),
            limitations=limitations,
            host_info_requested=collect_host_info,
            host_info_result=host_info_result,
            security_status_requested=collect_security_status,
            security_status_result=security_status_result,
            policy_status_requested=collect_policy_status,
            policy_status_result=policy_status_result,
            registry_audit_requested=collect_registry_audit,
            registry_audit_template_path=registry_template_path,
            registry_audit_result=registry_audit_result,
            command_results=command_history,
        )

    return _winrm_auth_result(
        started=started,
        status="auth_failed",
        error_code=WINRM_AUTH_FAILED,
        message="WinRM authentication attempt failed.",
        endpoint_used=endpoint_url,
        transport="ntlm",
        safe_detail=f"status_code={status_code}",
        limitations=limitations,
        host_info_requested=collect_host_info,
        security_status_requested=collect_security_status,
        policy_status_requested=collect_policy_status,
        registry_audit_requested=collect_registry_audit,
        registry_audit_template_path=registry_template_path,
    )


def _select_winrm_endpoint(target: str, service_statuses: list[dict[str, Any]]) -> dict[str, str] | None:
    service_by_port = {int(item["port"]): item for item in service_statuses}
    if service_by_port.get(5986, {}).get("reachable"):
        return {"scheme": "https", "url": f"https://{target}:5986/wsman"}
    if service_by_port.get(5985, {}).get("reachable"):
        return {"scheme": "http", "url": f"http://{target}:5985/wsman"}
    return None


def _run_windows_section(
    section_name: str,
    requested: bool,
    progress_message: str,
    progress_callback: Any | None,
    command_timeout: float,
    budget: WindowsAuditBudget,
    collector: Any,
    *collector_args: Any,
) -> dict[str, Any]:
    if not requested:
        return {"requested": False, "status": "skipped", "commands_completed": 0}
    if not budget.has_time():
        return _section_budget_skipped(section_name)
    _windows_progress(progress_callback, progress_message)
    result = collector(*collector_args, command_timeout=command_timeout, budget=budget)
    if budget.exceeded and result.get("status") not in {"failed", "partial"}:
        result["status"] = "partial"
        result["error_code"] = WINDOWS_AUDIT_TIME_BUDGET_EXCEEDED
        result["error_message"] = "Windows audit time budget was exceeded."
    return result


def _section_budget_skipped(section_name: str) -> dict[str, Any]:
    return {
        "requested": True,
        "status": "skipped",
        "error_code": WINDOWS_AUDIT_TIME_BUDGET_EXCEEDED,
        "error_message": "Windows audit time budget was exceeded before this section could run.",
        "safe_detail": section_name,
        "commands_completed": 0,
        "command_results": [],
    }


def _winrm_username(username: str, domain: str | None) -> str:
    if domain and "\\" not in username and "@" not in username:
        return f"{domain}\\{username}"
    return username


def _safe_command_summary(value: Any) -> str:
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value or "")
    return " ".join(text.split())[:120]


def execute_windows_command(
    session: Any,
    *,
    command_name: str,
    command_used_safe_label: str,
    command_type: str,
    command: str,
    command_timeout: float = DEFAULT_WINDOWS_COMMAND_TIMEOUT_SECONDS,
    budget: WindowsAuditBudget | None = None,
) -> dict[str, Any]:
    """Run one safe WinRM command and return normalised timing/error metadata."""
    started = perf_counter()
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if budget is not None and not budget.has_time():
        ended_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return {
            "command_name": command_name,
            "command_used_safe_label": command_used_safe_label,
            "success": False,
            "stdout": "",
            "stderr": "",
            "exit_status": None,
            "error_code": WINDOWS_AUDIT_TIME_BUDGET_EXCEEDED,
            "error_message": "Windows audit time budget was exceeded before command execution.",
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_seconds": 0.0,
            "timed_out": False,
        }
    try:
        if command_type == "ps":
            response = session.run_ps(command)
        elif command == NET_ACCOUNTS_COMMAND:
            try:
                response = session.run_cmd("net", ["accounts"])
            except TypeError:
                response = session.run_cmd(command)
        else:
            response = session.run_cmd(command)
        status_code = int(getattr(response, "status_code", 1) or 0)
        stdout = _safe_multiline_output_text(getattr(response, "std_out", b""))
        stderr = _safe_multiline_output_text(getattr(response, "std_err", b""))
        duration = round(perf_counter() - started, 3)
        timed_out = duration > float(command_timeout)
        success = status_code == 0 and not timed_out
        error_code = ""
        error_message = ""
        if timed_out:
            error_code = WINDOWS_COMMAND_TIMEOUT
            error_message = "Windows command exceeded the configured command timeout."
        elif status_code != 0:
            error_code = WINDOWS_COMMAND_FAILED
            error_message = "Windows command returned a non-zero status."
        return {
            "command_name": command_name,
            "command_used_safe_label": command_used_safe_label,
            "success": success,
            "stdout": stdout,
            "stderr": stderr,
            "exit_status": status_code,
            "error_code": error_code,
            "error_message": error_message,
            "started_at": started_at,
            "ended_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_seconds": duration,
            "timed_out": timed_out,
        }
    except TimeoutError:
        duration = round(perf_counter() - started, 3)
        return {
            "command_name": command_name,
            "command_used_safe_label": command_used_safe_label,
            "success": False,
            "stdout": "",
            "stderr": "",
            "exit_status": None,
            "error_code": WINDOWS_COMMAND_TIMEOUT,
            "error_message": "Windows command timed out.",
            "started_at": started_at,
            "ended_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_seconds": duration,
            "timed_out": True,
        }
    except Exception as exc:
        duration = round(perf_counter() - started, 3)
        return {
            "command_name": command_name,
            "command_used_safe_label": command_used_safe_label,
            "success": False,
            "stdout": "",
            "stderr": "",
            "exit_status": None,
            "error_code": _normalise_command_exception(exc),
            "error_message": "Windows command could not be completed.",
            "started_at": started_at,
            "ended_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_seconds": duration,
            "timed_out": False,
        }


def _collect_windows_host_info(
    session: Any,
    *,
    command_timeout: float = DEFAULT_WINDOWS_COMMAND_TIMEOUT_SECONDS,
    budget: WindowsAuditBudget | None = None,
) -> dict[str, Any]:
    completed = 0
    command_results: list[dict[str, Any]] = []
    try:
        hostname = _run_safe_ps(session, WINDOWS_HOST_INFO_COMMANDS["hostname"], "hostname", command_timeout, budget, command_results)
        completed += 1
        current_identity = _run_safe_ps(session, WINDOWS_HOST_INFO_COMMANDS["current_identity"], "whoami", command_timeout, budget, command_results)
        completed += 1
        powershell_version = _run_safe_ps(session, WINDOWS_HOST_INFO_COMMANDS["powershell_version"], "PowerShell version", command_timeout, budget, command_results)
        completed += 1
        os_data = _json_object(_run_safe_ps(session, WINDOWS_HOST_INFO_COMMANDS["os_information"], "Win32_OperatingSystem", command_timeout, budget, command_results))
        completed += 1
        computer_data = _json_object(_run_safe_ps(session, WINDOWS_HOST_INFO_COMMANDS["computer_system"], "Win32_ComputerSystem", command_timeout, budget, command_results))
        completed += 1
        timezone_data = _json_object(_run_safe_ps(session, WINDOWS_HOST_INFO_COMMANDS["timezone"], "Get-TimeZone", command_timeout, budget, command_results))
        completed += 1
    except TimeoutError as exc:
        result = _initial_host_info_result(True)
        result.update(
            {
                "status": "failed",
                "error_code": ERROR_WINDOWS_HOST_INFO_TIMEOUT,
                "error_message": "Windows host information collection timed out.",
                "safe_detail": exc.__class__.__name__,
                "commands_completed": completed,
                "command_results": command_results,
            }
        )
        return result
    except Exception as exc:
        error_code = ERROR_WINDOWS_HOST_INFO_TIMEOUT if isinstance(exc, WindowsCommandError) and exc.error_code == WINDOWS_COMMAND_TIMEOUT else ERROR_WINDOWS_HOST_INFO_FAILED
        result = _initial_host_info_result(True)
        result.update(
            {
                "status": "failed",
                "error_code": error_code,
                "error_message": "Windows host information collection failed.",
                "safe_detail": exc.__class__.__name__,
                "commands_completed": completed,
                "command_results": command_results,
            }
        )
        return result

    host_info = _build_host_info(
        hostname=hostname,
        current_identity=current_identity,
        powershell_version=powershell_version,
        os_data=os_data,
        computer_data=computer_data,
        timezone_data=timezone_data,
    )
    status = "collected" if any(host_info.values()) else "failed"
    result = _initial_host_info_result(True)
    result.update(
        {
            "status": status,
            "host_info": host_info,
            "commands_completed": completed,
            "error_code": "" if status == "collected" else ERROR_WINDOWS_HOST_INFO_FAILED,
            "error_message": "" if status == "collected" else "Windows host information returned incomplete data.",
            "command_results": command_results,
        }
    )
    return result


def _run_safe_ps(
    session: Any,
    command: str,
    command_name: str = "PowerShell command",
    command_timeout: float = DEFAULT_WINDOWS_COMMAND_TIMEOUT_SECONDS,
    budget: WindowsAuditBudget | None = None,
    command_results: list[dict[str, Any]] | None = None,
) -> str:
    result = execute_windows_command(
        session,
        command_name=command_name,
        command_used_safe_label=command_name,
        command_type="ps",
        command=command,
        command_timeout=command_timeout,
        budget=budget,
    )
    if command_results is not None:
        command_results.append(result)
    if not result["success"]:
        raise WindowsCommandError(str(result.get("error_code") or WINDOWS_COMMAND_FAILED), str(result.get("error_message") or "Command failed."))
    return str(result.get("stdout") or "")


def _safe_output_text(value: Any) -> str:
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value or "")
    return " ".join(text.split())


def _json_object(value: str) -> dict[str, Any]:
    parsed = _json_value(value)
    if isinstance(parsed, list):
        first = parsed[0] if parsed else {}
        return first if isinstance(first, dict) else {}
    return parsed if isinstance(parsed, dict) else {}


def _json_value(value: str) -> Any:
    if not value:
        return {}
    return json.loads(value)


def _build_host_info(
    *,
    hostname: str,
    current_identity: str,
    powershell_version: str,
    os_data: dict[str, Any],
    computer_data: dict[str, Any],
    timezone_data: dict[str, Any],
) -> dict[str, str]:
    return {
        "hostname": _short_value(hostname),
        "current_identity": _short_value(current_identity),
        "powershell_version": _short_value(powershell_version),
        "os_caption": _short_value(os_data.get("Caption")),
        "os_version": _short_value(os_data.get("Version")),
        "os_build": _short_value(os_data.get("BuildNumber")),
        "os_architecture": _short_value(os_data.get("OSArchitecture")),
        "last_boot_time": _short_value(os_data.get("LastBootUpTime")),
        "install_date": _short_value(os_data.get("InstallDate")),
        "domain": _short_value(computer_data.get("Domain")),
        "workgroup": _short_value(computer_data.get("Workgroup")),
        "part_of_domain": _short_value(computer_data.get("PartOfDomain")),
        "manufacturer": _short_value(computer_data.get("Manufacturer")),
        "model": _short_value(computer_data.get("Model")),
        "timezone_id": _short_value(timezone_data.get("Id")),
        "timezone_display_name": _short_value(timezone_data.get("DisplayName")),
    }


def _short_value(value: Any, limit: int = 160) -> str:
    if value is None:
        return ""
    return " ".join(str(value).split())[:limit]


def _initial_host_info_result(requested: bool) -> dict[str, Any]:
    return {
        "requested": requested,
        "status": "skipped",
        "error_code": "",
        "error_message": "",
        "safe_detail": "",
        "host_info": dict(EMPTY_WINDOWS_HOST_INFO),
        "commands_completed": 0,
    }


def _collect_windows_security_status(
    session: Any,
    *,
    command_timeout: float = DEFAULT_WINDOWS_COMMAND_TIMEOUT_SECONDS,
    budget: WindowsAuditBudget | None = None,
) -> dict[str, Any]:
    completed = 0
    command_results: list[dict[str, Any]] = []
    limitations: list[str] = []
    firewall_profiles: list[dict[str, str]] = []
    defender_service: dict[str, str] = {"status": "", "start_type": ""}
    defender_status = dict(EMPTY_WINDOWS_SECURITY_STATUS["defender_status"])

    try:
        firewall_profiles = _firewall_profiles_from_output(
            _run_safe_ps(session, WINDOWS_SECURITY_STATUS_COMMANDS["firewall_profiles"], "Get-NetFirewallProfile", command_timeout, budget, command_results)
        )
        completed += 1
    except TimeoutError as exc:
        return _security_status_error(ERROR_WINDOWS_SECURITY_STATUS_TIMEOUT, exc, completed)
    except Exception as exc:
        limitations.append(f"Firewall profile status unavailable: {exc.__class__.__name__}.")

    try:
        defender_service = _defender_service_from_output(
            _run_safe_ps(session, WINDOWS_SECURITY_STATUS_COMMANDS["defender_service"], "Get-Service WinDefend", command_timeout, budget, command_results)
        )
        completed += 1
    except TimeoutError as exc:
        return _security_status_error(ERROR_WINDOWS_SECURITY_STATUS_TIMEOUT, exc, completed)
    except Exception as exc:
        limitations.append(f"Defender service status unavailable: {exc.__class__.__name__}.")

    try:
        defender_status = _defender_status_from_output(
            _run_safe_ps(session, WINDOWS_SECURITY_STATUS_COMMANDS["defender_status"], "Get-MpComputerStatus", command_timeout, budget, command_results)
        )
        completed += 1
    except TimeoutError as exc:
        return _security_status_error(ERROR_WINDOWS_SECURITY_STATUS_TIMEOUT, exc, completed)
    except Exception as exc:
        limitations.append(f"Defender computer status unavailable: {exc.__class__.__name__}.")

    security_status = {
        "firewall_profiles": firewall_profiles,
        "defender_service": defender_service,
        "defender_status": defender_status,
        "security_status_limitations": limitations,
    }
    has_data = bool(firewall_profiles or any(defender_service.values()) or any(defender_status.values()))
    if has_data and limitations:
        status = "partial"
    elif has_data:
        status = "checked"
    else:
        status = "failed"
    result = _initial_security_status_result(True)
    result.update(
        {
            "status": status,
            "security_status": security_status,
            "commands_completed": completed,
            "error_code": "" if status == "checked" else ERROR_WINDOWS_SECURITY_STATUS_FAILED,
            "error_message": ""
            if status == "checked"
            else "One or more Windows security status commands failed or returned incomplete data.",
            "safe_detail": "; ".join(limitations),
            "command_results": command_results,
        }
    )
    return result


def _security_status_error(error_code: str, exc: Exception, commands_completed: int) -> dict[str, Any]:
    result = _initial_security_status_result(True)
    result.update(
        {
            "status": "failed",
            "error_code": error_code,
            "error_message": "Windows security status collection failed.",
            "safe_detail": exc.__class__.__name__,
            "commands_completed": commands_completed,
        }
    )
    return result


def _initial_security_status_result(requested: bool) -> dict[str, Any]:
    return {
        "requested": requested,
        "status": "skipped",
        "error_code": "",
        "error_message": "",
        "safe_detail": "",
        "security_status": dict(EMPTY_WINDOWS_SECURITY_STATUS),
        "commands_completed": 0,
    }


def _collect_windows_policy_status(
    session: Any,
    *,
    command_timeout: float = DEFAULT_WINDOWS_COMMAND_TIMEOUT_SECONDS,
    budget: WindowsAuditBudget | None = None,
) -> dict[str, Any]:
    completed = 0
    command_results: list[dict[str, Any]] = []
    try:
        output = _run_safe_cmd(session, NET_ACCOUNTS_COMMAND, NET_ACCOUNTS_COMMAND, command_timeout, budget, command_results)
        completed += 1
    except TimeoutError as exc:
        result = _policy_status_error(ERROR_WINDOWS_POLICY_STATUS_TIMEOUT, exc, completed)
        result["command_results"] = command_results
        return result
    except Exception as exc:
        error_code = ERROR_WINDOWS_POLICY_STATUS_TIMEOUT if isinstance(exc, WindowsCommandError) and exc.error_code == WINDOWS_COMMAND_TIMEOUT else ERROR_WINDOWS_POLICY_STATUS_FAILED
        result = _policy_status_error(error_code, exc, completed)
        result["command_results"] = command_results
        return result

    policy_status = parse_net_accounts_output(output)
    has_core_data = any(
        policy_status.get(key) is not None
        for key in (
            "minimum_password_length",
            "maximum_password_age_days",
            "password_history_length",
            "lockout_threshold",
        )
    )
    has_incomplete_values = any(
        policy_status.get(key) is None
        for key in (
            "minimum_password_age_days",
            "maximum_password_age_days",
            "minimum_password_length",
            "password_history_length",
            "lockout_threshold",
            "lockout_duration_minutes",
            "lockout_observation_window_minutes",
        )
    )
    status = "partial" if has_core_data and has_incomplete_values else "checked" if has_core_data else "failed"
    result = _initial_policy_status_result(True)
    result.update(
        {
            "status": status,
            "policy_status": policy_status,
            "commands_completed": completed,
            "error_code": "" if status == "checked" else ERROR_WINDOWS_POLICY_STATUS_FAILED,
            "error_message": ""
            if status == "checked"
            else "Windows local security policy indicators returned incomplete data.",
            "command_results": command_results,
        }
    )
    return result


def _run_safe_cmd(
    session: Any,
    command: str,
    command_name: str = "command",
    command_timeout: float = DEFAULT_WINDOWS_COMMAND_TIMEOUT_SECONDS,
    budget: WindowsAuditBudget | None = None,
    command_results: list[dict[str, Any]] | None = None,
) -> str:
    result = execute_windows_command(
        session,
        command_name=command_name,
        command_used_safe_label=command_name,
        command_type="cmd",
        command=command,
        command_timeout=command_timeout,
        budget=budget,
    )
    if command_results is not None:
        command_results.append(result)
    if not result["success"]:
        raise WindowsCommandError(str(result.get("error_code") or WINDOWS_COMMAND_FAILED), str(result.get("error_message") or "Command failed."))
    return str(result.get("stdout") or "")


def _safe_multiline_output_text(value: Any) -> str:
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value or "")
    return "\n".join(line.rstrip() for line in text.splitlines())


def _policy_status_error(error_code: str, exc: Exception, commands_completed: int) -> dict[str, Any]:
    result = _initial_policy_status_result(True)
    result.update(
        {
            "status": "failed",
            "error_code": error_code,
            "error_message": "Windows local security policy indicator collection failed.",
            "safe_detail": exc.__class__.__name__,
            "commands_completed": commands_completed,
        }
    )
    return result


def _initial_policy_status_result(requested: bool) -> dict[str, Any]:
    return {
        "requested": requested,
        "status": "skipped",
        "error_code": "",
        "error_message": "",
        "safe_detail": "",
        "policy_status": dict(EMPTY_WINDOWS_POLICY_STATUS),
        "commands_completed": 0,
    }


def _collect_windows_registry_audit(
    session: Any,
    template_path: str | Path | None,
    *,
    command_timeout: float = DEFAULT_WINDOWS_COMMAND_TIMEOUT_SECONDS,
    budget: WindowsAuditBudget | None = None,
) -> dict[str, Any]:
    completed = 0
    command_results: list[dict[str, Any]] = []
    effective_template_path = template_path or DEFAULT_WINDOWS_REGISTRY_TEMPLATE
    try:
        template = load_registry_template(effective_template_path)
    except WindowsRegistryTemplateError as exc:
        result = _initial_registry_audit_result(True, effective_template_path)
        registry_audit = empty_registry_audit(effective_template_path)
        registry_audit["limitations"] = [
            str(exc),
            "Windows registry audit did not run because the template could not be loaded safely.",
        ]
        result.update(
            {
                "status": "failed",
                "error_code": exc.error_code,
                "error_message": str(exc),
                "safe_detail": exc.error_code,
                "registry_audit": registry_audit,
            }
        )
        return result

    observed_by_check_id: dict[str, dict[str, Any]] = {}
    for check in template.get("checks") or []:
        if not getattr(check, "enabled", False):
            continue
        try:
            raw_output = _run_safe_ps(session, build_registry_query_command(check), f"registry:{check.id}", command_timeout, budget, command_results)
            completed += 1
            value_data = _json_object(raw_output)
            observed_by_check_id[check.id] = {
                "present": bool(value_data.get("Present")),
                "observed_value": value_data.get("Value"),
            }
        except TimeoutError as exc:
            return _registry_audit_error(ERROR_WINDOWS_REGISTRY_AUDIT_TIMEOUT, exc, completed, effective_template_path)
        except Exception as exc:
            completed += 1
            observed_by_check_id[check.id] = {
                "status": "unknown",
                "error_code": ERROR_WINDOWS_REGISTRY_AUDIT_FAILED,
                "evidence_summary": (
                    f"Registry value {check.hive}\\{check.path}\\{check.value_name} was not present "
                    f"or could not be read using the exact template-defined path."
                ),
                "observed_value": "",
                "safe_detail": exc.__class__.__name__,
            }

    registry_audit = evaluate_registry_audit(template, observed_by_check_id)
    unknown_or_error = any(item.get("status") in {"unknown", "error"} for item in registry_audit["check_results"])
    status = "partial" if unknown_or_error else "checked"
    result = _initial_registry_audit_result(True, effective_template_path)
    result.update(
        {
            "status": status,
            "registry_audit": registry_audit,
            "commands_completed": completed,
            "error_code": "" if status == "checked" else ERROR_WINDOWS_REGISTRY_AUDIT_FAILED,
            "error_message": "" if status == "checked" else "One or more registry indicators could not be read.",
            "safe_detail": "",
            "command_results": command_results,
        }
    )
    return result


def _registry_audit_error(
    error_code: str,
    exc: Exception,
    commands_completed: int,
    template_path: str | Path | None,
) -> dict[str, Any]:
    result = _initial_registry_audit_result(True, template_path)
    registry_audit = empty_registry_audit(template_path or DEFAULT_WINDOWS_REGISTRY_TEMPLATE)
    registry_audit["limitations"] = [
        "Windows registry audit command execution failed.",
        "Version 12.6 performs narrow template-based registry checks only.",
    ]
    result.update(
        {
            "status": "failed",
            "error_code": error_code,
            "error_message": "Windows registry audit failed.",
            "safe_detail": exc.__class__.__name__,
            "registry_audit": registry_audit,
            "commands_completed": commands_completed,
        }
    )
    return result


def _initial_registry_audit_result(requested: bool, template_path: str | Path | None) -> dict[str, Any]:
    return {
        "requested": requested,
        "status": "skipped",
        "error_code": "",
        "error_message": "",
        "safe_detail": "",
        "registry_audit": empty_registry_audit(template_path or DEFAULT_WINDOWS_REGISTRY_TEMPLATE),
        "commands_completed": 0,
    }


def _firewall_profiles_from_output(value: str) -> list[dict[str, str]]:
    parsed = _json_value(value)
    items = parsed if isinstance(parsed, list) else [parsed]
    profiles: list[dict[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        profiles.append(
            {
                "name": _short_value(item.get("Name")),
                "enabled": _short_value(item.get("Enabled")),
                "default_inbound_action": _short_value(item.get("DefaultInboundAction")),
                "default_outbound_action": _short_value(item.get("DefaultOutboundAction")),
            }
        )
    return profiles


def _defender_service_from_output(value: str) -> dict[str, str]:
    data = _json_object(value)
    return {
        "status": _short_value(data.get("Status")),
        "start_type": _short_value(data.get("StartType")),
    }


def _defender_status_from_output(value: str) -> dict[str, str]:
    data = _json_object(value)
    return {
        "am_service_enabled": _short_value(data.get("AMServiceEnabled")),
        "antispyware_enabled": _short_value(data.get("AntispywareEnabled")),
        "antivirus_enabled": _short_value(data.get("AntivirusEnabled")),
        "real_time_protection_enabled": _short_value(data.get("RealTimeProtectionEnabled")),
        "behavior_monitor_enabled": _short_value(data.get("BehaviorMonitorEnabled")),
        "ioav_protection_enabled": _short_value(data.get("IoavProtectionEnabled")),
        "nis_enabled": _short_value(data.get("NISEnabled")),
        "antivirus_signature_last_updated": _short_value(data.get("AntivirusSignatureLastUpdated")),
        "antispyware_signature_last_updated": _short_value(data.get("AntispywareSignatureLastUpdated")),
    }


def _classify_winrm_exception(exc: Exception) -> str:
    name = exc.__class__.__name__.lower()
    text = str(exc).lower()
    if "timeout" in name or "timeout" in text:
        return WINRM_TIMEOUT
    if any(token in text for token in ("401", "unauthorized", "forbidden", "auth", "credential")):
        return WINRM_AUTH_FAILED
    if any(token in text for token in ("connect", "connection", "refused", "unreachable", "certificate", "ssl")):
        return WINRM_CONNECTION_FAILED
    return WINRM_UNKNOWN_ERROR


def _winrm_error_message(error_code: str) -> str:
    messages = {
        WINRM_AUTH_FAILED: "WinRM authentication attempt failed.",
        WINRM_TIMEOUT: "WinRM authentication check timed out.",
        WINRM_CONNECTION_FAILED: "WinRM connection failed before authentication could be validated.",
        WINRM_UNKNOWN_ERROR: "WinRM authentication check encountered an unexpected error.",
    }
    return messages.get(error_code, "WinRM authentication check did not succeed.")


def _winrm_status_from_error_code(error_code: str) -> str:
    if error_code == WINRM_AUTH_FAILED:
        return "auth_failed"
    if error_code == WINRM_TIMEOUT:
        return "timeout"
    return "error"


def _winrm_auth_result(
    *,
    started: float,
    status: str,
    error_code: str,
    message: str,
    endpoint_used: str = "",
    transport: str = "",
    authenticated: bool = False,
    validation_result_summary: str = "",
    safe_detail: str = "",
    limitations: str,
    host_info_requested: bool = False,
    host_info_result: dict[str, Any] | None = None,
    security_status_requested: bool = False,
    security_status_result: dict[str, Any] | None = None,
    policy_status_requested: bool = False,
    policy_status_result: dict[str, Any] | None = None,
    registry_audit_requested: bool = False,
    registry_audit_template_path: str | Path | None = None,
    registry_audit_result: dict[str, Any] | None = None,
    command_results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    host_result = host_info_result or _initial_host_info_result(host_info_requested)
    security_result = security_status_result or _initial_security_status_result(security_status_requested)
    policy_result = policy_status_result or _initial_policy_status_result(policy_status_requested)
    registry_result = registry_audit_result or _initial_registry_audit_result(
        registry_audit_requested,
        registry_audit_template_path,
    )
    return {
        "attempted": True,
        "status": status,
        "error_code": error_code,
        "message": message,
        "endpoint_used": endpoint_used,
        "transport": transport,
        "authenticated": authenticated,
        "safe_validation_command": SAFE_WINRM_VALIDATION_COMMAND,
        "validation_result_summary": validation_result_summary,
        "limitations": limitations,
        "safe_detail": safe_detail,
        "duration_seconds": round(perf_counter() - started, 3),
        "host_info_requested": bool(host_result.get("requested")),
        "host_info_status": host_result.get("status") or "skipped",
        "host_info_error_code": host_result.get("error_code") or "",
        "host_info_error_message": host_result.get("error_message") or "",
        "host_info_safe_detail": host_result.get("safe_detail") or "",
        "host_info": host_result.get("host_info") or dict(EMPTY_WINDOWS_HOST_INFO),
        "host_info_commands_completed": int(host_result.get("commands_completed") or 0),
        "security_status_requested": bool(security_result.get("requested")),
        "security_status_status": security_result.get("status") or "skipped",
        "security_status_error_code": security_result.get("error_code") or "",
        "security_status_error_message": security_result.get("error_message") or "",
        "security_status_safe_detail": security_result.get("safe_detail") or "",
        "security_status": security_result.get("security_status") or dict(EMPTY_WINDOWS_SECURITY_STATUS),
        "security_status_commands_completed": int(security_result.get("commands_completed") or 0),
        "policy_status_requested": bool(policy_result.get("requested")),
        "policy_status_status": policy_result.get("status") or "skipped",
        "policy_status_error_code": policy_result.get("error_code") or "",
        "policy_status_error_message": policy_result.get("error_message") or "",
        "policy_status_safe_detail": policy_result.get("safe_detail") or "",
        "policy_status": policy_result.get("policy_status") or dict(EMPTY_WINDOWS_POLICY_STATUS),
        "policy_status_commands_completed": int(policy_result.get("commands_completed") or 0),
        "registry_audit_requested": bool(registry_result.get("requested")),
        "registry_audit_status": registry_result.get("status") or "skipped",
        "registry_audit_error_code": registry_result.get("error_code") or "",
        "registry_audit_error_message": registry_result.get("error_message") or "",
        "registry_audit_safe_detail": registry_result.get("safe_detail") or "",
        "registry_audit": registry_result.get("registry_audit") or empty_registry_audit(registry_audit_template_path),
        "registry_audit_commands_completed": int(registry_result.get("commands_completed") or 0),
        "command_results": command_results or [],
    }


def _audit_status(*, checks_failed: int) -> str:
    return "failed" if checks_failed else "success"


def _service_finding(
    target: str,
    status: dict[str, Any],
    title: str,
    severity: str,
    category: str,
) -> Finding:
    port = int(status["port"])
    service = str(status["service"]).lower().replace(" ", "_").replace("/", "_")
    details = _windows_evidence(
        summary=str(status["evidence"]),
        source="tcp-connect",
        command_name="tcp-connect",
        observed_value=f"TCP port {port} reachable",
        expected_value="Restricted to authorised networks when required",
        limitation=str(status["limitation"]),
    )
    return create_finding(
        title=title,
        severity=severity,  # type: ignore[arg-type]
        category=category,
        affected_host=target,
        affected_port=port,
        service=service,
        evidence=evidence_summary(details),
        evidence_details=details,
        confidence="High",
        impact=f"{status['service']} is reachable from the scanned network.",
        recommendation=str(status["recommendation"]),
        verification=f"Re-run VulScan or test TCP connectivity to port {port}.",
        limitation=str(status["limitation"]),
        source=SOURCE,
    )


def _winrm_auth_finding(target: str, winrm_auth: dict[str, Any]) -> Finding:
    status = str(winrm_auth.get("status") or "")
    if status == "authenticated":
        details = _windows_evidence(
            summary="WinRM authentication succeeded and safe validation command completed.",
            source=SAFE_WINRM_VALIDATION_COMMAND,
            command_name=SAFE_WINRM_VALIDATION_COMMAND,
            observed_value="Authentication succeeded",
            expected_value="Single authorised WinRM authentication attempt",
            limitation="Authentication success does not indicate vulnerability.",
        )
        return create_finding(
            title="WinRM Authentication Successful",
            severity="Informational",
            category="Windows Credentialed Access",
            affected_host=target,
            service="winrm",
            evidence=evidence_summary(details),
            evidence_details=details,
            confidence="High",
            impact="Credentialed Windows auditing can be performed in later versions.",
            recommendation="Use least-privilege accounts and restrict WinRM to trusted networks.",
            verification="Re-run VulScan WinRM authentication check with authorised credentials.",
            limitation="Authentication success does not indicate vulnerability.",
            source=SOURCE,
        )
    if status == "not_reachable":
        details = _windows_evidence(
            summary="TCP connection to WinRM ports failed or endpoint was unavailable.",
            source="tcp-connect",
            command_name="tcp-connect",
            observed_value="WinRM not reachable",
            expected_value="Reachable only when authorised and required",
            limitation="Unreachable WinRM may be expected in hardened environments.",
        )
        return create_finding(
            title="WinRM Not Reachable",
            severity="Informational",
            category="Windows Remote Management",
            affected_host=target,
            service="winrm",
            evidence=evidence_summary(details),
            evidence_details=details,
            confidence="High",
            impact="WinRM authentication could not be validated because WinRM was not reachable.",
            recommendation="Verify WinRM is enabled and reachable only if required.",
            verification="Re-run VulScan after confirming authorised WinRM network access.",
            limitation="Unreachable WinRM may be expected in hardened environments.",
            source=SOURCE,
        )
    if status == "dependency_missing":
        details = _windows_evidence(
            summary="pywinrm dependency is not installed.",
            source="local dependency check",
            command_name="import winrm",
            observed_value="pywinrm missing",
            expected_value="pywinrm available for WinRM checks",
            limitation="VulScan cannot perform WinRM authentication without this dependency.",
        )
        return create_finding(
            title="WinRM Dependency Missing",
            severity="Informational",
            category="Tool Configuration",
            affected_host=target,
            service="winrm",
            evidence=evidence_summary(details),
            evidence_details=details,
            confidence="High",
            impact="VulScan cannot perform WinRM authentication checks without pywinrm.",
            recommendation="Install pywinrm in the VulScan virtual environment to enable WinRM authentication checks.",
            verification="Install pywinrm and re-run VulScan with --windows-auth-method winrm.",
            limitation="VulScan cannot perform WinRM authentication without this dependency.",
            source=SOURCE,
        )
    details = _windows_evidence(
        summary="WinRM authentication attempt failed.",
        source=SAFE_WINRM_VALIDATION_COMMAND,
        command_name=SAFE_WINRM_VALIDATION_COMMAND,
        observed_value=str(winrm_auth.get("status") or "failed"),
        expected_value="Single authorised WinRM authentication attempt succeeds",
        limitation="Failure may be caused by credentials, policy, firewall, certificate, or WinRM configuration.",
    )
    return create_finding(
        title="WinRM Authentication Failed",
        severity="Informational",
        category="Windows Credentialed Access",
        affected_host=target,
        service="winrm",
        evidence=evidence_summary(details),
        evidence_details=details,
        confidence="Medium",
        impact="Credentialed Windows auditing could not be validated.",
        recommendation="Verify username, password, domain, and WinRM configuration.",
        verification="Re-run VulScan WinRM authentication check with authorised credentials after configuration review.",
        limitation="Failure may be caused by credentials, policy, firewall, certificate, or WinRM configuration.",
        source=SOURCE,
    )


def _host_info_findings(target: str, winrm_auth: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if not winrm_auth.get("authenticated"):
        return findings

    host_info = dict(winrm_auth.get("host_info") or {})
    status = str(winrm_auth.get("host_info_status") or "")
    if status == "collected":
        os_name = host_info.get("os_name") or host_info.get("caption") or "unknown"
        build_number = host_info.get("build_number") or host_info.get("build") or "unknown"
        details = _windows_evidence(
            summary=f"Windows host information collected using read-only WinRM commands. OS: {os_name}, Build: {build_number}.",
            source="Win32_OperatingSystem",
            command_name="safe-winrm-host-info",
            observed_value=f"OS={os_name}; Build={build_number}",
            expected_value="Read-only host inventory fields",
            limitation="Host information alone does not confirm vulnerabilities.",
        )
        findings.append(
            create_finding(
                title="Windows Host Information Collected",
                severity="Informational",
                category="Windows Host Information",
                affected_host=target,
                service="winrm",
                evidence=evidence_summary(details),
                evidence_details=details,
                confidence="High",
                impact="Host information improves asset inventory, reporting, and future vulnerability correlation.",
                recommendation="Use this information to support asset management and patch review.",
                verification="Re-run VulScan with --windows-host-info.",
                limitation="Host information alone does not confirm vulnerabilities.",
                source=SOURCE,
            )
        )
        part_of_domain = str(host_info.get("part_of_domain") or "").lower()
        if part_of_domain == "true" and host_info.get("domain"):
            domain_details = _windows_evidence(
                summary="PartOfDomain=True and a domain value was reported.",
                source="Win32_ComputerSystem",
                command_name="safe-winrm-host-info",
                observed_value=f"PartOfDomain=True; Domain={host_info.get('domain')}",
                expected_value="Interpret with domain policy context",
                limitation="Domain membership does not indicate insecure configuration.",
            )
            findings.append(
                create_finding(
                    title="Windows System Appears Domain Joined",
                    severity="Informational",
                    category="Windows Host Information",
                    affected_host=target,
                    service="winrm",
                    evidence=evidence_summary(domain_details),
                    evidence_details=domain_details,
                    confidence="Medium",
                    impact="Domain context may affect interpretation of future Windows policy checks.",
                    recommendation="Consider domain policy context when interpreting future local policy checks.",
                    verification="Re-run VulScan with --windows-host-info.",
                    limitation="Domain membership does not indicate insecure configuration.",
                    source=SOURCE,
                )
            )
        elif part_of_domain == "false" or host_info.get("workgroup"):
            workgroup_details = _windows_evidence(
                summary="PartOfDomain=False or a workgroup value was reported.",
                source="Win32_ComputerSystem",
                command_name="safe-winrm-host-info",
                observed_value=f"PartOfDomain={part_of_domain or 'unknown'}; Workgroup={host_info.get('workgroup') or ''}",
                expected_value="Interpret local policy context",
                limitation="Workgroup membership does not indicate vulnerability.",
            )
            findings.append(
                create_finding(
                    title="Windows System Appears Workgroup Joined",
                    severity="Informational",
                    category="Windows Host Information",
                    affected_host=target,
                    service="winrm",
                    evidence=evidence_summary(workgroup_details),
                    evidence_details=workgroup_details,
                    confidence="Medium",
                    impact="Local security configuration may be more important when domain policy does not apply.",
                    recommendation="Review local security configuration directly because domain policy may not apply.",
                    verification="Re-run VulScan with --windows-host-info.",
                    limitation="Workgroup membership does not indicate vulnerability.",
                    source=SOURCE,
                )
            )
        return findings

    details = _windows_evidence(
        summary="Safe read-only host information command failed or returned incomplete data.",
        source="safe-winrm-host-info",
        command_name="safe-winrm-host-info",
        observed_value=str(winrm_auth.get("host_info_status") or "failed"),
        expected_value="Read-only host information collected",
        limitation="Missing host info may be caused by permissions, policy, or WinRM configuration.",
    )
    return [
        create_finding(
            title="Windows Host Information Collection Failed",
            severity="Informational",
            category="Windows Host Information",
            affected_host=target,
            service="winrm",
            evidence=evidence_summary(details),
            evidence_details=details,
            confidence="Medium",
            impact="Windows host information could not be used for reporting or future correlation.",
            recommendation="Verify WinRM permissions and target configuration.",
            verification="Re-run VulScan with --windows-host-info after confirming WinRM permissions.",
            limitation="Missing host info may be caused by permissions, policy, or WinRM configuration.",
            source=SOURCE,
        )
    ]


def _security_status_findings(target: str, winrm_auth: dict[str, Any]) -> list[Finding]:
    if not winrm_auth.get("authenticated"):
        return []

    security_status = dict(winrm_auth.get("security_status") or {})
    firewall_profiles = list(security_status.get("firewall_profiles") or [])
    defender_service = dict(security_status.get("defender_service") or {})
    defender_status = dict(security_status.get("defender_status") or {})
    findings: list[Finding] = []

    disabled_profiles = [
        profile for profile in firewall_profiles if str(profile.get("enabled") or "").lower() == "false"
    ]
    if disabled_profiles:
        profile_name = disabled_profiles[0].get("name") or "Unknown"
        details = _windows_evidence(
            summary=f"Firewall {profile_name} profile observed Enabled=False; expected Enabled=True.",
            source="Get-NetFirewallProfile",
            command_name="Get-NetFirewallProfile",
            observed_value=f"{profile_name}.Enabled=False",
            expected_value="Enabled=True",
            limitation="Firewall status should be interpreted with domain policy and third-party firewall controls.",
        )
        findings.append(
            create_finding(
                title="Windows Firewall Profile Disabled",
                severity="Medium",
                category="Windows Firewall",
                affected_host=target,
                service="winrm",
                evidence=evidence_summary(details),
                evidence_details=details,
                confidence="Medium",
                impact="Disabled firewall profiles may allow unwanted inbound network access.",
                recommendation="Enable Windows Firewall profiles unless a documented compensating control exists.",
                verification="Run Get-NetFirewallProfile and review Enabled state.",
                limitation="Domain policy or third-party firewall controls may affect interpretation.",
                source=SECURITY_SOURCE,
            )
        )
    if firewall_profiles:
        details = _windows_evidence(
            summary="Firewall profiles reviewed using Get-NetFirewallProfile.",
            source="Get-NetFirewallProfile",
            command_name="Get-NetFirewallProfile",
            observed_value=f"{len(firewall_profiles)} profile(s) reviewed",
            expected_value="Profile status available",
            limitation="This check does not enumerate individual firewall rules.",
        )
        findings.append(
            create_finding(
                title="Windows Firewall Status Reviewed",
                severity="Informational",
                category="Windows Firewall",
                affected_host=target,
                service="winrm",
                evidence=evidence_summary(details),
                evidence_details=details,
                confidence="High",
                impact="Firewall status supports host exposure review.",
                recommendation="Review firewall profile settings according to organisational policy.",
                verification="Run Get-NetFirewallProfile.",
                limitation="This check does not enumerate individual firewall rules.",
                source=SECURITY_SOURCE,
            )
        )

    if defender_service and str(defender_service.get("status") or "").lower() not in {"", "running"}:
        service_status = defender_service.get("status") or "unknown"
        details = _windows_evidence(
            summary=f"WinDefend service observed Status={service_status}; expected Running.",
            source="Get-Service WinDefend",
            command_name="Get-Service WinDefend",
            observed_value=f"Status={service_status}",
            expected_value="Running",
            limitation="Third-party antivirus may be used instead of Defender.",
        )
        findings.append(
            create_finding(
                title="Microsoft Defender Service Not Running",
                severity="Medium",
                category="Endpoint Protection",
                affected_host=target,
                service="windefend",
                evidence=evidence_summary(details),
                evidence_details=details,
                confidence="Medium",
                impact="Endpoint protection may not be active.",
                recommendation="Verify Microsoft Defender or approved alternative endpoint protection is active.",
                verification="Run Get-Service WinDefend.",
                limitation="Third-party antivirus may be used instead of Defender.",
                source=SECURITY_SOURCE,
            )
        )
    if str(defender_status.get("real_time_protection_enabled") or "").lower() == "false":
        details = _windows_evidence(
            summary="RealTimeProtectionEnabled=False; expected True.",
            source="Get-MpComputerStatus",
            command_name="Get-MpComputerStatus",
            observed_value="RealTimeProtectionEnabled=False",
            expected_value="True",
            limitation="Some enterprise policies or third-party EDR solutions may change Defender behaviour.",
        )
        findings.append(
            create_finding(
                title="Microsoft Defender Real-Time Protection Disabled",
                severity="High",
                category="Endpoint Protection",
                affected_host=target,
                service="defender",
                evidence=evidence_summary(details),
                evidence_details=details,
                confidence="Medium",
                impact="Malware protection may be reduced.",
                recommendation="Enable real-time protection or verify approved compensating controls.",
                verification="Run Get-MpComputerStatus and check RealTimeProtectionEnabled.",
                limitation="Some enterprise policies or third-party EDR solutions may change Defender behaviour.",
                source=SECURITY_SOURCE,
            )
        )
    if any(defender_status.values()):
        details = _windows_evidence(
            summary="Defender status reviewed using Get-MpComputerStatus.",
            source="Get-MpComputerStatus",
            command_name="Get-MpComputerStatus",
            observed_value="Defender status fields available",
            expected_value="Endpoint protection status available",
            limitation="Get-MpComputerStatus may be unavailable or restricted on some systems.",
        )
        findings.append(
            create_finding(
                title="Microsoft Defender Status Reviewed",
                severity="Informational",
                category="Endpoint Protection",
                affected_host=target,
                service="defender",
                evidence=evidence_summary(details),
                evidence_details=details,
                confidence="High",
                impact="Endpoint protection status supports security posture review.",
                recommendation="Review Defender/EDR posture according to organisational policy.",
                verification="Run Get-MpComputerStatus.",
                limitation="Get-MpComputerStatus may be unavailable or restricted on some systems.",
                source=SECURITY_SOURCE,
            )
        )
    if winrm_auth.get("security_status_status") == "failed" or security_status.get("security_status_limitations"):
        details = _windows_evidence(
            summary="One or more read-only Windows security status commands failed or returned incomplete data.",
            source="Windows security status",
            command_name="safe-winrm-security-status",
            observed_value=str(winrm_auth.get("security_status_status") or "failed"),
            expected_value="Firewall and Defender status collected",
            limitation="Command availability and permissions vary by Windows version and policy.",
        )
        findings.append(
            create_finding(
                title="Windows Security Status Collection Failed",
                severity="Informational",
                category="Windows Security Status",
                affected_host=target,
                service="winrm",
                evidence=evidence_summary(details),
                evidence_details=details,
                confidence="Medium",
                impact="VulScan could not fully confirm firewall or Defender status.",
                recommendation="Verify manually with appropriate permissions.",
                verification="Run Get-NetFirewallProfile and Get-MpComputerStatus manually.",
                limitation="Command availability and permissions vary by Windows version and policy.",
                source=SECURITY_SOURCE,
            )
        )
    return findings


def _completed_finding(
    target: str,
    service_statuses: list[dict[str, Any]],
    winrm_auth: dict[str, Any],
    auth_method: str,
) -> Finding:
    if auth_method == "winrm":
        details = _windows_evidence(
            summary=f"WinRM authentication check completed with status: {winrm_auth.get('status')}.",
            source=SAFE_WINRM_VALIDATION_COMMAND,
            command_name=SAFE_WINRM_VALIDATION_COMMAND,
            observed_value=str(winrm_auth.get("status") or "skipped"),
            expected_value="Single authorised WinRM authentication validation completed",
            limitation="Version 12.8 improves evidence quality only and does not add intrusive Windows checks.",
        )
        return create_finding(
            title="Windows WinRM Authentication Check Completed",
            severity="Informational",
            category="Windows Audit",
            affected_host=target,
            evidence=evidence_summary(details),
            evidence_details=details,
            confidence="High",
            impact="A safe single-attempt WinRM authentication validation was completed.",
            recommendation="Use later authenticated Windows audit modules for deeper read-only checks.",
            verification="Re-run VulScan with --windows-audit --windows-auth-method winrm.",
            limitation="Version 12.2 validates authentication and optionally collects basic host information only; it does not run deep Windows enumeration.",
            source=SOURCE,
        )

    reachable = [f"{item['service']}:{item['port']}" for item in service_statuses if item.get("reachable")]
    observed = ", ".join(reachable) if reachable else "no Windows management services reachable"
    details = _windows_evidence(
        summary=f"Windows service reachability checks completed; {observed}.",
        source="tcp-connect",
        command_name="tcp-connect",
        observed_value=observed,
        expected_value="Only authorised management services reachable",
        limitation="Reachability checks do not confirm insecure configuration.",
    )
    return create_finding(
        title="Windows Audit Foundation Completed",
        severity="Informational",
        category="Windows Audit",
        affected_host=target,
        evidence=evidence_summary(details),
        evidence_details=details,
        confidence="High",
        impact="Foundation-level Windows service exposure indicators were collected.",
        recommendation="Use authenticated Windows audit in later versions for deeper checks.",
        verification="Re-run VulScan with --windows-audit.",
        limitation="Version 12.2 performs foundation-level reachability checks unless WinRM authentication or host information collection is explicitly requested.",
        source=SOURCE,
    )


def _windows_evidence(
    *,
    summary: str,
    source: str,
    command_name: str,
    observed_value: Any,
    expected_value: Any,
    limitation: str,
) -> dict[str, Any]:
    return build_evidence(
        summary=summary,
        source=source,
        command_name=command_name,
        command_used_safe_label=command_name,
        observed_value=observed_value,
        expected_value=expected_value,
        limitation=limitation,
        raw_output_included=False,
    )


def _windows_progress(progress_callback: Any | None, message: str) -> None:
    if progress_callback:
        progress_callback(message)


def _normalise_command_exception(exc: Exception) -> str:
    name = exc.__class__.__name__.lower()
    text = str(exc).lower()
    if "timeout" in name or "timeout" in text:
        return WINDOWS_COMMAND_TIMEOUT
    if "not recognized" in text or "not found" in text or "unavailable" in text:
        return WINDOWS_COMMAND_UNAVAILABLE
    if any(token in text for token in ("connect", "connection", "refused", "unreachable", "ssl", "certificate")):
        return WINDOWS_WINRM_CONNECTION_FAILED
    return WINDOWS_UNKNOWN_ERROR


def _has_partial_windows_results(winrm_auth: dict[str, Any]) -> bool:
    if not winrm_auth.get("attempted"):
        return False
    section_statuses = [
        winrm_auth.get("host_info_status"),
        winrm_auth.get("security_status_status"),
        winrm_auth.get("policy_status_status"),
        winrm_auth.get("registry_audit_status"),
    ]
    if any(status in {"failed", "partial"} for status in section_statuses):
        return True
    if any(
        winrm_auth.get(flag) and winrm_auth.get(status_key) == "skipped"
        for flag, status_key in (
            ("host_info_requested", "host_info_status"),
            ("security_status_requested", "security_status_status"),
            ("policy_status_requested", "policy_status_status"),
            ("registry_audit_requested", "registry_audit_status"),
        )
    ):
        return True
    return any(result.get("timed_out") for result in winrm_auth.get("command_results") or [])


def _partial_results_finding(target: str, winrm_auth: dict[str, Any]) -> Finding:
    details = _windows_evidence(
        summary="One or more Windows audit sections failed, timed out, or were skipped.",
        source=SOURCE,
        command_name="windows-audit-orchestration",
        observed_value=_section_status_summary(winrm_auth),
        expected_value="All requested Windows audit sections complete successfully",
        limitation="Partial results may not represent the full Windows security posture.",
    )
    return create_finding(
        title="Windows Audit Completed with Partial Results",
        severity="Informational",
        category="Windows Audit Reliability",
        affected_host=target,
        service="winrm",
        evidence=evidence_summary(details),
        evidence_details=details,
        confidence="High",
        impact="Some Windows audit indicators may be unavailable or incomplete.",
        recommendation="Review timeout settings, WinRM availability, and permissions.",
        verification="Re-run the Windows audit after reviewing timeout and WinRM settings.",
        limitation="Partial results may not represent the full Windows security posture.",
        source=SOURCE,
    )


def _section_status_summary(winrm_auth: dict[str, Any]) -> str:
    sections = _windows_section_statuses(winrm_auth, [])
    return ", ".join(f"{name}={section['status']}" for name, section in sections.items())


def _windows_section_statuses(
    winrm_auth: dict[str, Any],
    service_statuses: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    sections: dict[str, dict[str, Any]] = {
        "service_reachability": {
            "status": "success",
            "checks_planned": len(WINDOWS_SERVICE_CHECKS),
            "checks_completed": len(service_statuses),
            "checks_failed": sum(1 for item in service_statuses if item.get("error_code")),
            "checks_skipped": max(0, len(WINDOWS_SERVICE_CHECKS) - len(service_statuses)),
            "duration_seconds": round(sum(float(item.get("duration_seconds") or 0.0) for item in service_statuses), 3),
            "error_code": "",
            "limitation": "TCP reachability only; no service configuration is changed.",
        },
        "winrm_authentication": {
            "status": _section_status_from_winrm(winrm_auth),
            "checks_planned": 1 if winrm_auth.get("attempted") else 0,
            "checks_completed": 1 if winrm_auth.get("attempted") else 0,
            "checks_failed": 0 if winrm_auth.get("authenticated") or not winrm_auth.get("attempted") else 1,
            "checks_skipped": 0,
            "duration_seconds": float(winrm_auth.get("duration_seconds") or 0.0),
            "error_code": "" if winrm_auth.get("authenticated") else str(winrm_auth.get("error_code") or ""),
            "limitation": "Single safe WinRM validation command only.",
        },
    }
    _add_requested_section(
        sections,
        key="host_information",
        requested=bool(winrm_auth.get("host_info_requested")),
        raw_status=str(winrm_auth.get("host_info_status") or "skipped"),
        planned=6,
        completed=int(winrm_auth.get("host_info_commands_completed") or 0),
        error_code=str(winrm_auth.get("host_info_error_code") or ""),
        command_results=winrm_auth.get("command_results") or [],
        command_prefixes=("hostname", "whoami", "PowerShell version", "Win32_OperatingSystem", "Win32_ComputerSystem", "Get-TimeZone"),
        limitation="Read-only host inventory commands only.",
    )
    _add_requested_section(
        sections,
        key="security_status",
        requested=bool(winrm_auth.get("security_status_requested")),
        raw_status=str(winrm_auth.get("security_status_status") or "skipped"),
        planned=3,
        completed=int(winrm_auth.get("security_status_commands_completed") or 0),
        error_code=str(winrm_auth.get("security_status_error_code") or ""),
        command_results=winrm_auth.get("command_results") or [],
        command_prefixes=("Get-NetFirewallProfile", "Get-Service WinDefend", "Get-MpComputerStatus"),
        limitation="Read-only Firewall and Defender status commands only.",
    )
    _add_requested_section(
        sections,
        key="local_security_policy",
        requested=bool(winrm_auth.get("policy_status_requested")),
        raw_status=str(winrm_auth.get("policy_status_status") or "skipped"),
        planned=1,
        completed=int(winrm_auth.get("policy_status_commands_completed") or 0),
        error_code=str(winrm_auth.get("policy_status_error_code") or ""),
        command_results=winrm_auth.get("command_results") or [],
        command_prefixes=(NET_ACCOUNTS_COMMAND,),
        limitation="Read-only net accounts indicator only.",
    )
    registry_commands = [
        result for result in winrm_auth.get("command_results") or [] if str(result.get("command_name") or "").startswith("registry:")
    ]
    registry_planned = max(len(registry_commands), int((winrm_auth.get("registry_audit") or {}).get("checks_total") or 0))
    _add_requested_section(
        sections,
        key="registry_audit",
        requested=bool(winrm_auth.get("registry_audit_requested")),
        raw_status=str(winrm_auth.get("registry_audit_status") or "skipped"),
        planned=registry_planned,
        completed=int(winrm_auth.get("registry_audit_commands_completed") or 0),
        error_code=str(winrm_auth.get("registry_audit_error_code") or ""),
        command_results=registry_commands,
        command_prefixes=("registry:",),
        limitation="Exact template-defined HKLM value reads only.",
    )
    sections["patch_status"] = {
        "status": "skipped",
        "checks_planned": 0,
        "checks_completed": 0,
        "checks_failed": 0,
        "checks_skipped": 0,
        "duration_seconds": 0.0,
        "error_code": "",
        "limitation": "Patch status flag is reserved in this build.",
    }
    return sections


def _add_requested_section(
    sections: dict[str, dict[str, Any]],
    *,
    key: str,
    requested: bool,
    raw_status: str,
    planned: int,
    completed: int,
    error_code: str,
    command_results: list[dict[str, Any]],
    command_prefixes: tuple[str, ...],
    limitation: str,
) -> None:
    status = _section_status_from_raw(raw_status, requested)
    related_results = [
        result
        for result in command_results
        if any(str(result.get("command_name") or "").startswith(prefix) for prefix in command_prefixes)
    ]
    failed = sum(1 for result in related_results if not result.get("success"))
    sections[key] = {
        "status": status,
        "checks_planned": planned if requested else 0,
        "checks_completed": completed,
        "checks_failed": failed if failed else (1 if status == "failed" else 0),
        "checks_skipped": max(0, (planned if requested else 0) - completed),
        "duration_seconds": round(sum(float(result.get("duration_seconds") or 0.0) for result in related_results), 3),
        "error_code": error_code,
        "limitation": limitation,
    }


def _section_status_from_raw(raw_status: str, requested: bool) -> str:
    if not requested:
        return "skipped"
    if raw_status in {"checked", "collected", "authenticated"}:
        return "success"
    if raw_status in {"partial"}:
        return "partial"
    if raw_status in {"failed", "timeout", "auth_failed", "error"}:
        return "failed"
    return "skipped"


def _section_status_from_winrm(winrm_auth: dict[str, Any]) -> str:
    if not winrm_auth.get("attempted"):
        return "skipped"
    return "success" if winrm_auth.get("authenticated") else "failed"


def _build_summary(
    *,
    target: str,
    username: str | None,
    domain: str | None,
    auth_method: str,
    service_statuses: list[dict[str, Any]],
    status: str,
    checks_failed: int,
    findings_count: int,
    winrm_auth: dict[str, Any],
    connection_timeout: float = DEFAULT_WINDOWS_TIMEOUT_SECONDS,
    command_timeout: float = DEFAULT_WINDOWS_COMMAND_TIMEOUT_SECONDS,
    audit_timeout: float = DEFAULT_WINDOWS_AUDIT_TIMEOUT_SECONDS,
    total_duration: float = 0.0,
) -> dict[str, Any]:
    service_by_port = {int(item["port"]): item for item in service_statuses}
    command_results = list(winrm_auth.get("command_results") or [])
    timed_out_commands = sum(1 for result in command_results if result.get("timed_out"))
    slowest = max(command_results, key=lambda item: float(item.get("duration_seconds") or 0.0), default={})
    section_statuses = _windows_section_statuses(winrm_auth, service_statuses)
    sections_planned = len(section_statuses)
    sections_completed = sum(1 for section in section_statuses.values() if section["status"] == "success")
    sections_failed = sum(1 for section in section_statuses.values() if section["status"] == "failed")
    sections_skipped = sum(1 for section in section_statuses.values() if section["status"] == "skipped")
    checks_completed = (
        len(service_statuses)
        + (1 if winrm_auth.get("attempted") else 0)
        + int(winrm_auth.get("host_info_commands_completed") or 0)
        + int(winrm_auth.get("security_status_commands_completed") or 0)
        + int(winrm_auth.get("policy_status_commands_completed") or 0)
        + int(winrm_auth.get("registry_audit_commands_completed") or 0)
    )
    checks_skipped = sum(int(section.get("checks_skipped") or 0) for section in section_statuses.values())
    performance_notes = []
    if timed_out_commands:
        performance_notes.append(f"{timed_out_commands} Windows command(s) timed out.")
    if any(section["error_code"] == WINDOWS_AUDIT_TIME_BUDGET_EXCEEDED for section in section_statuses.values()):
        performance_notes.append("Windows audit time budget was exceeded; remaining checks were skipped.")
    limitations = [
        "Version 12.6 performs socket reachability checks, one safe WinRM authentication validation when requested, optional read-only host information collection, optional read-only firewall and Defender status collection, optional net accounts local security policy indicators, and optional narrow template-based registry indicators.",
        "It does not enumerate shares, query broad registry trees, export registry hives, export security policy, list users, list groups, list files, list processes, dump credentials, change registry values, change password or lockout policy, change firewall or Defender settings, exploit, brute force, or modify systems.",
    ]
    if winrm_auth.get("limitations"):
        limitations.append(str(winrm_auth["limitations"]))
    return redact_nested({
        "enabled": True,
        "status": status,
        "target": target,
        "authenticated": bool(winrm_auth.get("authenticated")),
        "auth_method": auth_method,
        "domain": domain or "",
        "username_used": username or "",
        "smb_reachable": bool(service_by_port.get(445, {}).get("reachable")),
        "netbios_smb_reachable": bool(service_by_port.get(139, {}).get("reachable")),
        "winrm_http_reachable": bool(service_by_port.get(5985, {}).get("reachable")),
        "winrm_https_reachable": bool(service_by_port.get(5986, {}).get("reachable")),
        "rdp_reachable": bool(service_by_port.get(3389, {}).get("reachable")),
        "service_statuses": service_statuses,
        "checks_completed": checks_completed,
        "checks_failed": checks_failed,
        "checks_skipped": checks_skipped,
        "findings_count": findings_count,
        "highest_windows_risk_score": 0,
        "highest_windows_risk_label": "Informational",
        "winrm_auth_attempted": bool(winrm_auth.get("attempted")),
        "winrm_auth_status": winrm_auth.get("status") or "skipped",
        "winrm_error_code": winrm_auth.get("error_code") or "",
        "winrm_endpoint_used": winrm_auth.get("endpoint_used") or "",
        "winrm_transport": winrm_auth.get("transport") or "",
        "winrm_authenticated": bool(winrm_auth.get("authenticated")),
        "safe_validation_command": winrm_auth.get("safe_validation_command") or "",
        "validation_result_summary": winrm_auth.get("validation_result_summary") or "",
        "winrm_auth_duration_seconds": float(winrm_auth.get("duration_seconds") or 0.0),
        "windows_host_info_collected": winrm_auth.get("host_info_status") == "collected",
        "windows_host_info": winrm_auth.get("host_info") or dict(EMPTY_WINDOWS_HOST_INFO),
        "windows_host_info_status": winrm_auth.get("host_info_status") or "skipped",
        "windows_host_info_error_code": winrm_auth.get("host_info_error_code") or "",
        "windows_host_info_error_message": winrm_auth.get("host_info_error_message") or "",
        "windows_security_status_checked": winrm_auth.get("security_status_status") in {"checked", "partial"},
        "windows_security_status": winrm_auth.get("security_status") or dict(EMPTY_WINDOWS_SECURITY_STATUS),
        "windows_security_status_status": winrm_auth.get("security_status_status") or "skipped",
        "windows_security_status_error_code": winrm_auth.get("security_status_error_code") or "",
        "windows_security_status_error_message": winrm_auth.get("security_status_error_message") or "",
        "windows_policy_status_checked": winrm_auth.get("policy_status_status") in {"checked", "partial"},
        "windows_policy_status": winrm_auth.get("policy_status") or dict(EMPTY_WINDOWS_POLICY_STATUS),
        "windows_policy_status_status": winrm_auth.get("policy_status_status") or "skipped",
        "windows_policy_status_error_code": winrm_auth.get("policy_status_error_code") or "",
        "windows_policy_status_error_message": winrm_auth.get("policy_status_error_message") or "",
        "windows_registry_audit_checked": winrm_auth.get("registry_audit_status") in {"checked", "partial"},
        "windows_registry_audit": winrm_auth.get("registry_audit") or empty_registry_audit(),
        "windows_registry_audit_status": winrm_auth.get("registry_audit_status") or "skipped",
        "windows_registry_audit_error_code": winrm_auth.get("registry_audit_error_code") or "",
        "windows_registry_audit_error_message": winrm_auth.get("registry_audit_error_message") or "",
        "connection_timeout_seconds": float(connection_timeout),
        "command_timeout_seconds": float(command_timeout),
        "audit_timeout_seconds": float(audit_timeout),
        "total_duration_seconds": float(total_duration),
        "sections": section_statuses,
        "sections_planned": sections_planned,
        "sections_completed": sections_completed,
        "sections_failed": sections_failed,
        "sections_skipped": sections_skipped,
        "checks_planned": sum(int(section.get("checks_planned") or 0) for section in section_statuses.values()),
        "timed_out_commands": timed_out_commands,
        "slowest_command_name": slowest.get("command_name") or "",
        "slowest_command_duration_seconds": float(slowest.get("duration_seconds") or 0.0),
        "performance_notes": performance_notes,
        "limitations": limitations,
    })


def _build_credentialed_audit(
    *,
    target: str,
    username: str | None,
    domain: str | None,
    auth_method: str,
    started_at: str,
    ended_at: str,
    duration_seconds: float,
    status: str,
    service_statuses: list[dict[str, Any]],
    findings: list[Finding],
    errors: list[dict[str, Any]],
    summary: dict[str, Any],
) -> dict[str, Any]:
    checks = [
        CredentialedCheckResult(
            check_id=f"windows-service-{item['port']}",
            check_name=f"{item['service']} reachability",
            source=SOURCE,
            status="success",
            command_name=f"tcp-connect:{item['port']}",
            duration_seconds=float(item.get("duration_seconds") or 0.0),
            findings_count=1 if item.get("reachable") and int(item["port"]) in {445, 5985, 5986, 3389} else 0,
            evidence_summary=str(item.get("evidence") or ""),
        ).to_dict()
        for item in service_statuses
    ]
    winrm_auth = summary.get("winrm_auth_status")
    if summary.get("winrm_auth_attempted"):
        checks.append(
            CredentialedCheckResult(
                check_id="windows-winrm-authentication",
                check_name="WinRM authentication validation",
                source=SOURCE,
                status="success" if summary.get("winrm_authenticated") else "failed",
                command_name=str(summary.get("safe_validation_command") or SAFE_WINRM_VALIDATION_COMMAND),
                duration_seconds=0.0,
                findings_count=1,
                error_code=str(summary.get("winrm_error_code") or "") or None,
                error_message="" if summary.get("winrm_authenticated") else str(winrm_auth or ""),
                evidence_summary=str(summary.get("validation_result_summary") or winrm_auth or ""),
            ).to_dict()
        )
    host_info = dict(summary.get("windows_host_info") or {})
    if summary.get("windows_host_info_collected") or summary.get("windows_host_info_status") == "failed":
        checks.append(
            CredentialedCheckResult(
                check_id="windows-host-information",
                check_name="Windows host information",
                source=SOURCE,
                status="success" if summary.get("windows_host_info_collected") else "failed",
                command_name="safe-winrm-host-info",
                duration_seconds=0.0,
                findings_count=1,
                error_code=str(summary.get("windows_host_info_error_code") or "") or None,
                error_message=str(summary.get("windows_host_info_error_message") or ""),
                evidence_summary="Windows host information collected."
                if summary.get("windows_host_info_collected")
                else "Windows host information collection failed.",
            ).to_dict()
        )
    security_status = dict(summary.get("windows_security_status") or {})
    if summary.get("windows_security_status_checked") or summary.get("windows_security_status_status") == "failed":
        checks.append(
            CredentialedCheckResult(
                check_id="windows-security-status",
                check_name="Windows firewall and Defender status",
                source=SECURITY_SOURCE,
                status="partial"
                if summary.get("windows_security_status_status") == "partial"
                else "success"
                if summary.get("windows_security_status_checked")
                else "failed",
                command_name="safe-winrm-security-status",
                duration_seconds=0.0,
                findings_count=1,
                error_code=str(summary.get("windows_security_status_error_code") or "") or None,
                error_message=str(summary.get("windows_security_status_error_message") or ""),
                evidence_summary="Windows firewall and Defender status collected."
                if summary.get("windows_security_status_checked")
                else "Windows security status collection failed.",
            ).to_dict()
        )
    policy_status = dict(summary.get("windows_policy_status") or {})
    if summary.get("windows_policy_status_checked") or summary.get("windows_policy_status_status") == "failed":
        checks.append(
            CredentialedCheckResult(
                check_id="windows-local-security-policy-indicators",
                check_name="Windows local security policy indicators",
                source=POLICY_SOURCE,
                status="partial"
                if summary.get("windows_policy_status_status") == "partial"
                else "success"
                if summary.get("windows_policy_status_checked")
                else "failed",
                command_name=NET_ACCOUNTS_COMMAND,
                duration_seconds=0.0,
                findings_count=1,
                error_code=str(summary.get("windows_policy_status_error_code") or "") or None,
                error_message=str(summary.get("windows_policy_status_error_message") or ""),
                evidence_summary="Windows local security policy indicators collected."
                if summary.get("windows_policy_status_checked")
                else "Windows local security policy indicator collection failed.",
            ).to_dict()
        )
    registry_audit = dict(summary.get("windows_registry_audit") or {})
    if summary.get("windows_registry_audit_checked") or summary.get("windows_registry_audit_status") == "failed":
        checks.append(
            CredentialedCheckResult(
                check_id="windows-registry-audit-template",
                check_name="Windows registry audit template",
                source=REGISTRY_SOURCE,
                status="partial"
                if summary.get("windows_registry_audit_status") == "partial"
                else "success"
                if summary.get("windows_registry_audit_checked")
                else "failed",
                command_name="safe-winrm-registry-template",
                duration_seconds=0.0,
                findings_count=int(registry_audit.get("checks_with_findings") or 0),
                error_code=str(summary.get("windows_registry_audit_error_code") or "") or None,
                error_message=str(summary.get("windows_registry_audit_error_message") or ""),
                evidence_summary=(
                    f"Windows registry audit template executed with "
                    f"{registry_audit.get('checks_executed', 0)} checks."
                ),
            ).to_dict()
        )
    domain_or_workgroup = host_info.get("domain") or host_info.get("workgroup") or ""
    firewall_profiles = list(security_status.get("firewall_profiles") or [])
    defender_status = dict(security_status.get("defender_status") or {})
    credentialed_summary = dict(summary)
    credentialed_summary.update(
        {
            "hostname": host_info.get("hostname") or "",
            "os_caption": host_info.get("os_caption") or "",
            "os_version": host_info.get("os_version") or "",
            "os_build": host_info.get("os_build") or "",
            "domain_or_workgroup": domain_or_workgroup,
            "powershell_version": host_info.get("powershell_version") or "",
            "firewall_profiles_checked": len(firewall_profiles),
            "defender_status_available": any(defender_status.values()),
            "defender_realtime_enabled": defender_status.get("real_time_protection_enabled") or "",
            "firewall_disabled_profiles_count": sum(
                1 for profile in firewall_profiles if str(profile.get("enabled") or "").lower() == "false"
            ),
            "minimum_password_length": policy_status.get("minimum_password_length"),
            "maximum_password_age_days": policy_status.get("maximum_password_age_days"),
            "password_history_length": policy_status.get("password_history_length"),
            "lockout_threshold": policy_status.get("lockout_threshold"),
            "registry_template_name": registry_audit.get("template_name") or "",
            "registry_checks_executed": registry_audit.get("checks_executed") or 0,
            "registry_checks_with_findings": registry_audit.get("checks_with_findings") or 0,
            "sections_completed": summary.get("sections_completed") or 0,
            "sections_failed": summary.get("sections_failed") or 0,
            "sections_skipped": summary.get("sections_skipped") or 0,
            "status": status,
        }
    )
    audit = CredentialedAuditResult(
        source=SOURCE,
        module_name=MODULE_NAME if auth_method == "winrm" else FOUNDATION_MODULE_NAME,
        status=status,
        target=target,
        authenticated=bool(summary.get("winrm_authenticated")),
        auth_method=auth_method,
        username=username or "",
        profile=PROFILE,
        started_at=started_at,
        ended_at=ended_at,
        duration_seconds=duration_seconds,
        checks_planned=len(checks),
        checks_completed=int(summary.get("checks_completed") or len(checks)),
        checks_failed=len(errors),
        checks_skipped=int(summary.get("checks_skipped") or 0),
        findings=[finding_to_dict(finding) for finding in findings],
        summary=credentialed_summary,
        errors=errors,
        limitations=list(summary["limitations"]),
        performance={
            "duration_seconds": duration_seconds,
            "connection_timeout_seconds": summary.get("connection_timeout_seconds"),
            "command_timeout_seconds": summary.get("command_timeout_seconds"),
            "audit_timeout_seconds": summary.get("audit_timeout_seconds"),
            "total_duration_seconds": summary.get("total_duration_seconds"),
            "timed_out_commands": summary.get("timed_out_commands"),
            "slowest_command_name": summary.get("slowest_command_name"),
            "slowest_command_duration_seconds": summary.get("slowest_command_duration_seconds"),
            "winrm_auth_duration_seconds": summary.get("winrm_auth_duration_seconds"),
        },
        metadata={
            "domain": domain or "",
            "service_statuses": service_statuses,
            "winrm_endpoint_used": summary.get("winrm_endpoint_used") or "",
            "winrm_transport": summary.get("winrm_transport") or "",
            "windows_host_info": host_info,
            "windows_security_status": security_status,
            "windows_policy_status": policy_status,
            "windows_registry_audit": registry_audit,
            "checks": checks,
        },
    )
    return audit.to_dict()


def _authentication_state(auth_method: str, username: str | None) -> bool | str:
    if auth_method == "none":
        return False
    if username:
        return "unknown"
    return False
