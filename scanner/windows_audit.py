"""Windows SMB/WinRM audit foundation checks."""

from __future__ import annotations

import importlib
import json
import socket
from datetime import datetime, timezone
from time import perf_counter
from typing import Any

from scanner.credentialed_result import (
    CredentialedAuditResult,
    CredentialedCheckResult,
    build_error,
)
from scanner.finding import Finding, create_finding, finding_to_dict
from scanner.windows_policy_audit import (
    EMPTY_WINDOWS_POLICY_STATUS,
    NET_ACCOUNTS_COMMAND,
    SOURCE as POLICY_SOURCE,
    build_windows_policy_findings,
    parse_net_accounts_output,
)


SOURCE = "windows_audit"
SECURITY_SOURCE = "windows_security_audit"
MODULE_NAME = "Windows WinRM Authentication Check"
FOUNDATION_MODULE_NAME = "Windows SMB/WinRM Audit Foundation"
PROFILE = "foundation"
ALLOWED_AUTH_METHODS = {"none", "smb", "winrm"}
DEFAULT_TIMEOUT_SECONDS = 2.0
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
ERROR_SERVICE_CHECK_FAILED = "WINDOWS_AUDIT_SERVICE_CHECK_FAILED"
ERROR_WINDOWS_HOST_INFO_FAILED = "WINDOWS_HOST_INFO_FAILED"
ERROR_WINDOWS_HOST_INFO_TIMEOUT = "WINDOWS_HOST_INFO_TIMEOUT"
ERROR_WINDOWS_SECURITY_STATUS_FAILED = "WINDOWS_SECURITY_STATUS_FAILED"
ERROR_WINDOWS_SECURITY_STATUS_TIMEOUT = "WINDOWS_SECURITY_STATUS_TIMEOUT"
ERROR_WINDOWS_POLICY_STATUS_FAILED = "WINDOWS_POLICY_STATUS_FAILED"
ERROR_WINDOWS_POLICY_STATUS_TIMEOUT = "WINDOWS_POLICY_STATUS_TIMEOUT"
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


def validate_windows_audit_options(
    *,
    windows_audit: bool,
    windows_user: str | None,
    windows_password: str | None,
    windows_auth_method: str,
    windows_host_info: bool = False,
    windows_security_status: bool = False,
    windows_policy_status: bool = False,
) -> str:
    """Validate Windows audit options without exposing credential values."""
    normalized_method = (windows_auth_method or "none").strip().lower()
    if normalized_method not in ALLOWED_AUTH_METHODS:
        allowed = ", ".join(sorted(ALLOWED_AUTH_METHODS))
        raise WindowsAuditConfigurationError(
            f"Unsupported Windows auth method '{windows_auth_method}'. Allowed values: {allowed}.",
            ERROR_INVALID_AUTH_METHOD,
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
    return normalized_method


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
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
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
    )

    service_statuses = [
        _check_service(resolved_ip, check, timeout=timeout) for check in WINDOWS_SERVICE_CHECKS
    ]
    winrm_auth = _initial_winrm_auth_result()
    if normalized_method == "winrm":
        winrm_auth = _perform_winrm_auth_check(
            target=target,
            username=str(username or ""),
            password=str(password or ""),
            domain=domain,
            service_statuses=service_statuses,
            collect_host_info=collect_host_info,
            collect_security_status=collect_security_status,
            collect_policy_status=collect_policy_status,
            timeout=timeout,
        )
    findings = _build_windows_findings(target, service_statuses)
    if normalized_method == "winrm":
        findings.append(_winrm_auth_finding(target, winrm_auth))
    if collect_host_info:
        findings.extend(_host_info_findings(target, winrm_auth))
    if collect_security_status:
        findings.extend(_security_status_findings(target, winrm_auth))
    if collect_policy_status and winrm_auth.get("authenticated"):
        findings.extend(build_windows_policy_findings(target, winrm_auth.get("policy_status") or {}))
    findings.append(_completed_finding(target, service_statuses, winrm_auth, normalized_method))
    checks_failed = sum(1 for status in service_statuses if status.get("error_code"))
    if winrm_auth["attempted"] and winrm_auth["status"] != "authenticated":
        checks_failed += 1
    if collect_host_info and winrm_auth.get("host_info_status") == "failed":
        checks_failed += 1
    if collect_security_status and winrm_auth.get("security_status_status") in {"failed", "partial"}:
        checks_failed += 1
    if collect_policy_status and winrm_auth.get("policy_status_status") in {"failed", "partial"}:
        checks_failed += 1
    status = (
        "partial"
        if (
            winrm_auth.get("authenticated")
            and (
                (collect_host_info and winrm_auth.get("host_info_status") == "failed")
                or (collect_security_status and winrm_auth.get("security_status_status") in {"failed", "partial"})
                or (collect_policy_status and winrm_auth.get("policy_status_status") in {"failed", "partial"})
            )
        )
        else _audit_status(checks_failed=checks_failed)
    )
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
        "checks_skipped": 0,
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
    timeout: float,
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
            operation_timeout_sec=max(1, int(timeout)),
            read_timeout_sec=max(2, int(timeout) + 1),
        )
        response = session.run_cmd(SAFE_WINRM_VALIDATION_COMMAND)
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
        )

    status_code = int(getattr(response, "status_code", 1) or 0)
    if status_code == 0:
        host_info_result = (
            _collect_windows_host_info(session) if collect_host_info else _initial_host_info_result(False)
        )
        security_status_result = (
            _collect_windows_security_status(session)
            if collect_security_status
            else _initial_security_status_result(False)
        )
        policy_status_result = (
            _collect_windows_policy_status(session)
            if collect_policy_status
            else _initial_policy_status_result(False)
        )
        return _winrm_auth_result(
            started=started,
            status="authenticated",
            error_code=WINRM_AUTH_SUCCESS,
            message="WinRM authentication succeeded and a safe validation command completed.",
            endpoint_used=endpoint_url,
            transport="ntlm",
            authenticated=True,
            validation_result_summary=_safe_command_summary(getattr(response, "std_out", b"")),
            limitations=limitations,
            host_info_requested=collect_host_info,
            host_info_result=host_info_result,
            security_status_requested=collect_security_status,
            security_status_result=security_status_result,
            policy_status_requested=collect_policy_status,
            policy_status_result=policy_status_result,
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
    )


def _select_winrm_endpoint(target: str, service_statuses: list[dict[str, Any]]) -> dict[str, str] | None:
    service_by_port = {int(item["port"]): item for item in service_statuses}
    if service_by_port.get(5986, {}).get("reachable"):
        return {"scheme": "https", "url": f"https://{target}:5986/wsman"}
    if service_by_port.get(5985, {}).get("reachable"):
        return {"scheme": "http", "url": f"http://{target}:5985/wsman"}
    return None


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


def _collect_windows_host_info(session: Any) -> dict[str, Any]:
    completed = 0
    try:
        hostname = _run_safe_ps(session, WINDOWS_HOST_INFO_COMMANDS["hostname"])
        completed += 1
        current_identity = _run_safe_ps(session, WINDOWS_HOST_INFO_COMMANDS["current_identity"])
        completed += 1
        powershell_version = _run_safe_ps(session, WINDOWS_HOST_INFO_COMMANDS["powershell_version"])
        completed += 1
        os_data = _json_object(_run_safe_ps(session, WINDOWS_HOST_INFO_COMMANDS["os_information"]))
        completed += 1
        computer_data = _json_object(_run_safe_ps(session, WINDOWS_HOST_INFO_COMMANDS["computer_system"]))
        completed += 1
        timezone_data = _json_object(_run_safe_ps(session, WINDOWS_HOST_INFO_COMMANDS["timezone"]))
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
            }
        )
        return result
    except Exception as exc:
        result = _initial_host_info_result(True)
        result.update(
            {
                "status": "failed",
                "error_code": ERROR_WINDOWS_HOST_INFO_FAILED,
                "error_message": "Windows host information collection failed.",
                "safe_detail": exc.__class__.__name__,
                "commands_completed": completed,
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
        }
    )
    return result


def _run_safe_ps(session: Any, command: str) -> str:
    response = session.run_ps(command)
    status_code = int(getattr(response, "status_code", 1) or 0)
    if status_code != 0:
        raise RuntimeError(f"powershell_status_{status_code}")
    return _safe_output_text(getattr(response, "std_out", b""))


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


def _collect_windows_security_status(session: Any) -> dict[str, Any]:
    completed = 0
    limitations: list[str] = []
    firewall_profiles: list[dict[str, str]] = []
    defender_service: dict[str, str] = {"status": "", "start_type": ""}
    defender_status = dict(EMPTY_WINDOWS_SECURITY_STATUS["defender_status"])

    try:
        firewall_profiles = _firewall_profiles_from_output(
            _run_safe_ps(session, WINDOWS_SECURITY_STATUS_COMMANDS["firewall_profiles"])
        )
        completed += 1
    except TimeoutError as exc:
        return _security_status_error(ERROR_WINDOWS_SECURITY_STATUS_TIMEOUT, exc, completed)
    except Exception as exc:
        limitations.append(f"Firewall profile status unavailable: {exc.__class__.__name__}.")

    try:
        defender_service = _defender_service_from_output(
            _run_safe_ps(session, WINDOWS_SECURITY_STATUS_COMMANDS["defender_service"])
        )
        completed += 1
    except TimeoutError as exc:
        return _security_status_error(ERROR_WINDOWS_SECURITY_STATUS_TIMEOUT, exc, completed)
    except Exception as exc:
        limitations.append(f"Defender service status unavailable: {exc.__class__.__name__}.")

    try:
        defender_status = _defender_status_from_output(
            _run_safe_ps(session, WINDOWS_SECURITY_STATUS_COMMANDS["defender_status"])
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


def _collect_windows_policy_status(session: Any) -> dict[str, Any]:
    completed = 0
    try:
        output = _run_safe_cmd(session, NET_ACCOUNTS_COMMAND)
        completed += 1
    except TimeoutError as exc:
        return _policy_status_error(ERROR_WINDOWS_POLICY_STATUS_TIMEOUT, exc, completed)
    except Exception as exc:
        return _policy_status_error(ERROR_WINDOWS_POLICY_STATUS_FAILED, exc, completed)

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
        }
    )
    return result


def _run_safe_cmd(session: Any, command: str) -> str:
    if command == NET_ACCOUNTS_COMMAND:
        try:
            response = session.run_cmd("net", ["accounts"])
        except TypeError:
            response = session.run_cmd(command)
    else:
        response = session.run_cmd(command)
    status_code = int(getattr(response, "status_code", 1) or 0)
    if status_code != 0:
        raise RuntimeError(f"command_status_{status_code}")
    return _safe_multiline_output_text(getattr(response, "std_out", b""))


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
) -> dict[str, Any]:
    host_result = host_info_result or _initial_host_info_result(host_info_requested)
    security_result = security_status_result or _initial_security_status_result(security_status_requested)
    policy_result = policy_status_result or _initial_policy_status_result(policy_status_requested)
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
    return create_finding(
        title=title,
        severity=severity,  # type: ignore[arg-type]
        category=category,
        affected_host=target,
        affected_port=port,
        service=service,
        evidence=str(status["evidence"]),
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
        return create_finding(
            title="WinRM Authentication Successful",
            severity="Informational",
            category="Windows Credentialed Access",
            affected_host=target,
            service="winrm",
            evidence="WinRM authentication succeeded and a safe read-only validation command completed.",
            confidence="High",
            impact="Credentialed Windows auditing can be performed in later versions.",
            recommendation="Use least-privilege accounts and restrict WinRM to trusted networks.",
            verification="Re-run VulScan WinRM authentication check with authorised credentials.",
            limitation="Authentication success does not indicate vulnerability.",
            source=SOURCE,
        )
    if status == "not_reachable":
        return create_finding(
            title="WinRM Not Reachable",
            severity="Informational",
            category="Windows Remote Management",
            affected_host=target,
            service="winrm",
            evidence="TCP connection to 5985 and 5986 failed or WinRM endpoint unavailable.",
            confidence="High",
            impact="WinRM authentication could not be validated because WinRM was not reachable.",
            recommendation="Verify WinRM is enabled and reachable only if required.",
            verification="Re-run VulScan after confirming authorised WinRM network access.",
            limitation="Unreachable WinRM may be expected in hardened environments.",
            source=SOURCE,
        )
    if status == "dependency_missing":
        return create_finding(
            title="WinRM Dependency Missing",
            severity="Informational",
            category="Tool Configuration",
            affected_host=target,
            service="winrm",
            evidence="pywinrm is not installed.",
            confidence="High",
            impact="VulScan cannot perform WinRM authentication checks without pywinrm.",
            recommendation="Install pywinrm in the VulScan virtual environment to enable WinRM authentication checks.",
            verification="Install pywinrm and re-run VulScan with --windows-auth-method winrm.",
            limitation="VulScan cannot perform WinRM authentication without this dependency.",
            source=SOURCE,
        )
    return create_finding(
        title="WinRM Authentication Failed",
        severity="Informational",
        category="Windows Credentialed Access",
        affected_host=target,
        service="winrm",
        evidence="WinRM authentication attempt failed.",
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
        findings.append(
            create_finding(
                title="Windows Host Information Collected",
                severity="Informational",
                category="Windows Host Information",
                affected_host=target,
                service="winrm",
                evidence="Basic Windows host information collected using read-only WinRM commands.",
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
            findings.append(
                create_finding(
                    title="Windows System Appears Domain Joined",
                    severity="Informational",
                    category="Windows Host Information",
                    affected_host=target,
                    service="winrm",
                    evidence="PartOfDomain is true and a domain value was reported.",
                    confidence="Medium",
                    impact="Domain context may affect interpretation of future Windows policy checks.",
                    recommendation="Consider domain policy context when interpreting future local policy checks.",
                    verification="Re-run VulScan with --windows-host-info.",
                    limitation="Domain membership does not indicate insecure configuration.",
                    source=SOURCE,
                )
            )
        elif part_of_domain == "false" or host_info.get("workgroup"):
            findings.append(
                create_finding(
                    title="Windows System Appears Workgroup Joined",
                    severity="Informational",
                    category="Windows Host Information",
                    affected_host=target,
                    service="winrm",
                    evidence="PartOfDomain is false or a workgroup value was reported.",
                    confidence="Medium",
                    impact="Local security configuration may be more important when domain policy does not apply.",
                    recommendation="Review local security configuration directly because domain policy may not apply.",
                    verification="Re-run VulScan with --windows-host-info.",
                    limitation="Workgroup membership does not indicate vulnerability.",
                    source=SOURCE,
                )
            )
        return findings

    return [
        create_finding(
            title="Windows Host Information Collection Failed",
            severity="Informational",
            category="Windows Host Information",
            affected_host=target,
            service="winrm",
            evidence="Safe read-only host information command failed or returned incomplete data.",
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
        findings.append(
            create_finding(
                title="Windows Firewall Profile Disabled",
                severity="Medium",
                category="Windows Firewall",
                affected_host=target,
                service="winrm",
                evidence="One or more Windows Firewall profiles reported Enabled=False.",
                confidence="Medium",
                impact="Disabled firewall profiles may allow unwanted inbound network access.",
                recommendation="Enable Windows Firewall profiles unless a documented compensating control exists.",
                verification="Run Get-NetFirewallProfile and review Enabled state.",
                limitation="Domain policy or third-party firewall controls may affect interpretation.",
                source=SECURITY_SOURCE,
            )
        )
    if firewall_profiles:
        findings.append(
            create_finding(
                title="Windows Firewall Status Reviewed",
                severity="Informational",
                category="Windows Firewall",
                affected_host=target,
                service="winrm",
                evidence="Firewall profile status was collected using read-only PowerShell.",
                confidence="High",
                impact="Firewall status supports host exposure review.",
                recommendation="Review firewall profile settings according to organisational policy.",
                verification="Run Get-NetFirewallProfile.",
                limitation="This check does not enumerate individual firewall rules.",
                source=SECURITY_SOURCE,
            )
        )

    if defender_service and str(defender_service.get("status") or "").lower() not in {"", "running"}:
        findings.append(
            create_finding(
                title="Microsoft Defender Service Not Running",
                severity="Medium",
                category="Endpoint Protection",
                affected_host=target,
                service="windefend",
                evidence="WinDefend service status is not Running.",
                confidence="Medium",
                impact="Endpoint protection may not be active.",
                recommendation="Verify Microsoft Defender or approved alternative endpoint protection is active.",
                verification="Run Get-Service WinDefend.",
                limitation="Third-party antivirus may be used instead of Defender.",
                source=SECURITY_SOURCE,
            )
        )
    if str(defender_status.get("real_time_protection_enabled") or "").lower() == "false":
        findings.append(
            create_finding(
                title="Microsoft Defender Real-Time Protection Disabled",
                severity="High",
                category="Endpoint Protection",
                affected_host=target,
                service="defender",
                evidence="RealTimeProtectionEnabled=False from Get-MpComputerStatus.",
                confidence="Medium",
                impact="Malware protection may be reduced.",
                recommendation="Enable real-time protection or verify approved compensating controls.",
                verification="Run Get-MpComputerStatus and check RealTimeProtectionEnabled.",
                limitation="Some enterprise policies or third-party EDR solutions may change Defender behaviour.",
                source=SECURITY_SOURCE,
            )
        )
    if any(defender_status.values()):
        findings.append(
            create_finding(
                title="Microsoft Defender Status Reviewed",
                severity="Informational",
                category="Endpoint Protection",
                affected_host=target,
                service="defender",
                evidence="Defender status was collected using read-only PowerShell.",
                confidence="High",
                impact="Endpoint protection status supports security posture review.",
                recommendation="Review Defender/EDR posture according to organisational policy.",
                verification="Run Get-MpComputerStatus.",
                limitation="Get-MpComputerStatus may be unavailable or restricted on some systems.",
                source=SECURITY_SOURCE,
            )
        )
    if winrm_auth.get("security_status_status") == "failed" or security_status.get("security_status_limitations"):
        findings.append(
            create_finding(
                title="Windows Security Status Collection Failed",
                severity="Informational",
                category="Windows Security Status",
                affected_host=target,
                service="winrm",
                evidence="One or more read-only Windows security status commands failed or returned incomplete data.",
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
        return create_finding(
            title="Windows WinRM Authentication Check Completed",
            severity="Informational",
            category="Windows Audit",
            affected_host=target,
            evidence=f"WinRM authentication check completed with status: {winrm_auth.get('status')}.",
            confidence="High",
            impact="A safe single-attempt WinRM authentication validation was completed.",
            recommendation="Use later authenticated Windows audit modules for deeper read-only checks.",
            verification="Re-run VulScan with --windows-audit --windows-auth-method winrm.",
            limitation="Version 12.2 validates authentication and optionally collects basic host information only; it does not run deep Windows enumeration.",
            source=SOURCE,
        )

    reachable = [f"{item['service']}:{item['port']}" for item in service_statuses if item.get("reachable")]
    observed = ", ".join(reachable) if reachable else "no Windows management services reachable"
    return create_finding(
        title="Windows Audit Foundation Completed",
        severity="Informational",
        category="Windows Audit",
        affected_host=target,
        evidence=f"Windows service reachability checks completed; {observed}.",
        confidence="High",
        impact="Foundation-level Windows service exposure indicators were collected.",
        recommendation="Use authenticated Windows audit in later versions for deeper checks.",
        verification="Re-run VulScan with --windows-audit.",
        limitation="Version 12.2 performs foundation-level reachability checks unless WinRM authentication or host information collection is explicitly requested.",
        source=SOURCE,
    )


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
) -> dict[str, Any]:
    service_by_port = {int(item["port"]): item for item in service_statuses}
    checks_completed = (
        len(service_statuses)
        + (1 if winrm_auth.get("attempted") else 0)
        + int(winrm_auth.get("host_info_commands_completed") or 0)
        + int(winrm_auth.get("security_status_commands_completed") or 0)
        + int(winrm_auth.get("policy_status_commands_completed") or 0)
    )
    limitations = [
        "Version 12.5 performs socket reachability checks, one safe WinRM authentication validation when requested, optional read-only host information collection, optional read-only firewall and Defender status collection, and optional net accounts local security policy indicators.",
        "It does not enumerate shares, query the registry, export security policy, list users, list groups, list files, list processes, dump credentials, change password or lockout policy, change firewall or Defender settings, exploit, brute force, or modify systems.",
    ]
    if winrm_auth.get("limitations"):
        limitations.append(str(winrm_auth["limitations"]))
    return {
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
        "checks_skipped": 0,
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
        "limitations": limitations,
    }


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
        checks_skipped=0,
        findings=[finding_to_dict(finding) for finding in findings],
        summary=credentialed_summary,
        errors=errors,
        limitations=list(summary["limitations"]),
        performance={
            "duration_seconds": duration_seconds,
            "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
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
