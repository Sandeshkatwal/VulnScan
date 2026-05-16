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


SOURCE = "windows_audit"
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

ERROR_INVALID_AUTH_METHOD = "WINDOWS_AUTH_METHOD_INVALID"
ERROR_PASSWORD_WITHOUT_USERNAME = "WINDOWS_PASSWORD_WITHOUT_USERNAME"
ERROR_WINRM_CREDENTIALS_MISSING = "WINRM_CREDENTIALS_MISSING"
ERROR_WINDOWS_HOST_INFO_PREREQUISITES = "WINDOWS_HOST_INFO_PREREQUISITES_MISSING"
ERROR_SERVICE_CHECK_FAILED = "WINDOWS_AUDIT_SERVICE_CHECK_FAILED"
ERROR_WINDOWS_HOST_INFO_FAILED = "WINDOWS_HOST_INFO_FAILED"
ERROR_WINDOWS_HOST_INFO_TIMEOUT = "WINDOWS_HOST_INFO_TIMEOUT"
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
            timeout=timeout,
        )
    findings = _build_windows_findings(target, service_statuses)
    if normalized_method == "winrm":
        findings.append(_winrm_auth_finding(target, winrm_auth))
    if collect_host_info:
        findings.extend(_host_info_findings(target, winrm_auth))
    findings.append(_completed_finding(target, service_statuses, winrm_auth, normalized_method))
    checks_failed = sum(1 for status in service_statuses if status.get("error_code"))
    if winrm_auth["attempted"] and winrm_auth["status"] != "authenticated":
        checks_failed += 1
    if collect_host_info and winrm_auth.get("host_info_status") == "failed":
        checks_failed += 1
    status = (
        "partial"
        if collect_host_info and winrm_auth.get("authenticated") and winrm_auth.get("host_info_status") == "failed"
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
    }


def _perform_winrm_auth_check(
    *,
    target: str,
    username: str,
    password: str,
    domain: str | None,
    service_statuses: list[dict[str, Any]],
    collect_host_info: bool,
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
        )

    status_code = int(getattr(response, "status_code", 1) or 0)
    if status_code == 0:
        host_info_result = (
            _collect_windows_host_info(session) if collect_host_info else _initial_host_info_result(False)
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
    if not value:
        return {}
    parsed = json.loads(value)
    if isinstance(parsed, list):
        first = parsed[0] if parsed else {}
        return first if isinstance(first, dict) else {}
    return parsed if isinstance(parsed, dict) else {}


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
) -> dict[str, Any]:
    host_result = host_info_result or _initial_host_info_result(host_info_requested)
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
    )
    limitations = [
        "Version 12.2 performs socket reachability checks, one safe WinRM authentication validation when requested, and optional read-only host information collection.",
        "It does not enumerate shares, query the registry, query security policy, list users, list groups, list files, list processes, dump credentials, exploit, brute force, or modify systems.",
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
    domain_or_workgroup = host_info.get("domain") or host_info.get("workgroup") or ""
    credentialed_summary = dict(summary)
    credentialed_summary.update(
        {
            "hostname": host_info.get("hostname") or "",
            "os_caption": host_info.get("os_caption") or "",
            "os_version": host_info.get("os_version") or "",
            "os_build": host_info.get("os_build") or "",
            "domain_or_workgroup": domain_or_workgroup,
            "powershell_version": host_info.get("powershell_version") or "",
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
