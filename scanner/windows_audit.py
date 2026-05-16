"""Windows SMB/WinRM audit foundation checks."""

from __future__ import annotations

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
MODULE_NAME = "Windows SMB/WinRM Audit Foundation"
PROFILE = "foundation"
ALLOWED_AUTH_METHODS = {"none", "smb", "winrm"}
DEFAULT_TIMEOUT_SECONDS = 2.0

ERROR_INVALID_AUTH_METHOD = "WINDOWS_AUTH_METHOD_INVALID"
ERROR_PASSWORD_WITHOUT_USERNAME = "WINDOWS_PASSWORD_WITHOUT_USERNAME"
ERROR_SERVICE_CHECK_FAILED = "WINDOWS_AUDIT_SERVICE_CHECK_FAILED"

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
        return normalized_method
    if windows_password and not (windows_user and windows_user.strip()):
        raise WindowsAuditConfigurationError(
            "Windows password was provided without --windows-user.",
            ERROR_PASSWORD_WITHOUT_USERNAME,
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
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Run safe Windows service reachability checks only."""
    started = perf_counter()
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    normalized_method = validate_windows_audit_options(
        windows_audit=True,
        windows_user=username,
        windows_password=password,
        windows_auth_method=auth_method,
    )

    service_statuses = [
        _check_service(resolved_ip, check, timeout=timeout) for check in WINDOWS_SERVICE_CHECKS
    ]
    findings = _build_windows_findings(target, service_statuses)
    findings.append(_foundation_completed_finding(target, service_statuses))
    checks_failed = sum(1 for status in service_statuses if status.get("error_code"))
    status = "partial" if checks_failed else "success"
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
    summary = _build_summary(
        target=target,
        username=username,
        domain=domain,
        auth_method=normalized_method,
        service_statuses=service_statuses,
        status=status,
        checks_failed=checks_failed,
        findings_count=len(findings),
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
        "module_name": MODULE_NAME,
        "status": status,
        "target": target,
        "authenticated": summary["authenticated"],
        "auth_method": normalized_method,
        "domain": domain or "",
        "username_used": username or "",
        "service_statuses": service_statuses,
        "checks_completed": len(service_statuses),
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


def _foundation_completed_finding(target: str, service_statuses: list[dict[str, Any]]) -> Finding:
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
        limitation="Version 12.0 performs foundation-level reachability checks only.",
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
) -> dict[str, Any]:
    service_by_port = {int(item["port"]): item for item in service_statuses}
    return {
        "enabled": True,
        "status": status,
        "target": target,
        "authenticated": _authentication_state(auth_method, username),
        "auth_method": auth_method,
        "domain": domain or "",
        "username_used": username or "",
        "smb_reachable": bool(service_by_port.get(445, {}).get("reachable")),
        "netbios_smb_reachable": bool(service_by_port.get(139, {}).get("reachable")),
        "winrm_http_reachable": bool(service_by_port.get(5985, {}).get("reachable")),
        "winrm_https_reachable": bool(service_by_port.get(5986, {}).get("reachable")),
        "rdp_reachable": bool(service_by_port.get(3389, {}).get("reachable")),
        "service_statuses": service_statuses,
        "checks_completed": len(service_statuses),
        "checks_failed": checks_failed,
        "checks_skipped": 0,
        "findings_count": findings_count,
        "highest_windows_risk_score": 0,
        "highest_windows_risk_label": "Informational",
        "limitations": (
            "Version 12.0 performs socket reachability checks only. It does not authenticate, enumerate shares, "
            "exploit, brute force, dump credentials, or modify systems."
        ),
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
    audit = CredentialedAuditResult(
        source=SOURCE,
        module_name=MODULE_NAME,
        status=status,
        target=target,
        authenticated=False,
        auth_method=auth_method,
        username=username or "",
        profile=PROFILE,
        started_at=started_at,
        ended_at=ended_at,
        duration_seconds=duration_seconds,
        checks_planned=len(service_statuses),
        checks_completed=len(service_statuses),
        checks_failed=len(errors),
        checks_skipped=0,
        findings=[finding_to_dict(finding) for finding in findings],
        summary=summary,
        errors=errors,
        limitations=[summary["limitations"]],
        performance={"duration_seconds": duration_seconds, "timeout_seconds": DEFAULT_TIMEOUT_SECONDS},
        metadata={
            "domain": domain or "",
            "service_statuses": service_statuses,
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
