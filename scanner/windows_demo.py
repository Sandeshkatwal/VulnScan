"""Safe fake Windows audit demo data."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from scanner.credentialed_result import CredentialedAuditResult, CredentialedCheckResult
from scanner.finding import Finding, create_finding, finding_to_dict
from scanner.windows_result import build_windows_audit_sections


SOURCE = "windows_demo"
DEMO_NOTICE = "Demo data only. No real target was scanned."


def build_windows_demo_result(
    *,
    target: str,
    profile_summary: dict[str, Any],
    audit_timeout_seconds: float,
) -> dict[str, Any]:
    """Build a Windows audit result using fake sample data only."""
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    ended_at = started_at
    host_info = _demo_host_info()
    security_status = _demo_security_status()
    patch_status = _demo_patch_status()
    policy_status = _demo_policy_status()
    registry_audit = _demo_registry_audit()
    service_statuses = _demo_service_statuses(target)
    findings = _demo_findings(target)
    sections = _demo_legacy_sections()
    summary = {
        "enabled": True,
        "status": "success",
        "target": target,
        "demo_mode": True,
        "demo_notice": DEMO_NOTICE,
        "authenticated": False,
        "auth_method": "demo",
        "domain": "",
        "username_used": "",
        "smb_reachable": True,
        "netbios_smb_reachable": False,
        "winrm_http_reachable": True,
        "winrm_https_reachable": False,
        "rdp_reachable": True,
        "service_statuses": service_statuses,
        "checks_completed": 18,
        "checks_failed": 0,
        "checks_skipped": 0,
        "findings_count": len(findings),
        "highest_windows_risk_score": 0,
        "highest_windows_risk_label": "Informational",
        "winrm_auth_attempted": False,
        "winrm_auth_status": "demo",
        "winrm_error_code": "",
        "winrm_endpoint_used": "demo://winrm",
        "winrm_transport": "demo",
        "winrm_authenticated": False,
        "safe_validation_command": "demo-data",
        "validation_result_summary": DEMO_NOTICE,
        "winrm_auth_duration_seconds": 0.0,
        "windows_host_info_collected": True,
        "windows_host_info": host_info,
        "windows_host_info_status": "collected",
        "windows_security_status_checked": True,
        "windows_security_status": security_status,
        "windows_security_status_status": "checked",
        "windows_patch_status_checked": True,
        "windows_patch_status": patch_status,
        "windows_patch_status_status": "checked",
        "windows_policy_status_checked": True,
        "windows_policy_status": policy_status,
        "windows_policy_status_status": "checked",
        "windows_registry_audit_checked": True,
        "windows_registry_audit": registry_audit,
        "windows_registry_audit_status": "checked",
        "connection_timeout_seconds": 0.0,
        "command_timeout_seconds": 0.0,
        "audit_timeout_seconds": float(audit_timeout_seconds),
        "total_duration_seconds": 0.0,
        "sections": sections,
        "sections_planned": len(sections),
        "sections_completed": len(sections),
        "sections_failed": 0,
        "sections_skipped": 0,
        "checks_planned": 18,
        "timed_out_commands": 0,
        "slowest_command_name": "demo-data",
        "slowest_command_duration_seconds": 0.0,
        "performance_notes": ["Demo mode does not connect to a network target."],
        "limitations": [
            DEMO_NOTICE,
            "Demo reports are for screenshots, report validation, and portfolio use only.",
        ],
        **profile_summary,
    }
    credentialed_audit = _demo_credentialed_audit(
        target=target,
        started_at=started_at,
        ended_at=ended_at,
        findings=findings,
        summary=summary,
    )
    result = {
        "enabled": True,
        "source": SOURCE,
        "module_name": "Windows Audit Demo Mode",
        "status": "success",
        "target": target,
        "demo_mode": True,
        "demo_notice": DEMO_NOTICE,
        "authenticated": False,
        "auth_method": "demo",
        "domain": "",
        "username_used": "",
        "started_at": started_at,
        "ended_at": ended_at,
        "service_statuses": service_statuses,
        "checks_completed": summary["checks_completed"],
        "checks_failed": 0,
        "checks_skipped": 0,
        "findings": findings,
        "summary": summary,
        "credentialed_audit": credentialed_audit,
        "errors": [],
        "duration_seconds": 0.0,
    }
    result["windows_audit_sections"] = build_windows_audit_sections(windows_result=result)
    return result


def build_demo_scan_result(target: str) -> dict[str, Any]:
    return {
        "host": target,
        "resolved_ip": "demo-data",
        "duration_seconds": 0.0,
        "open_ports": [],
        "demo_mode": True,
        "demo_notice": DEMO_NOTICE,
    }


def _demo_host_info() -> dict[str, Any]:
    return {
        "hostname": "WIN-DEMO-01",
        "current_identity": "WORKGROUP\\demo-auditor",
        "powershell_version": "5.1",
        "os_caption": "Microsoft Windows 11 Pro",
        "os_version": "10.0.22631",
        "os_build": "22631",
        "os_architecture": "64-bit",
        "last_boot_time": "2026-05-10T09:15:00Z",
        "install_date": "2025-11-01T12:00:00Z",
        "domain": "",
        "workgroup": "WORKGROUP",
        "part_of_domain": "False",
        "manufacturer": "Demo Manufacturer",
        "model": "Demo Workstation",
        "timezone_id": "GMT Standard Time",
        "timezone_display_name": "GMT Standard Time",
    }


def _demo_service_statuses(target: str) -> list[dict[str, Any]]:
    rows = [
        (445, "SMB", True),
        (139, "NetBIOS/SMB", False),
        (5985, "WinRM HTTP", True),
        (5986, "WinRM HTTPS", False),
        (3389, "RDP", True),
    ]
    return [
        {
            "host": target,
            "port": port,
            "service": service,
            "reachable": reachable,
            "evidence": f"Demo TCP connection to port {port} marked {'reachable' if reachable else 'not reachable'}.",
            "recommendation": "Demo data only. Validate real exposure with an authorised scan.",
            "limitation": DEMO_NOTICE,
            "duration_seconds": 0.0,
        }
        for port, service, reachable in rows
    ]


def _demo_security_status() -> dict[str, Any]:
    return {
        "firewall_profiles": [
            {"name": "Domain", "enabled": "True", "default_inbound_action": "Block", "default_outbound_action": "Allow"},
            {"name": "Private", "enabled": "True", "default_inbound_action": "Block", "default_outbound_action": "Allow"},
            {"name": "Public", "enabled": "False", "default_inbound_action": "Allow", "default_outbound_action": "Allow"},
        ],
        "defender_service": {"status": "Running", "start_type": "Automatic"},
        "defender_status": {
            "am_service_enabled": "True",
            "antispyware_enabled": "True",
            "antivirus_enabled": "True",
            "real_time_protection_enabled": "True",
            "behavior_monitor_enabled": "True",
            "ioav_protection_enabled": "True",
            "nis_enabled": "True",
            "antivirus_signature_last_updated": "2026-05-15T08:30:00Z",
            "antispyware_signature_last_updated": "2026-05-15T08:30:00Z",
        },
        "security_status_limitations": [DEMO_NOTICE],
    }


def _demo_patch_status() -> dict[str, Any]:
    return {
        "windows_update_service": "Running",
        "bits_service": "Running",
        "hotfix_count": 42,
        "most_recent_hotfix_date": "2026-05-14",
        "pending_reboot_detected": False,
        "limitations": [DEMO_NOTICE],
    }


def _demo_policy_status() -> dict[str, Any]:
    return {
        "checked": True,
        "source_command": "demo-data",
        "minimum_password_age_days": 0,
        "maximum_password_age_days": 99999,
        "minimum_password_length": 8,
        "password_history_length": 0,
        "lockout_threshold": 0,
        "lockout_duration_minutes": None,
        "lockout_observation_window_minutes": None,
        "force_logoff": "Never",
        "computer_role": "WORKSTATION",
        "domain_policy_context_note": "Demo data only.",
        "limitations": [DEMO_NOTICE],
    }


def _demo_registry_audit() -> dict[str, Any]:
    return {
        "template_name": "Demo Windows Registry Audit Template",
        "template_version": "demo",
        "template_path": "demo-data",
        "checks_total": 3,
        "checks_executed": 3,
        "checks_failed": 1,
        "checks_skipped": 0,
        "checks_passed": 2,
        "checks_with_findings": 1,
        "check_results": [
            _registry_result("WIN-REG-RDP-NLA", "Remote Desktop NLA Setting Indicator", "failed", "Terminal Server\\WinStations\\RDP-Tcp", "UserAuthentication", "0", "1", True),
            _registry_result("WIN-REG-SMBV1", "SMBv1 Disabled", "passed", "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "SMB1", "0", "0", False),
            _registry_result("WIN-REG-WDIGEST", "WDigest UseLogonCredential Disabled", "passed", "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", "UseLogonCredential", "0", "0", False),
        ],
        "limitations": [DEMO_NOTICE],
    }


def _registry_result(
    check_id: str,
    title: str,
    status: str,
    path: str,
    value_name: str,
    observed: str,
    expected: str,
    finding_created: bool,
) -> dict[str, Any]:
    return {
        "id": check_id,
        "title": title,
        "status": status,
        "hive": "HKLM",
        "path": path,
        "value_name": value_name,
        "observed_value": observed,
        "expected_value": expected,
        "operator": "equals",
        "finding_created": finding_created,
        "evidence_summary": f"Demo registry value {value_name} observed {observed}; expected {expected}.",
        "limitation": DEMO_NOTICE,
        "severity": "Medium" if finding_created else "Informational",
        "category": "Windows Registry Audit",
        "recommendation": "Use demo mode for report validation only.",
        "error_code": "",
    }


def _demo_legacy_sections() -> dict[str, dict[str, Any]]:
    return {
        "service_reachability": _section("success", 5, 5, 0, 0, "Demo service reachability data."),
        "winrm_authentication": _section("success", 1, 1, 0, 0, "Demo WinRM authentication data."),
        "host_information": _section("success", 6, 6, 0, 0, "Demo host information data."),
        "security_status": _section("success", 3, 3, 0, 0, "Demo Firewall and Defender status data."),
        "patch_status": _section("success", 3, 3, 0, 0, "Demo patch status data."),
        "local_security_policy": _section("success", 1, 1, 0, 0, "Demo local security policy data."),
        "registry_audit": _section("success", 3, 3, 0, 0, "Demo registry audit data."),
    }


def _section(status: str, planned: int, completed: int, failed: int, skipped: int, limitation: str) -> dict[str, Any]:
    return {
        "status": status,
        "checks_planned": planned,
        "checks_completed": completed,
        "checks_failed": failed,
        "checks_skipped": skipped,
        "duration_seconds": 0.0,
        "error_code": "",
        "limitation": limitation,
    }


def _demo_findings(target: str) -> list[Finding]:
    return [
        create_finding(
            title="Demo Mode Notice",
            severity="Informational",
            category="Demo",
            affected_host=target,
            service="windows-demo",
            evidence="Demo mode was used. No real target was scanned.",
            confidence="High",
            impact="Demo results do not represent a real system.",
            recommendation="Use demo mode for screenshots and report validation only.",
            verification="Review command line for --windows-demo.",
            limitation="Demo results do not represent a real system.",
            source=SOURCE,
        ),
        create_finding(
            title="Windows Firewall Public Profile Disabled",
            severity="Medium",
            category="Windows Security Status",
            affected_host=target,
            service="winrm",
            evidence="Demo firewall Public profile observed Enabled=False; expected Enabled=True.",
            confidence="High",
            impact="A disabled public firewall profile can increase exposure on untrusted networks.",
            recommendation="Enable Windows Firewall for the Public profile where appropriate.",
            verification="Review Windows Firewall profile settings on the real host.",
            limitation=DEMO_NOTICE,
            source="windows_security_audit",
        ),
        create_finding(
            title="RDP Service Reachable",
            severity="Medium",
            category="Windows Service Reachability",
            affected_host=target,
            affected_port=3389,
            service="rdp",
            evidence="Demo TCP connection to port 3389 marked reachable.",
            confidence="High",
            impact="Reachable RDP should be restricted to trusted networks.",
            recommendation="Restrict RDP exposure using firewall rules, VPN, or trusted management networks.",
            verification="Run an authorised scan against the real target.",
            limitation=DEMO_NOTICE,
            source="windows_audit",
        ),
        create_finding(
            title="Windows Minimum Password Length May Be Weak",
            severity="Medium",
            category="Windows Local Security Policy",
            affected_host=target,
            service="winrm",
            evidence="Demo minimum password length observed 8; expected at least 12.",
            confidence="High",
            impact="Shorter passwords can reduce resistance to guessing or cracking.",
            recommendation="Set minimum password length to at least 12 or according to organisational policy.",
            verification="Review real policy with authorised administrative tools.",
            limitation=DEMO_NOTICE,
            source="windows_policy_audit",
        ),
        create_finding(
            title="Windows Account Lockout Threshold Not Configured",
            severity="Medium",
            category="Windows Local Security Policy",
            affected_host=target,
            service="winrm",
            evidence="Demo lockout threshold observed 0; expected a configured threshold.",
            confidence="High",
            impact="Accounts may be more exposed to repeated password attempts.",
            recommendation="Configure account lockout policy according to organisational policy.",
            verification="Review real policy with authorised administrative tools.",
            limitation=DEMO_NOTICE,
            source="windows_policy_audit",
        ),
        create_finding(
            title="Remote Desktop NLA Setting Indicator",
            severity="Medium",
            category="Windows Registry Audit",
            affected_host=target,
            service="winrm",
            evidence="Demo registry value UserAuthentication observed 0; expected 1.",
            confidence="High",
            impact="RDP without NLA can increase remote access risk.",
            recommendation="Require Network Level Authentication for Remote Desktop where appropriate.",
            verification="Review the real registry value and RDP configuration on the authorised host.",
            limitation=DEMO_NOTICE,
            source="windows_registry_audit",
        ),
    ]


def _demo_credentialed_audit(
    *,
    target: str,
    started_at: str,
    ended_at: str,
    findings: list[Finding],
    summary: dict[str, Any],
) -> dict[str, Any]:
    checks = [
        CredentialedCheckResult(
            check_id="windows-demo-data",
            check_name="Windows audit demo data",
            source=SOURCE,
            status="success",
            command_name="demo-data",
            duration_seconds=0.0,
            findings_count=len(findings),
            evidence_summary=DEMO_NOTICE,
        ).to_dict()
    ]
    return CredentialedAuditResult(
        source=SOURCE,
        module_name="Windows Audit Demo Mode",
        status="success",
        target=target,
        authenticated=False,
        auth_method="demo",
        username="",
        profile=str(summary.get("windows_audit_profile") or "demo"),
        started_at=started_at,
        ended_at=ended_at,
        duration_seconds=0.0,
        checks_planned=1,
        checks_completed=1,
        checks_failed=0,
        checks_skipped=0,
        findings=[finding_to_dict(finding) for finding in findings],
        summary=summary,
        errors=[],
        limitations=[DEMO_NOTICE],
        performance={"duration_seconds": 0.0},
        metadata={"checks": checks, "demo_mode": True, "demo_notice": DEMO_NOTICE},
    ).to_dict()
