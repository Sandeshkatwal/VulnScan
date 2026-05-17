from datetime import datetime, timezone

from scanner.report_html import save_html_report


def test_html_report_renders_credentialed_audit_modules(tmp_path) -> None:
    scan_result = {
        "host": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "scan_mode": "safe",
        "duration_seconds": 0.1,
        "open_ports": [],
        "findings": [],
        "http_findings": [],
        "tls_findings": [],
        "ssh_findings": [],
        "windows_findings": [],
        "ssh_audit": {"enabled": True, "status": "success"},
        "ssh_audit_summary": {"enabled": True, "status": "success"},
        "windows_audit_summary": {
            "enabled": True,
            "status": "success",
            "auth_method": "winrm",
            "username_used": "auditor",
            "domain": "WORKGROUP",
            "smb_reachable": False,
            "winrm_http_reachable": True,
            "winrm_https_reachable": False,
            "rdp_reachable": False,
            "winrm_auth_attempted": True,
            "winrm_auth_status": "authenticated",
            "winrm_error_code": "WINRM_AUTH_SUCCESS",
            "winrm_endpoint_used": "http://127.0.0.1:5985/wsman",
            "winrm_transport": "ntlm",
            "safe_validation_command": "hostname",
            "validation_result_summary": "LABHOST",
            "windows_host_info_collected": True,
            "windows_host_info_status": "collected",
            "windows_host_info": {
                "hostname": "LABHOST",
                "current_identity": "workgroup\\auditor",
                "os_caption": "Microsoft Windows Server 2022 Standard",
                "os_version": "10.0.20348",
                "os_build": "20348",
                "os_architecture": "64-bit",
                "domain": "WORKGROUP",
                "workgroup": "",
                "powershell_version": "5.1",
                "last_boot_time": "2026-05-16T09:00:00Z",
                "timezone_display_name": "GMT Standard Time",
            },
            "windows_security_status_checked": True,
            "windows_security_status_status": "checked",
            "windows_security_status": {
                "firewall_profiles": [
                    {
                        "name": "Domain",
                        "enabled": "True",
                        "default_inbound_action": "Block",
                        "default_outbound_action": "Allow",
                    }
                ],
                "defender_service": {"status": "Running", "start_type": "Automatic"},
                "defender_status": {
                    "real_time_protection_enabled": "True",
                    "antivirus_enabled": "True",
                    "am_service_enabled": "True",
                    "antivirus_signature_last_updated": "2026-05-15T10:00:00Z",
                    "antispyware_signature_last_updated": "2026-05-15T10:00:00Z",
                },
                "security_status_limitations": [],
            },
            "findings_count": 1,
            "highest_windows_risk_score": 0,
            "highest_windows_risk_label": "Informational",
            "limitations": ["Validation only."],
        },
        "credentialed_audits": [
            {
                "source": "ssh_audit",
                "module_name": "Authenticated SSH Audit",
                "status": "success",
                "target": "127.0.0.1",
                "authenticated": True,
                "auth_method": "password",
                "username": "sadmin",
                "profile": "standard",
                "duration_seconds": 1.0,
                "checks_completed": 1,
                "checks_failed": 0,
                "checks_skipped": 0,
                "findings": [],
            },
            {
                "source": "windows_audit",
                "module_name": "Windows WinRM Authentication Check",
                "status": "success",
                "target": "127.0.0.1",
                "authenticated": True,
                "auth_method": "winrm",
                "username": "auditor",
                "profile": "foundation",
                "duration_seconds": 1.0,
                "checks_completed": 6,
                "checks_failed": 0,
                "checks_skipped": 0,
                "findings": [],
            }
        ],
    }

    path = save_html_report(
        scan_result=scan_result,
        scanner_name="VulScan",
        scanner_version="test",
        scan_start_time=datetime.now(timezone.utc),
        scan_end_time=datetime.now(timezone.utc),
        reports_dir=tmp_path,
    )

    html = path.read_text(encoding="utf-8")

    assert "Credentialed Audit Modules" in html
    assert "Authenticated SSH Audit" in html
    assert "Windows WinRM Authentication Check" in html
    assert "LABHOST" in html
    assert "Microsoft Windows Server 2022 Standard" in html
    assert "Windows Security Status" in html
    assert "Running" in html
    assert "SENSITIVE_VALUE" not in html


def test_html_report_redacts_windows_evidence_secrets(tmp_path) -> None:
    scan_result = {
        "host": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "scan_mode": "safe",
        "duration_seconds": 0.1,
        "open_ports": [],
        "findings": [
            {
                "id": "FINDING-0001",
                "title": "Windows Test",
                "severity": "Informational",
                "category": "Windows Audit",
                "affected_host": "127.0.0.1",
                "affected_port": None,
                "affected_url": None,
                "service": "winrm",
                "evidence": "Observed Password=Secret123",
                "evidence_details": {"source": "unit", "observed_value": "Authorization: Basic dXNlcjpwYXNz"},
                "confidence": "High",
                "impact": "None.",
                "recommendation": "None.",
                "verification": "Unit test.",
                "limitation": "None.",
                "source": "windows_audit",
                "risk_score": 0,
                "risk_label": "Informational",
                "fix_priority": "Document and monitor",
                "created_at": "2026-05-16T10:00:00+00:00",
            }
        ],
        "http_findings": [],
        "tls_findings": [],
        "ssh_findings": [],
        "windows_findings": [],
        "ssh_audit": {"enabled": False, "status": "skipped"},
        "ssh_audit_summary": {"enabled": False, "status": "skipped"},
        "windows_audit_summary": {"enabled": True, "status": "success", "safe_detail": "AccessToken=HiddenValue"},
        "credentialed_audits": [],
    }

    path = save_html_report(
        scan_result=scan_result,
        scanner_name="VulScan",
        scanner_version="test",
        scan_start_time=datetime.now(timezone.utc),
        scan_end_time=datetime.now(timezone.utc),
        reports_dir=tmp_path,
    )

    html = path.read_text(encoding="utf-8")
    assert "Secret123" not in html
    assert "dXNlcjpwYXNz" not in html
    assert "HiddenValue" not in html
