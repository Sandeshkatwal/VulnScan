import json
from datetime import datetime, timezone

from scanner.report_json import save_json_report


def test_json_report_includes_credentialed_audits_and_findings(tmp_path) -> None:
    scan_result = {
        "host": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "scan_mode": "safe",
        "duration_seconds": 0.1,
        "open_ports": [],
        "findings": [
            {
                "id": "FINDING-0001",
                "title": "SSH Login Successful",
                "severity": "Informational",
                "category": "Credentialed Access",
                "affected_host": "127.0.0.1",
                "affected_port": 22,
                "affected_url": None,
                "service": "ssh",
                "evidence": "Authenticated SSH session established.",
                "confidence": "High",
                "impact": "Credentialed auditing can reduce false positives.",
                "recommendation": "Use least-privilege read-only credentials.",
                "verification": "Review SSH audit output.",
                "limitation": "Depends on account permissions.",
                "source": "ssh_audit",
                "risk_score": 0,
                "risk_label": "Informational",
                "fix_priority": "Document and monitor",
                "created_at": "2026-05-16T10:00:00+00:00",
            }
        ],
        "http_findings": [],
        "tls_findings": [],
        "ssh_findings": [],
        "windows_findings": [
            {
                "id": "FINDING-0002",
                "title": "WinRM Authentication Successful",
                "severity": "Informational",
                "category": "Windows Credentialed Access",
                "affected_host": "127.0.0.1",
                "affected_port": None,
                "affected_url": None,
                "service": "winrm",
                "evidence": "WinRM authentication succeeded.",
                "confidence": "High",
                "impact": "Credentialed Windows auditing can be performed in later versions.",
                "recommendation": "Use least-privilege accounts.",
                "verification": "Re-run VulScan.",
                "limitation": "Authentication success does not indicate vulnerability.",
                "source": "windows_audit",
                "risk_score": 0,
                "risk_label": "Informational",
                "fix_priority": "Document and monitor",
                "created_at": "2026-05-16T10:00:00+00:00",
            }
        ],
        "ssh_audit": {"enabled": True, "status": "success"},
        "ssh_audit_summary": {"enabled": True, "status": "success"},
        "windows_audit_summary": {
            "enabled": True,
            "status": "success",
            "auth_method": "winrm",
            "username_used": "auditor",
            "winrm_auth_status": "authenticated",
            "winrm_authenticated": True,
            "winrm_endpoint_used": "http://127.0.0.1:5985/wsman",
            "windows_host_info_collected": True,
            "windows_host_info": {
                "hostname": "LABHOST",
                "os_caption": "Microsoft Windows Server 2022 Standard",
                "os_version": "10.0.20348",
                "os_build": "20348",
                "domain": "WORKGROUP",
                "workgroup": "",
                "powershell_version": "5.1",
            },
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

    path = save_json_report(
        scan_result=scan_result,
        scanner_name="VulScan",
        scanner_version="test",
        scan_start_time=datetime.now(timezone.utc),
        scan_end_time=datetime.now(timezone.utc),
        reports_dir=tmp_path,
    )

    report = json.loads(path.read_text(encoding="utf-8"))

    assert report["credentialed_audits"][0]["source"] == "ssh_audit"
    assert report["credentialed_audits"][1]["source"] == "windows_audit"
    assert report["windows_audit_summary"]["winrm_auth_status"] == "authenticated"
    assert report["windows_audit_summary"]["windows_host_info"]["hostname"] == "LABHOST"
    assert report["findings"][0]["title"] == "SSH Login Successful"
