from scanner.main import _build_windows_audit_summary, _build_windows_credentialed_audits


def test_windows_audit_summary_uses_windows_findings_risk() -> None:
    scan_result = {
        "host": "192.0.2.50",
        "windows_audit": {
            "status": "success",
            "summary": {
                "enabled": True,
                "status": "success",
                "target": "192.0.2.50",
                "authenticated": False,
                "auth_method": "none",
                "domain": "",
                "username_used": "",
                "smb_reachable": True,
                "winrm_http_reachable": False,
                "winrm_https_reachable": False,
                "rdp_reachable": True,
                "checks_completed": 5,
                "checks_failed": 0,
                "checks_skipped": 0,
                "findings_count": 0,
                "highest_windows_risk_score": 0,
                "highest_windows_risk_label": "Informational",
                "limitations": "Foundation checks only.",
            },
        },
        "windows_findings": [
            {
                "title": "RDP Service Reachable",
                "risk_score": 60,
                "risk_label": "Medium priority",
                "source": "windows_audit",
            }
        ],
    }

    summary = _build_windows_audit_summary(scan_result)

    assert summary["enabled"] is True
    assert summary["findings_count"] == 1
    assert summary["highest_windows_risk_score"] == 60
    assert summary["highest_windows_risk_label"] == "Medium priority"


def test_windows_credentialed_audits_contains_windows_audit() -> None:
    windows_result = {
        "credentialed_audit": {
            "source": "windows_audit",
            "module_name": "Windows SMB/WinRM Audit Foundation",
            "status": "success",
            "target": "192.0.2.50",
            "authenticated": False,
            "auth_method": "none",
            "username": "",
            "profile": "foundation",
            "findings": [],
            "summary": {},
            "errors": [],
            "limitations": [],
            "performance": {},
            "metadata": {},
        }
    }
    windows_summary = {
        "checks_completed": 5,
        "checks_failed": 0,
        "checks_skipped": 0,
        "smb_reachable": True,
    }
    windows_findings = [{"title": "SMB Service Reachable", "source": "windows_audit"}]

    audits = _build_windows_credentialed_audits(
        windows_result=windows_result,
        windows_findings=windows_findings,
        windows_summary=windows_summary,
    )

    assert audits[0]["source"] == "windows_audit"
    assert audits[0]["module_name"] == "Windows SMB/WinRM Audit Foundation"
    assert audits[0]["findings"] == windows_findings
    assert audits[0]["summary"] == windows_summary


def test_windows_summary_does_not_include_password() -> None:
    scan_result = {
        "host": "192.0.2.50",
        "windows_audit": {
            "status": "success",
            "summary": {
                "enabled": True,
                "status": "success",
                "target": "192.0.2.50",
                "authenticated": "unknown",
                "auth_method": "smb",
                "domain": "WORKGROUP",
                "username_used": "auditor",
                "smb_reachable": True,
                "winrm_http_reachable": False,
                "winrm_https_reachable": False,
                "rdp_reachable": False,
                "checks_completed": 5,
                "checks_failed": 0,
                "checks_skipped": 0,
                "findings_count": 0,
                "highest_windows_risk_score": 0,
                "highest_windows_risk_label": "Informational",
                "limitations": "Foundation checks only.",
            },
        },
        "windows_findings": [],
    }

    summary = _build_windows_audit_summary(scan_result)

    assert "SENSITIVE_VALUE" not in str(summary)
    assert summary["username_used"] == "auditor"
