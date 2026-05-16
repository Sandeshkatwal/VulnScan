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
        "ssh_audit": {"enabled": True, "status": "success"},
        "ssh_audit_summary": {"enabled": True, "status": "success"},
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
    assert report["findings"][0]["title"] == "SSH Login Successful"
