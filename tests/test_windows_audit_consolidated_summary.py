import json
from datetime import datetime, timezone

from scanner.report_json import save_json_report


def test_windows_audit_consolidated_summary_includes_performance_fields(tmp_path) -> None:
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
        "ssh_audit": {"enabled": False, "status": "skipped"},
        "ssh_audit_summary": {"enabled": False, "status": "skipped"},
        "windows_audit_summary": {
            "enabled": True,
            "status": "partial",
            "connection_timeout_seconds": 10.0,
            "command_timeout_seconds": 15.0,
            "audit_timeout_seconds": 120.0,
            "total_duration_seconds": 2.5,
            "sections_completed": 3,
            "sections_failed": 1,
            "sections_skipped": 1,
            "checks_completed": 7,
            "checks_failed": 1,
            "checks_skipped": 1,
            "timed_out_commands": 1,
            "slowest_command_name": "Get-MpComputerStatus",
            "slowest_command_duration_seconds": 15.1,
        },
        "credentialed_audits": [],
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

    consolidated = report["windows_audit_consolidated_summary"]
    assert consolidated["connection_timeout_seconds"] == 10.0
    assert consolidated["command_timeout_seconds"] == 15.0
    assert consolidated["audit_timeout_seconds"] == 120.0
    assert consolidated["timed_out_commands"] == 1
