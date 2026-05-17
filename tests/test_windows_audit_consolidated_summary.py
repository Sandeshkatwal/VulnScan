import json
from datetime import datetime, timezone

from scanner.report_json import save_json_report
from scanner.windows_result import build_windows_consolidated_summary


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


def test_consolidated_summary_can_be_built_from_sections() -> None:
    sections = [
        {"section_id": "windows_service_reachability", "status": "success", "checks_completed": 5, "checks_failed": 0, "checks_skipped": 0},
        {"section_id": "winrm_authentication", "status": "success", "checks_completed": 1, "checks_failed": 0, "checks_skipped": 0},
    ]

    summary = build_windows_consolidated_summary(sections=sections, windows_findings=[], base_summary={"enabled": True})

    assert summary["sections_completed"] == 2
    assert summary["checks_completed"] == 6
    assert summary["status"] == "success"


def test_consolidated_summary_partial_when_one_section_fails() -> None:
    sections = [
        {"section_id": "windows_service_reachability", "status": "success", "checks_completed": 5, "checks_failed": 0, "checks_skipped": 0},
        {"section_id": "windows_security_status", "status": "failed", "checks_planned": 3, "checks_completed": 1, "checks_failed": 1, "checks_skipped": 2},
    ]

    summary = build_windows_consolidated_summary(sections=sections, windows_findings=[], base_summary={"enabled": True})

    assert summary["status"] == "partial"
    assert summary["sections_failed"] == 1


def test_consolidated_summary_success_when_requested_sections_succeed() -> None:
    sections = [
        {"section_id": "windows_service_reachability", "status": "success", "checks_completed": 5, "checks_failed": 0, "checks_skipped": 0},
        {"section_id": "winrm_authentication", "status": "success", "checks_planned": 1, "checks_completed": 1, "checks_failed": 0, "checks_skipped": 0},
        {"section_id": "windows_patch_status", "status": "skipped", "checks_planned": 0, "checks_completed": 0, "checks_failed": 0, "checks_skipped": 0},
    ]

    summary = build_windows_consolidated_summary(sections=sections, windows_findings=[], base_summary={"enabled": True})

    assert summary["status"] == "success"
