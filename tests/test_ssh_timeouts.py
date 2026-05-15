from scanner.audit_profiles import get_audit_profile
from scanner.main import _build_ssh_audit_summary


def test_ssh_audit_summary_includes_performance_fields() -> None:
    profile = get_audit_profile("standard")
    scan_result = {
        "host": "192.0.2.10",
        "ssh_findings": [],
        "ssh_audit": {
            "status": "partial",
            "authenticated": True,
            "error_code": "SSH_AUDIT_TIME_BUDGET_EXCEEDED",
            "error_message": "SSH audit time budget was exceeded before all checks completed.",
            "connection_timeout_seconds": 8.0,
            "command_timeout_seconds": 10.0,
            "audit_timeout_seconds": 60.0,
            "total_duration_seconds": 60.1,
            "checks_planned": 8,
            "checks_completed": 6,
            "checks_failed": 1,
            "checks_skipped": 2,
            "partial_failures": 1,
            "timed_out_commands": 1,
            "slowest_command_name": "apt list --upgradable",
            "slowest_command_duration_seconds": 10.0,
            "performance_notes": ["1 command(s) timed out."],
        },
    }

    summary = _build_ssh_audit_summary(
        scan_result=scan_result,
        username="sadmin",
        auth_method="password",
        ssh_port=22,
        audit_profile=profile,
    )

    assert summary["status"] == "partial"
    assert summary["connection_timeout_seconds"] == 8.0
    assert summary["command_timeout_seconds"] == 10.0
    assert summary["audit_timeout_seconds"] == 60.0
    assert summary["total_duration_seconds"] == 60.1
    assert summary["checks_planned"] == 8
    assert summary["checks_completed"] == 6
    assert summary["checks_failed"] == 1
    assert summary["checks_skipped"] == 2
    assert summary["timed_out_commands"] == 1
    assert summary["slowest_command_name"] == "apt list --upgradable"
    assert summary["performance_notes"]


def test_ssh_audit_summary_does_not_include_secrets() -> None:
    profile = get_audit_profile("basic")
    scan_result = {
        "host": "192.0.2.10",
        "ssh_findings": [],
        "ssh_audit": {
            "status": "failed",
            "authenticated": False,
            "error_code": "SSH_AUTH_FAILED",
            "error_message": "SSH authentication failed. No audit commands were run.",
            "connection_timeout_seconds": 8.0,
            "command_timeout_seconds": 10.0,
            "audit_timeout_seconds": 30.0,
            "total_duration_seconds": 1.0,
            "checks_planned": 0,
            "checks_completed": 0,
            "checks_failed": 0,
            "checks_skipped": 0,
            "timed_out_commands": 0,
            "performance_notes": [],
        },
    }

    summary = _build_ssh_audit_summary(
        scan_result=scan_result,
        username="sadmin",
        auth_method="key",
        ssh_port=22,
        audit_profile=profile,
    )

    serialized = str(summary)
    assert "secret-password" not in serialized
    assert "C:\\Users\\Sande\\.ssh\\id_rsa" not in serialized
