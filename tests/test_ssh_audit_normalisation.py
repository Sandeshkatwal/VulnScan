from pathlib import Path

from scanner.audit_profiles import get_audit_profile
from scanner.main import _build_credentialed_audits, _build_ssh_audit_summary
from scanner.ssh_audit import audit_ssh_host


def test_ssh_audit_result_contains_required_normalised_fields() -> None:
    result = audit_ssh_host(
        host="host.example",
        resolved_ip="192.0.2.10",
        username="sadmin",
        key_path=Path("tests/fixtures/not-a-key"),
        audit_profile=get_audit_profile("basic"),
    )

    credentialed = result["credentialed_audit"]

    assert credentialed["source"] == "ssh_audit"
    assert credentialed["module_name"] == "Authenticated SSH Audit"
    assert credentialed["status"] == "failed"
    assert credentialed["target"] == "host.example"
    assert credentialed["authenticated"] is False
    assert credentialed["auth_method"] == "key"
    assert credentialed["username"] == "sadmin"
    assert credentialed["profile"] == "basic"
    assert "started_at" in credentialed
    assert "ended_at" in credentialed
    assert "performance" in credentialed
    assert "summary" in credentialed
    assert "errors" in credentialed


def test_normalised_result_does_not_include_password_or_key_path() -> None:
    result = audit_ssh_host(
        host="host.example",
        resolved_ip="192.0.2.10",
        username="sadmin",
        key_path=Path("tests/fixtures/not-a-key"),
        audit_profile=get_audit_profile("basic"),
    )

    serialized = str(result["credentialed_audit"])

    assert "SENSITIVE_VALUE" not in serialized
    assert "SENSITIVE_PATH" not in serialized
    assert "not-a-key" not in serialized


def test_ssh_audit_summary_can_be_built_from_credentialed_audit_result() -> None:
    profile = get_audit_profile("standard")
    credentialed = {
        "source": "ssh_audit",
        "module_name": "Authenticated SSH Audit",
        "status": "partial",
        "target": "192.0.2.10",
        "authenticated": True,
        "auth_method": "password",
        "username": "sadmin",
        "profile": "standard",
        "started_at": "2026-05-16T10:00:00+00:00",
        "ended_at": "2026-05-16T10:00:02+00:00",
        "duration_seconds": 2.0,
        "checks_planned": 3,
        "checks_completed": 2,
        "checks_failed": 1,
        "checks_skipped": 0,
        "findings": [],
        "summary": {
            "package_manager": "apt",
            "package_update_count": 0,
            "ssh_hardening_checked": True,
            "linux_config_audit_checked": True,
        },
        "errors": [
            {
                "error_code": "SSH_COMMAND_TIMEOUT",
                "message": "One or more SSH audit commands timed out.",
                "severity": "error",
                "safe_detail": "",
                "source": "ssh_audit",
                "check_name": "Authenticated SSH Audit",
            }
        ],
        "limitations": [],
        "performance": {
            "connection_timeout_seconds": 8.0,
            "command_timeout_seconds": 10.0,
            "audit_timeout_seconds": 60.0,
            "total_duration_seconds": 2.0,
            "timed_out_commands": 1,
        },
        "metadata": {
            "os_family": "Debian/Kali/Parrot/Ubuntu",
            "hostname": "test-host",
            "kernel_summary": "Linux test-host",
        },
    }
    scan_result = {
        "host": "192.0.2.10",
        "ssh_findings": [],
        "ssh_audit": {},
        "credentialed_audits": [credentialed],
    }

    summary = _build_ssh_audit_summary(
        scan_result=scan_result,
        username="sadmin",
        auth_method="password",
        ssh_port=22,
        audit_profile=profile,
    )

    assert summary["status"] == "partial"
    assert summary["error_code"] == "SSH_COMMAND_TIMEOUT"
    assert summary["checks_completed"] == 2
    assert summary["timed_out_commands"] == 1
    assert summary["hostname"] == "test-host"


def test_build_credentialed_audits_preserves_existing_findings() -> None:
    ssh_result = {
        "credentialed_audit": {
            "source": "ssh_audit",
            "module_name": "Authenticated SSH Audit",
            "status": "success",
            "profile": "standard",
            "findings": [],
        },
        "checks_completed": 1,
        "checks_failed": 0,
        "checks_skipped": 0,
        "total_duration_seconds": 1.2,
    }
    ssh_findings = [{"id": "FINDING-0001", "title": "SSH Login Successful"}]

    audits = _build_credentialed_audits(
        ssh_result=ssh_result,
        ssh_findings=ssh_findings,
    )

    assert audits[0]["findings"] == ssh_findings
