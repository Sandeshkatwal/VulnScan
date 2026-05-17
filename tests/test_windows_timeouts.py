import time

import pytest

from scanner.windows_audit import (
    WINDOWS_AUDIT_TIME_BUDGET_EXCEEDED,
    WINDOWS_COMMAND_TIMEOUT,
    WindowsAuditBudget,
    WindowsAuditConfigurationError,
    audit_windows_host,
    execute_windows_command,
    validate_windows_audit_options,
)


class FakeResponse:
    def __init__(self, status_code=0, std_out=b"ok", std_err=b""):
        self.status_code = status_code
        self.std_out = std_out
        self.std_err = std_err


class SlowSession:
    def run_cmd(self, command, args=None):
        time.sleep(0.02)
        return FakeResponse(std_out=b"LABHOST")


class FakeWinRMModule:
    class Session:
        def __init__(self, *args, **kwargs):
            pass

        def run_cmd(self, command, args=None):
            time.sleep(0.005)
            return FakeResponse(std_out=b"LABHOST")

        def run_ps(self, command):
            return FakeResponse(std_out=b"{}")


def test_invalid_windows_timeout_is_rejected() -> None:
    with pytest.raises(WindowsAuditConfigurationError):
        validate_windows_audit_options(
            windows_audit=True,
            windows_user=None,
            windows_password=None,
            windows_auth_method="none",
            windows_timeout=0,
        )


def test_invalid_windows_command_timeout_is_rejected() -> None:
    with pytest.raises(WindowsAuditConfigurationError):
        validate_windows_audit_options(
            windows_audit=True,
            windows_user=None,
            windows_password=None,
            windows_auth_method="none",
            windows_command_timeout=181,
        )


def test_invalid_windows_audit_timeout_is_rejected() -> None:
    with pytest.raises(WindowsAuditConfigurationError):
        validate_windows_audit_options(
            windows_audit=True,
            windows_user=None,
            windows_password=None,
            windows_auth_method="none",
            windows_audit_timeout=901,
        )


def test_command_timeout_returns_structured_timeout() -> None:
    result = execute_windows_command(
        SlowSession(),
        command_name="hostname",
        command_used_safe_label="hostname",
        command_type="cmd",
        command="hostname",
        command_timeout=0.001,
        budget=WindowsAuditBudget(10),
    )

    assert result["success"] is False
    assert result["error_code"] == WINDOWS_COMMAND_TIMEOUT
    assert result["timed_out"] is True
    assert "password" not in str(result).lower()


def test_overall_budget_skips_remaining_sections(monkeypatch) -> None:
    def fake_check_service(resolved_ip, check, timeout):
        return {
            "port": check["port"],
            "service": check["service"],
            "reachable": check["port"] == 5985,
            "evidence": "fake",
            "recommendation": check["recommendation"],
            "limitation": check["limitation"],
            "duration_seconds": 0.0,
            "error_code": None,
            "error_message": "",
        }

    monkeypatch.setattr("scanner.windows_audit._check_service", fake_check_service)
    monkeypatch.setattr("scanner.windows_audit.importlib.import_module", lambda name: FakeWinRMModule)

    result = audit_windows_host(
        target="192.0.2.50",
        resolved_ip="192.0.2.50",
        username="auditor",
        password="placeholder",
        auth_method="winrm",
        collect_host_info=True,
        timeout=1,
        command_timeout=1,
        audit_timeout=0.001,
    )

    summary = result["summary"]
    assert summary["status"] == "partial"
    assert summary["sections_skipped"] >= 1
    assert WINDOWS_AUDIT_TIME_BUDGET_EXCEEDED in str(summary)
    assert "placeholder" not in str(summary)
