import socket
from pathlib import Path
from types import SimpleNamespace

from scanner import ssh_audit
from scanner.audit_profiles import get_audit_profile
from scanner.ssh_audit import (
    SshAuditConfigurationError,
    _run_command,
    audit_ssh_host,
    validate_ssh_audit_options,
)


class _TimeoutClient:
    def exec_command(self, command: str, timeout: float):
        raise socket.timeout()


def test_missing_credentials_validation_uses_structured_code() -> None:
    try:
        validate_ssh_audit_options(True, "user", None, None)
    except SshAuditConfigurationError as exc:
        assert exc.error_code == "SSH_CREDENTIALS_MISSING"
    else:
        raise AssertionError("Expected missing credentials to raise")


def test_missing_ssh_key_returns_structured_result() -> None:
    result = audit_ssh_host(
        host="host.example",
        resolved_ip="192.0.2.10",
        username="user",
        key_path=Path("tests/fixtures/not-a-key"),
        audit_profile=get_audit_profile("basic"),
    )

    assert result["status"] == "failed"
    assert result["error_code"] == "SSH_KEY_NOT_FOUND"
    assert "not-a-key" not in result["error_message"]


def test_command_timeout_returns_structured_error() -> None:
    result = _run_command(_TimeoutClient(), "uname -a")

    assert result["success"] is False
    assert result["error_code"] == "SSH_COMMAND_TIMEOUT"
    assert result["command_name"] == "uname -a"
    assert result["duration_seconds"] >= 0


def test_auth_failure_returns_structured_result(monkeypatch) -> None:
    class AuthenticationException(Exception):
        pass

    class SSHException(Exception):
        pass

    class FakeClient:
        def set_missing_host_key_policy(self, policy):
            return None

        def connect(self, **kwargs):
            raise AuthenticationException()

        def close(self):
            return None

    fake_paramiko = SimpleNamespace(
        AuthenticationException=AuthenticationException,
        SSHException=SSHException,
        SSHClient=lambda: FakeClient(),
        AutoAddPolicy=lambda: object(),
    )
    monkeypatch.setattr(ssh_audit, "paramiko", fake_paramiko)

    result = audit_ssh_host(
        host="host.example",
        resolved_ip="192.0.2.10",
        username="user",
        password="placeholder",
        audit_profile=get_audit_profile("basic"),
    )

    assert result["status"] == "failed"
    assert result["error_code"] == "SSH_AUTH_FAILED"
    assert result["authenticated"] is False


def test_command_failure_does_not_crash_collection() -> None:
    command = {
        "command": "cat /etc/login.defs",
        "command_name": "cat /etc/login.defs",
        "success": False,
        "stdout": "",
        "stderr": "Command failed.",
        "raw_stdout": "",
        "raw_stderr": "Command failed.",
        "exit_status": 1,
        "error_code": "SSH_COMMAND_FAILED",
        "duration_seconds": 0.01,
        "timed_out": False,
    }

    assert ssh_audit._is_actionable_command_failure(command) is True
