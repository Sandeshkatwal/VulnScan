import importlib
import socket

from scanner.finding import Finding
from scanner.windows_audit import (
    WINRM_AUTH_FAILED,
    WINRM_AUTH_SUCCESS,
    WINRM_DEPENDENCY_MISSING,
    WINRM_NOT_REACHABLE,
    WINRM_TIMEOUT,
    WindowsAuditConfigurationError,
    audit_windows_host,
    validate_windows_audit_options,
)


class _FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class _Response:
    def __init__(self, status_code: int, std_out: bytes = b"") -> None:
        self.status_code = status_code
        self.std_out = std_out


class _WinrmModule:
    def __init__(self, response=None, exception: Exception | None = None) -> None:
        self.response = response
        self.exception = exception
        self.sessions = []

    def Session(self, endpoint, **kwargs):
        self.sessions.append({"endpoint": endpoint, **kwargs})
        return _Session(self.response, self.exception)


class _Session:
    def __init__(self, response=None, exception: Exception | None = None) -> None:
        self.response = response
        self.exception = exception

    def run_cmd(self, command):
        if self.exception:
            raise self.exception
        return self.response


def _mock_reachability(monkeypatch, reachable_ports: set[int]) -> None:
    def fake_create_connection(address, timeout=0):
        port = int(address[1])
        if port in reachable_ports:
            return _FakeSocket()
        raise socket.timeout()

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)


def _mock_winrm_import(monkeypatch, module) -> None:
    def fake_import_module(name):
        if name == "winrm":
            if module is None:
                raise ImportError("missing")
            return module
        return importlib.import_module(name)

    monkeypatch.setattr(importlib, "import_module", fake_import_module)


def test_winrm_auth_requires_username_and_password() -> None:
    try:
        validate_windows_audit_options(
            windows_audit=True,
            windows_user="auditor",
            windows_password=None,
            windows_auth_method="winrm",
        )
    except WindowsAuditConfigurationError as exc:
        assert exc.error_code == "WINRM_CREDENTIALS_MISSING"
    else:
        raise AssertionError("Expected missing WinRM credentials to raise")


def test_winrm_dependency_missing_is_safe_result(monkeypatch) -> None:
    _mock_reachability(monkeypatch, {5985})
    _mock_winrm_import(monkeypatch, None)

    result = audit_windows_host(
        target="192.0.2.60",
        resolved_ip="192.0.2.60",
        username="auditor",
        password="SENSITIVE_VALUE",
        auth_method="winrm",
    )

    summary = result["summary"]

    assert summary["winrm_auth_status"] == "dependency_missing"
    assert summary["winrm_error_code"] == WINRM_DEPENDENCY_MISSING
    assert "SENSITIVE_VALUE" not in str(result)
    assert "WinRM Dependency Missing" in {finding.title for finding in result["findings"]}


def test_winrm_auth_success_uses_single_safe_command(monkeypatch) -> None:
    _mock_reachability(monkeypatch, {5986, 5985})
    module = _WinrmModule(response=_Response(0, b"LABHOST\r\n"))
    _mock_winrm_import(monkeypatch, module)

    result = audit_windows_host(
        target="192.0.2.60",
        resolved_ip="192.0.2.60",
        username="auditor",
        password="SENSITIVE_VALUE",
        domain="WORKGROUP",
        auth_method="winrm",
    )

    summary = result["summary"]

    assert summary["winrm_auth_status"] == "authenticated"
    assert summary["winrm_error_code"] == WINRM_AUTH_SUCCESS
    assert summary["winrm_endpoint_used"] == "https://192.0.2.60:5986/wsman"
    assert summary["winrm_transport"] == "ntlm"
    assert summary["safe_validation_command"] == "hostname"
    assert summary["validation_result_summary"] == "LABHOST"
    assert result["credentialed_audit"]["source"] == "windows_audit"
    assert result["credentialed_audit"]["authenticated"] is True
    assert "SENSITIVE_VALUE" not in str(result)
    assert len(module.sessions) == 1


def test_winrm_auth_failure_is_normalised(monkeypatch) -> None:
    _mock_reachability(monkeypatch, {5985})
    module = _WinrmModule(response=_Response(1))
    _mock_winrm_import(monkeypatch, module)

    result = audit_windows_host(
        target="192.0.2.60",
        resolved_ip="192.0.2.60",
        username="auditor",
        password="SENSITIVE_VALUE",
        auth_method="winrm",
    )

    assert result["summary"]["winrm_auth_status"] == "auth_failed"
    assert result["summary"]["winrm_error_code"] == WINRM_AUTH_FAILED
    assert "WinRM Authentication Failed" in {finding.title for finding in result["findings"]}
    assert "SENSITIVE_VALUE" not in str(result)


def test_winrm_timeout_is_normalised(monkeypatch) -> None:
    _mock_reachability(monkeypatch, {5985})
    module = _WinrmModule(exception=TimeoutError("timed out"))
    _mock_winrm_import(monkeypatch, module)

    result = audit_windows_host(
        target="192.0.2.60",
        resolved_ip="192.0.2.60",
        username="auditor",
        password="SENSITIVE_VALUE",
        auth_method="winrm",
    )

    assert result["summary"]["winrm_auth_status"] == "timeout"
    assert result["summary"]["winrm_error_code"] == WINRM_TIMEOUT
    assert "SENSITIVE_VALUE" not in str(result)


def test_winrm_not_reachable(monkeypatch) -> None:
    _mock_reachability(monkeypatch, set())

    result = audit_windows_host(
        target="192.0.2.60",
        resolved_ip="192.0.2.60",
        username="auditor",
        password="SENSITIVE_VALUE",
        auth_method="winrm",
    )

    summary = result["summary"]
    winrm_finding = next(finding for finding in result["findings"] if finding.title == "WinRM Not Reachable")

    assert summary["winrm_auth_status"] == "not_reachable"
    assert summary["winrm_error_code"] == WINRM_NOT_REACHABLE
    assert isinstance(winrm_finding, Finding)
    assert "SENSITIVE_VALUE" not in str(result)
