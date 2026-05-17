import importlib
import socket

from scanner.finding import Finding
from scanner.windows_audit import (
    ERROR_WINDOWS_REGISTRY_AUDIT_PREREQUISITES,
    ERROR_WINDOWS_REGISTRY_TEMPLATE_WITHOUT_AUDIT,
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
    def __init__(self, value_outputs: dict[str, tuple[int, bytes]], auth_status: int = 0) -> None:
        self.value_outputs = value_outputs
        self.auth_status = auth_status
        self.sessions = []

    def Session(self, endpoint, **kwargs):
        session = _Session(self.value_outputs, self.auth_status)
        self.sessions.append(session)
        return session


class _Session:
    def __init__(self, value_outputs: dict[str, tuple[int, bytes]], auth_status: int) -> None:
        self.value_outputs = value_outputs
        self.auth_status = auth_status
        self.cmd_commands = []
        self.ps_commands = []

    def run_cmd(self, command):
        self.cmd_commands.append(command)
        return _Response(self.auth_status, b"LABHOST\r\n" if self.auth_status == 0 else b"")

    def run_ps(self, command):
        self.ps_commands.append(command)
        for value_name, response in self.value_outputs.items():
            if f".'{value_name}'" in command or f"-Name '{value_name}'" in command:
                return _Response(response[0], response[1])
        return _Response(1, b"")


def _mock_reachability(monkeypatch) -> None:
    def fake_create_connection(address, timeout=0):
        if int(address[1]) == 5985:
            return _FakeSocket()
        raise socket.timeout()

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)


def _mock_winrm_import(monkeypatch, module) -> None:
    original_import_module = importlib.import_module

    def fake_import_module(name):
        if name == "winrm":
            return module
        return original_import_module(name)

    monkeypatch.setattr(importlib, "import_module", fake_import_module)


def _json_value(value: int) -> bytes:
    return f'{{"Present":true,"Value":{value}}}'.encode("utf-8")


def test_windows_registry_audit_prerequisites_are_validated() -> None:
    try:
        validate_windows_audit_options(
            windows_audit=True,
            windows_user="auditor",
            windows_password="SENSITIVE_VALUE",
            windows_auth_method="none",
            windows_registry_audit=True,
        )
    except WindowsAuditConfigurationError as exc:
        assert exc.error_code == ERROR_WINDOWS_REGISTRY_AUDIT_PREREQUISITES
        assert "SENSITIVE_VALUE" not in str(exc)
    else:
        raise AssertionError("Expected registry prerequisites to raise")


def test_windows_registry_template_without_audit_is_friendly_error() -> None:
    try:
        validate_windows_audit_options(
            windows_audit=True,
            windows_user="auditor",
            windows_password="SENSITIVE_VALUE",
            windows_auth_method="winrm",
            windows_registry_audit=False,
            windows_registry_template="templates\\windows_registry\\basic_security_indicators.json",
        )
    except WindowsAuditConfigurationError as exc:
        assert exc.error_code == ERROR_WINDOWS_REGISTRY_TEMPLATE_WITHOUT_AUDIT
        assert "SENSITIVE_VALUE" not in str(exc)
    else:
        raise AssertionError("Expected template without registry audit to raise")


def test_registry_value_equals_expected_passes(monkeypatch) -> None:
    _mock_reachability(monkeypatch)
    module = _WinrmModule(
        {
            "UserAuthentication": (0, _json_value(1)),
            "fDenyTSConnections": (0, _json_value(1)),
            "SMB1": (0, _json_value(0)),
            "RunAsPPL": (0, _json_value(1)),
            "UseLogonCredential": (0, _json_value(0)),
        }
    )
    _mock_winrm_import(monkeypatch, module)

    result = audit_windows_host(
        target="192.0.2.100",
        resolved_ip="192.0.2.100",
        username="auditor",
        password="SENSITIVE_VALUE",
        auth_method="winrm",
        collect_registry_audit=True,
    )

    registry_audit = result["summary"]["windows_registry_audit"]

    assert result["summary"]["windows_registry_audit_checked"] is True
    assert registry_audit["checks_executed"] == 5
    assert registry_audit["checks_passed"] == 5
    assert registry_audit["checks_with_findings"] == 0
    assert "SENSITIVE_VALUE" not in str(result)
    assert len(module.sessions[0].ps_commands) == 5


def test_registry_value_mismatch_creates_standard_finding(monkeypatch) -> None:
    _mock_reachability(monkeypatch)
    module = _WinrmModule(
        {
            "UserAuthentication": (0, _json_value(0)),
            "fDenyTSConnections": (0, _json_value(1)),
            "SMB1": (0, _json_value(0)),
            "RunAsPPL": (0, _json_value(1)),
            "UseLogonCredential": (0, _json_value(0)),
        }
    )
    _mock_winrm_import(monkeypatch, module)

    result = audit_windows_host(
        target="192.0.2.100",
        resolved_ip="192.0.2.100",
        username="auditor",
        password="SENSITIVE_VALUE",
        auth_method="winrm",
        collect_registry_audit=True,
    )

    finding = next(
        item for item in result["findings"] if item.title == "Remote Desktop NLA Setting Indicator"
    )

    assert isinstance(finding, Finding)
    assert finding.source == "windows_registry_audit"
    assert finding.severity == "Medium"
    assert result["summary"]["windows_registry_audit"]["checks_with_findings"] == 1


def test_missing_registry_value_is_unknown_not_risky_finding(monkeypatch) -> None:
    _mock_reachability(monkeypatch)
    module = _WinrmModule(
        {
            "UserAuthentication": (1, b""),
            "fDenyTSConnections": (0, _json_value(1)),
            "SMB1": (0, _json_value(0)),
            "RunAsPPL": (0, _json_value(1)),
            "UseLogonCredential": (0, _json_value(0)),
        }
    )
    _mock_winrm_import(monkeypatch, module)

    result = audit_windows_host(
        target="192.0.2.100",
        resolved_ip="192.0.2.100",
        username="auditor",
        password="SENSITIVE_VALUE",
        auth_method="winrm",
        collect_registry_audit=True,
    )

    registry_audit = result["summary"]["windows_registry_audit"]
    titles = {item.title for item in result["findings"]}

    assert result["status"] == "partial"
    assert registry_audit["check_results"][0]["status"] == "unknown"
    assert registry_audit["checks_with_findings"] == 0
    assert "Remote Desktop NLA Setting Indicator" not in titles
    assert "Windows Registry Audit Template Completed" in titles


def test_registry_checks_do_not_run_if_winrm_auth_fails(monkeypatch) -> None:
    _mock_reachability(monkeypatch)
    module = _WinrmModule({}, auth_status=1)
    _mock_winrm_import(monkeypatch, module)

    result = audit_windows_host(
        target="192.0.2.100",
        resolved_ip="192.0.2.100",
        username="auditor",
        password="SENSITIVE_VALUE",
        auth_method="winrm",
        collect_registry_audit=True,
    )

    assert result["summary"]["winrm_auth_status"] == "auth_failed"
    assert result["summary"]["windows_registry_audit_checked"] is False
    assert module.sessions[0].ps_commands == []
    assert "SENSITIVE_VALUE" not in str(result)
