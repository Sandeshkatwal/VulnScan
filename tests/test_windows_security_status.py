import importlib
import socket

from scanner.finding import Finding
from scanner.windows_audit import (
    ERROR_WINDOWS_SECURITY_STATUS_PREREQUISITES,
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
    def __init__(
        self,
        ps_outputs: dict[str, bytes],
        failing_commands: set[str] | None = None,
        auth_status: int = 0,
    ) -> None:
        self.ps_outputs = ps_outputs
        self.failing_commands = failing_commands or set()
        self.auth_status = auth_status
        self.sessions = []

    def Session(self, endpoint, **kwargs):
        session = _Session(self.ps_outputs, self.failing_commands, self.auth_status)
        self.sessions.append(session)
        return session


class _Session:
    def __init__(self, ps_outputs: dict[str, bytes], failing_commands: set[str], auth_status: int) -> None:
        self.ps_outputs = ps_outputs
        self.failing_commands = failing_commands
        self.auth_status = auth_status
        self.ps_commands = []

    def run_cmd(self, command):
        return _Response(self.auth_status, b"LABHOST\r\n" if self.auth_status == 0 else b"")

    def run_ps(self, command):
        self.ps_commands.append(command)
        if command in self.failing_commands:
            return _Response(1, b"")
        return _Response(0, self.ps_outputs.get(command, b""))


FIREWALL_COMMAND = (
    "Get-NetFirewallProfile | "
    "Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | "
    "ConvertTo-Json -Compress"
)
DEFENDER_SERVICE_COMMAND = "Get-Service WinDefend | Select-Object Name, Status, StartType | ConvertTo-Json -Compress"
DEFENDER_STATUS_COMMAND = (
    "Get-MpComputerStatus | "
    "Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled, "
    "BehaviorMonitorEnabled, IoavProtectionEnabled, NISEnabled, AntivirusSignatureLastUpdated, "
    "AntispywareSignatureLastUpdated | ConvertTo-Json -Compress"
)


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


def _security_outputs() -> dict[str, bytes]:
    return {
        FIREWALL_COMMAND: (
            b'[{"Name":"Domain","Enabled":true,"DefaultInboundAction":"Block","DefaultOutboundAction":"Allow"},'
            b'{"Name":"Private","Enabled":false,"DefaultInboundAction":"Allow","DefaultOutboundAction":"Allow"},'
            b'{"Name":"Public","Enabled":true,"DefaultInboundAction":"Block","DefaultOutboundAction":"Allow"}]'
        ),
        DEFENDER_SERVICE_COMMAND: b'{"Name":"WinDefend","Status":"Stopped","StartType":"Manual"}',
        DEFENDER_STATUS_COMMAND: (
            b'{"AMServiceEnabled":true,"AntispywareEnabled":true,"AntivirusEnabled":true,'
            b'"RealTimeProtectionEnabled":false,"BehaviorMonitorEnabled":true,"IoavProtectionEnabled":true,'
            b'"NISEnabled":true,"AntivirusSignatureLastUpdated":"2026-05-15T10:00:00Z",'
            b'"AntispywareSignatureLastUpdated":"2026-05-15T10:00:00Z"}'
        ),
    }


def test_windows_security_status_prerequisites_are_validated() -> None:
    try:
        validate_windows_audit_options(
            windows_audit=True,
            windows_user="auditor",
            windows_password="SENSITIVE_VALUE",
            windows_auth_method="none",
            windows_security_status=True,
        )
    except WindowsAuditConfigurationError as exc:
        assert exc.error_code == ERROR_WINDOWS_SECURITY_STATUS_PREREQUISITES
        assert "SENSITIVE_VALUE" not in str(exc)
    else:
        raise AssertionError("Expected security status prerequisites to raise")


def test_windows_security_status_is_collected(monkeypatch) -> None:
    _mock_reachability(monkeypatch)
    module = _WinrmModule(_security_outputs())
    _mock_winrm_import(monkeypatch, module)

    result = audit_windows_host(
        target="192.0.2.80",
        resolved_ip="192.0.2.80",
        username="auditor",
        password="SENSITIVE_VALUE",
        auth_method="winrm",
        collect_security_status=True,
    )

    summary = result["summary"]
    security_status = summary["windows_security_status"]

    assert summary["windows_security_status_checked"] is True
    assert len(security_status["firewall_profiles"]) == 3
    assert security_status["firewall_profiles"][1]["enabled"] == "False"
    assert security_status["defender_service"]["status"] == "Stopped"
    assert security_status["defender_status"]["real_time_protection_enabled"] == "False"
    assert "SENSITIVE_VALUE" not in str(result)
    assert len(module.sessions[0].ps_commands) == 3


def test_windows_security_findings_use_standard_model(monkeypatch) -> None:
    _mock_reachability(monkeypatch)
    module = _WinrmModule(_security_outputs())
    _mock_winrm_import(monkeypatch, module)

    result = audit_windows_host(
        target="192.0.2.80",
        resolved_ip="192.0.2.80",
        username="auditor",
        password="SENSITIVE_VALUE",
        auth_method="winrm",
        collect_security_status=True,
    )

    titles = {finding.title for finding in result["findings"]}
    firewall_finding = next(
        finding for finding in result["findings"] if finding.title == "Windows Firewall Profile Disabled"
    )

    assert "Windows Firewall Profile Disabled" in titles
    assert "Microsoft Defender Service Not Running" in titles
    assert "Microsoft Defender Real-Time Protection Disabled" in titles
    assert isinstance(firewall_finding, Finding)
    assert firewall_finding.source == "windows_security_audit"


def test_defender_status_unavailable_returns_partial_security_status(monkeypatch) -> None:
    _mock_reachability(monkeypatch)
    module = _WinrmModule(_security_outputs(), failing_commands={DEFENDER_STATUS_COMMAND})
    _mock_winrm_import(monkeypatch, module)

    result = audit_windows_host(
        target="192.0.2.80",
        resolved_ip="192.0.2.80",
        username="auditor",
        password="SENSITIVE_VALUE",
        auth_method="winrm",
        collect_security_status=True,
    )

    security_status = result["summary"]["windows_security_status"]
    titles = {finding.title for finding in result["findings"]}

    assert result["status"] == "partial"
    assert result["summary"]["windows_security_status_checked"] is True
    assert result["summary"]["windows_security_status_status"] == "partial"
    assert security_status["security_status_limitations"]
    assert "Windows Security Status Collection Failed" in titles
    assert "SENSITIVE_VALUE" not in str(result)


def test_security_status_commands_do_not_run_if_auth_fails(monkeypatch) -> None:
    _mock_reachability(monkeypatch)
    module = _WinrmModule(_security_outputs(), auth_status=1)
    _mock_winrm_import(monkeypatch, module)

    result = audit_windows_host(
        target="192.0.2.80",
        resolved_ip="192.0.2.80",
        username="auditor",
        password="SENSITIVE_VALUE",
        auth_method="winrm",
        collect_security_status=True,
    )

    assert result["summary"]["winrm_auth_status"] == "auth_failed"
    assert result["summary"]["windows_security_status_checked"] is False
    assert module.sessions[0].ps_commands == []
    assert "SENSITIVE_VALUE" not in str(result)
