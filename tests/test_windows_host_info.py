import importlib
import socket

from scanner.finding import Finding
from scanner.windows_audit import (
    ERROR_WINDOWS_HOST_INFO_PREREQUISITES,
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
    def __init__(self, auth_status: int = 0, ps_outputs: dict[str, bytes] | None = None) -> None:
        self.auth_status = auth_status
        self.ps_outputs = ps_outputs or {}
        self.sessions = []

    def Session(self, endpoint, **kwargs):
        session = _Session(self.auth_status, self.ps_outputs)
        self.sessions.append(session)
        return session


class _Session:
    def __init__(self, auth_status: int, ps_outputs: dict[str, bytes]) -> None:
        self.auth_status = auth_status
        self.ps_outputs = ps_outputs
        self.ps_commands = []

    def run_cmd(self, command):
        return _Response(self.auth_status, b"LABHOST\r\n" if self.auth_status == 0 else b"")

    def run_ps(self, command):
        self.ps_commands.append(command)
        return _Response(0, self.ps_outputs.get(command, b""))


def _mock_reachability(monkeypatch, reachable_ports: set[int]) -> None:
    def fake_create_connection(address, timeout=0):
        port = int(address[1])
        if port in reachable_ports:
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


def _host_info_outputs() -> dict[str, bytes]:
    return {
        "hostname": b"LABHOST\r\n",
        "whoami": b"workgroup\\auditor\r\n",
        "$PSVersionTable.PSVersion.ToString()": b"5.1.19041.1\r\n",
        (
            "Get-CimInstance Win32_OperatingSystem | "
            "Select-Object Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime, InstallDate | "
            "ConvertTo-Json -Compress"
        ): (
            b'{"Caption":"Microsoft Windows Server 2022 Standard","Version":"10.0.20348",'
            b'"BuildNumber":"20348","OSArchitecture":"64-bit","LastBootUpTime":"2026-05-16T09:00:00Z",'
            b'"InstallDate":"2025-01-01T10:00:00Z"}'
        ),
        (
            "Get-CimInstance Win32_ComputerSystem | "
            "Select-Object Domain, Workgroup, PartOfDomain, Manufacturer, Model | "
            "ConvertTo-Json -Compress"
        ): (
            b'{"Domain":"WORKGROUP","Workgroup":"WORKGROUP","PartOfDomain":false,'
            b'"Manufacturer":"Contoso","Model":"Virtual Machine"}'
        ),
        "Get-TimeZone | Select-Object Id, DisplayName | ConvertTo-Json -Compress": (
            b'{"Id":"GMT Standard Time","DisplayName":"(UTC+00:00) Dublin, Edinburgh, Lisbon, London"}'
        ),
    }


def test_windows_host_info_prerequisites_are_validated() -> None:
    try:
        validate_windows_audit_options(
            windows_audit=True,
            windows_user="auditor",
            windows_password="SENSITIVE_VALUE",
            windows_auth_method="none",
            windows_host_info=True,
        )
    except WindowsAuditConfigurationError as exc:
        assert exc.error_code == ERROR_WINDOWS_HOST_INFO_PREREQUISITES
        assert "SENSITIVE_VALUE" not in str(exc)
    else:
        raise AssertionError("Expected host info prerequisites to raise")


def test_windows_host_info_is_collected_after_winrm_auth(monkeypatch) -> None:
    _mock_reachability(monkeypatch, {5985})
    module = _WinrmModule(ps_outputs=_host_info_outputs())
    _mock_winrm_import(monkeypatch, module)

    result = audit_windows_host(
        target="192.0.2.70",
        resolved_ip="192.0.2.70",
        username="auditor",
        password="SENSITIVE_VALUE",
        domain="WORKGROUP",
        auth_method="winrm",
        collect_host_info=True,
    )

    summary = result["summary"]
    host_info = summary["windows_host_info"]

    assert summary["windows_host_info_collected"] is True
    assert host_info["hostname"] == "LABHOST"
    assert host_info["current_identity"] == "workgroup\\auditor"
    assert host_info["powershell_version"] == "5.1.19041.1"
    assert host_info["os_caption"] == "Microsoft Windows Server 2022 Standard"
    assert host_info["os_version"] == "10.0.20348"
    assert host_info["os_build"] == "20348"
    assert host_info["os_architecture"] == "64-bit"
    assert host_info["part_of_domain"] == "False"
    assert host_info["timezone_id"] == "GMT Standard Time"
    assert "SENSITIVE_VALUE" not in str(result)
    assert len(module.sessions[0].ps_commands) == 6


def test_host_info_finding_uses_standard_model(monkeypatch) -> None:
    _mock_reachability(monkeypatch, {5985})
    module = _WinrmModule(ps_outputs=_host_info_outputs())
    _mock_winrm_import(monkeypatch, module)

    result = audit_windows_host(
        target="192.0.2.70",
        resolved_ip="192.0.2.70",
        username="auditor",
        password="SENSITIVE_VALUE",
        auth_method="winrm",
        collect_host_info=True,
    )

    finding = next(finding for finding in result["findings"] if finding.title == "Windows Host Information Collected")

    assert isinstance(finding, Finding)
    assert finding.source == "windows_audit"


def test_host_info_commands_do_not_run_if_auth_fails(monkeypatch) -> None:
    _mock_reachability(monkeypatch, {5985})
    module = _WinrmModule(auth_status=1, ps_outputs=_host_info_outputs())
    _mock_winrm_import(monkeypatch, module)

    result = audit_windows_host(
        target="192.0.2.70",
        resolved_ip="192.0.2.70",
        username="auditor",
        password="SENSITIVE_VALUE",
        auth_method="winrm",
        collect_host_info=True,
    )

    assert result["summary"]["winrm_auth_status"] == "auth_failed"
    assert result["summary"]["windows_host_info_collected"] is False
    assert module.sessions[0].ps_commands == []
    assert "SENSITIVE_VALUE" not in str(result)
