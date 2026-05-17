import importlib
import socket

from scanner.finding import Finding
from scanner.main import _build_windows_audit_summary
from scanner.windows_audit import (
    ERROR_WINDOWS_POLICY_STATUS_PREREQUISITES,
    WindowsAuditConfigurationError,
    audit_windows_host,
    validate_windows_audit_options,
)
from scanner.windows_policy_audit import (
    NET_ACCOUNTS_COMMAND,
    build_windows_policy_findings,
    parse_net_accounts_output,
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
    def __init__(self, cmd_outputs: dict[str, bytes], auth_status: int = 0) -> None:
        self.cmd_outputs = cmd_outputs
        self.auth_status = auth_status
        self.sessions = []

    def Session(self, endpoint, **kwargs):
        session = _Session(self.cmd_outputs, self.auth_status)
        self.sessions.append(session)
        return session


class _Session:
    def __init__(self, cmd_outputs: dict[str, bytes], auth_status: int) -> None:
        self.cmd_outputs = cmd_outputs
        self.auth_status = auth_status
        self.cmd_commands = []

    def run_cmd(self, command):
        self.cmd_commands.append(command)
        if command == "hostname":
            return _Response(self.auth_status, b"LABHOST\r\n" if self.auth_status == 0 else b"")
        return _Response(0, self.cmd_outputs.get(command, b""))


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


def _net_accounts_output(computer_role: str = "WORKSTATION") -> str:
    return f"""
Force user logoff how long after time expires?       Never
Minimum password age (days)                          0
Maximum password age (days)                          400
Minimum password length                              8
Length of password history maintained                3
Lockout threshold                                    Never
Lockout duration (minutes)                           30
Lockout observation window (minutes)                 30
Computer role                                        {computer_role}
The command completed successfully.
"""


def test_windows_policy_status_prerequisites_are_validated() -> None:
    try:
        validate_windows_audit_options(
            windows_audit=True,
            windows_user="auditor",
            windows_password="SENSITIVE_VALUE",
            windows_auth_method="none",
            windows_policy_status=True,
        )
    except WindowsAuditConfigurationError as exc:
        assert exc.error_code == ERROR_WINDOWS_POLICY_STATUS_PREREQUISITES
        assert "SENSITIVE_VALUE" not in str(exc)
    else:
        raise AssertionError("Expected policy status prerequisites to raise")


def test_net_accounts_parser_extracts_policy_values() -> None:
    status = parse_net_accounts_output(_net_accounts_output("MEMBER SERVER"))

    assert status["minimum_password_length"] == 8
    assert status["maximum_password_age_days"] == 400
    assert status["password_history_length"] == 3
    assert status["lockout_threshold"] == 0
    assert status["lockout_duration_minutes"] == 30
    assert status["lockout_observation_window_minutes"] == 30
    assert status["computer_role"] == "MEMBER SERVER"


def test_windows_policy_status_is_collected_after_winrm_auth(monkeypatch) -> None:
    _mock_reachability(monkeypatch)
    module = _WinrmModule({NET_ACCOUNTS_COMMAND: _net_accounts_output().encode("utf-8")})
    _mock_winrm_import(monkeypatch, module)

    result = audit_windows_host(
        target="192.0.2.90",
        resolved_ip="192.0.2.90",
        username="auditor",
        password="SENSITIVE_VALUE",
        auth_method="winrm",
        collect_policy_status=True,
    )

    summary = result["summary"]

    assert summary["windows_policy_status_checked"] is True
    assert summary["windows_policy_status"]["minimum_password_length"] == 8
    assert NET_ACCOUNTS_COMMAND in module.sessions[0].cmd_commands
    assert "SENSITIVE_VALUE" not in str(result)


def test_policy_commands_do_not_run_if_auth_fails(monkeypatch) -> None:
    _mock_reachability(monkeypatch)
    module = _WinrmModule({NET_ACCOUNTS_COMMAND: _net_accounts_output().encode("utf-8")}, auth_status=1)
    _mock_winrm_import(monkeypatch, module)

    result = audit_windows_host(
        target="192.0.2.90",
        resolved_ip="192.0.2.90",
        username="auditor",
        password="SENSITIVE_VALUE",
        auth_method="winrm",
        collect_policy_status=True,
    )

    assert result["summary"]["winrm_auth_status"] == "auth_failed"
    assert result["summary"]["windows_policy_status_checked"] is False
    assert module.sessions[0].cmd_commands == ["hostname"]
    assert "SENSITIVE_VALUE" not in str(result)


def test_policy_findings_use_standard_model_and_weak_thresholds() -> None:
    policy_status = parse_net_accounts_output(_net_accounts_output())
    findings = build_windows_policy_findings("192.0.2.90", policy_status)
    titles = {finding.title for finding in findings}

    assert "Windows Local Security Policy Reviewed" in titles
    assert "Windows Minimum Password Length May Be Weak" in titles
    assert "Windows Maximum Password Age May Be Weak" in titles
    assert "Windows Password History Requirement May Be Weak" in titles
    assert "Windows Account Lockout Threshold Not Configured" in titles
    assert all(isinstance(finding, Finding) for finding in findings)
    assert {finding.source for finding in findings} == {"windows_policy_audit"}


def test_domain_policy_context_finding() -> None:
    policy_status = parse_net_accounts_output(_net_accounts_output("MEMBER SERVER"))
    titles = {finding.title for finding in build_windows_policy_findings("192.0.2.90", policy_status)}

    assert "Windows Policy May Be Controlled by Domain" in titles


def test_partial_policy_output_adds_collection_failed_finding() -> None:
    policy_status = parse_net_accounts_output("Minimum password length                              14")
    titles = {finding.title for finding in build_windows_policy_findings("192.0.2.90", policy_status)}

    assert policy_status["minimum_password_length"] == 14
    assert "Windows Local Security Policy Collection Failed" in titles


def test_incomplete_policy_output_returns_partial_status(monkeypatch) -> None:
    _mock_reachability(monkeypatch)
    module = _WinrmModule({NET_ACCOUNTS_COMMAND: b"Minimum password length                              14"})
    _mock_winrm_import(monkeypatch, module)

    result = audit_windows_host(
        target="192.0.2.90",
        resolved_ip="192.0.2.90",
        username="auditor",
        password="SENSITIVE_VALUE",
        auth_method="winrm",
        collect_policy_status=True,
    )

    assert result["status"] == "partial"
    assert result["summary"]["windows_policy_status_checked"] is True
    assert result["summary"]["windows_policy_status_status"] == "partial"
    assert "Windows Local Security Policy Collection Failed" in {finding.title for finding in result["findings"]}


def test_windows_policy_status_appears_in_windows_audit_summary() -> None:
    scan_result = {
        "host": "192.0.2.90",
        "windows_audit": {
            "status": "success",
            "summary": {
                "enabled": True,
                "status": "success",
                "windows_policy_status_checked": True,
                "windows_policy_status": {"minimum_password_length": 14},
            },
        },
        "windows_findings": [{"title": "Windows Local Security Policy Reviewed", "source": "windows_policy_audit"}],
    }

    summary = _build_windows_audit_summary(scan_result)

    assert summary["windows_policy_status_checked"] is True
    assert summary["windows_policy_status"]["minimum_password_length"] == 14
    assert "SENSITIVE_VALUE" not in str(summary)
