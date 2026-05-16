import socket

from scanner.finding import Finding
from scanner.windows_audit import (
    WindowsAuditConfigurationError,
    audit_windows_host,
    validate_windows_audit_options,
)


class _FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


def _mock_reachability(monkeypatch, reachable_ports: set[int]) -> None:
    def fake_create_connection(address, timeout=0):
        port = int(address[1])
        if port in reachable_ports:
            return _FakeSocket()
        raise socket.timeout()

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)


def test_smb_reachable_finding_uses_standard_model(monkeypatch) -> None:
    _mock_reachability(monkeypatch, {445})

    result = audit_windows_host(
        target="192.0.2.50",
        resolved_ip="192.0.2.50",
        auth_method="none",
    )

    titles = {finding.title for finding in result["findings"]}
    smb_finding = next(finding for finding in result["findings"] if finding.title == "SMB Service Reachable")

    assert "SMB Service Reachable" in titles
    assert isinstance(smb_finding, Finding)
    assert smb_finding.source == "windows_audit"
    assert smb_finding.affected_port == 445


def test_winrm_reachable_findings(monkeypatch) -> None:
    _mock_reachability(monkeypatch, {5985, 5986})

    result = audit_windows_host(
        target="192.0.2.50",
        resolved_ip="192.0.2.50",
        auth_method="none",
    )

    titles = {finding.title for finding in result["findings"]}

    assert "WinRM HTTP Reachable" in titles
    assert "WinRM HTTPS Reachable" in titles


def test_rdp_reachable_finding(monkeypatch) -> None:
    _mock_reachability(monkeypatch, {3389})

    result = audit_windows_host(
        target="192.0.2.50",
        resolved_ip="192.0.2.50",
        auth_method="none",
    )

    titles = {finding.title for finding in result["findings"]}

    assert "RDP Service Reachable" in titles


def test_invalid_windows_auth_method_raises_friendly_error() -> None:
    try:
        validate_windows_audit_options(
            windows_audit=True,
            windows_user=None,
            windows_password=None,
            windows_auth_method="kerberos",
        )
    except WindowsAuditConfigurationError as exc:
        assert exc.error_code == "WINDOWS_AUTH_METHOD_INVALID"
        assert "Allowed values" in str(exc)
    else:
        raise AssertionError("Expected invalid auth method to raise")


def test_windows_password_without_username_is_rejected() -> None:
    try:
        validate_windows_audit_options(
            windows_audit=True,
            windows_user=None,
            windows_password="SENSITIVE_VALUE",
            windows_auth_method="smb",
        )
    except WindowsAuditConfigurationError as exc:
        assert exc.error_code == "WINDOWS_PASSWORD_WITHOUT_USERNAME"
        assert "SENSITIVE_VALUE" not in str(exc)
    else:
        raise AssertionError("Expected password without username to raise")


def test_windows_audit_does_not_store_password(monkeypatch) -> None:
    _mock_reachability(monkeypatch, {445})

    result = audit_windows_host(
        target="192.0.2.50",
        resolved_ip="192.0.2.50",
        username="auditor",
        password="SENSITIVE_VALUE",
        domain="WORKGROUP",
        auth_method="smb",
    )

    serialized = str(result)

    assert "SENSITIVE_VALUE" not in serialized
    assert result["summary"]["username_used"] == "auditor"
    assert result["summary"]["domain"] == "WORKGROUP"
