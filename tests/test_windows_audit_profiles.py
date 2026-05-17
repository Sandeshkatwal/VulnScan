from typer.testing import CliRunner

from scanner.main import app
from scanner.windows_audit_profiles import (
    WindowsAuditProfileError,
    get_windows_audit_profile,
    resolve_windows_audit_profile,
)


def test_foundation_profile_enables_only_foundation_sections() -> None:
    plan = resolve_windows_audit_profile(profile_name="foundation", auth_method="none")

    assert plan["profile_name"] == "foundation"
    assert plan["profile_enabled_sections"] == ["windows_service_reachability"]
    assert plan["collect_host_info"] is False
    assert plan["collect_security_status"] is False
    assert plan["collect_policy_status"] is False
    assert plan["collect_registry_audit"] is False


def test_standard_profile_enables_host_security_and_patch_with_winrm() -> None:
    plan = resolve_windows_audit_profile(profile_name="standard", auth_method="winrm")

    assert "windows_host_info" in plan["profile_enabled_sections"]
    assert "windows_security_status" in plan["profile_enabled_sections"]
    assert "windows_patch_status" in plan["profile_enabled_sections"]
    assert plan["collect_host_info"] is True
    assert plan["collect_security_status"] is True
    assert plan["collect_patch_status"] is True


def test_detailed_profile_enables_policy_and_registry_with_winrm() -> None:
    plan = resolve_windows_audit_profile(profile_name="detailed", auth_method="winrm")

    assert "windows_policy_status" in plan["profile_enabled_sections"]
    assert "windows_registry_audit" in plan["profile_enabled_sections"]
    assert plan["collect_policy_status"] is True
    assert plan["collect_registry_audit"] is True


def test_invalid_windows_audit_profile_is_rejected() -> None:
    try:
        get_windows_audit_profile("aggressive")
    except WindowsAuditProfileError as exc:
        assert "foundation, standard, detailed" in str(exc)
    else:
        raise AssertionError("Expected invalid Windows audit profile to be rejected")


def test_manual_override_extends_foundation_profile() -> None:
    plan = resolve_windows_audit_profile(
        profile_name="foundation",
        auth_method="winrm",
        manual_registry_audit=True,
    )

    assert "windows_registry_audit" in plan["profile_enabled_sections"]
    assert plan["collect_registry_audit"] is True
    assert plan["enabled_by_profile"]["windows_registry_audit"] is False
    assert plan["enabled_by_manual_flag"]["windows_registry_audit"] is True
    assert plan["profile_manual_overrides"] == ["windows_registry_audit"]


def test_windows_audit_profile_without_windows_audit_prints_friendly_message(monkeypatch) -> None:
    def fake_scan_tcp_ports(target: str) -> dict:
        return {
            "host": target,
            "resolved_ip": "127.0.0.1",
            "duration_seconds": 0.01,
            "open_ports": [],
        }

    monkeypatch.setattr("scanner.main.scan_tcp_ports", fake_scan_tcp_ports)
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["scan", "--target", "127.0.0.1", "--windows-audit-profile", "foundation"],
    )

    assert result.exit_code == 0
    assert "Windows audit profiles apply only when --windows-audit is provided" in result.output


def test_invalid_profile_cli_shows_allowed_values() -> None:
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["scan", "--target", "127.0.0.1", "--windows-audit", "--windows-audit-profile", "aggressive"],
    )

    assert result.exit_code == 1
    assert "foundation, standard, detailed" in result.output
