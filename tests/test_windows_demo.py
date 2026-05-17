from typer.testing import CliRunner

from scanner.finding import Finding
from scanner.main import app
from scanner.windows_demo import DEMO_NOTICE, build_windows_demo_result
from scanner.windows_audit_profiles import resolve_windows_audit_profile


def _profile_summary() -> dict:
    plan = resolve_windows_audit_profile(profile_name="detailed", auth_method="winrm")
    return {
        "windows_audit_profile": plan["profile_name"],
        "profile_description": plan["profile_description"],
        "profile_enabled_sections": plan["profile_enabled_sections"],
        "profile_skipped_sections": plan["profile_skipped_sections"],
        "profile_manual_overrides": plan["profile_manual_overrides"],
        "profile_default_timeout_seconds": plan["profile_default_timeout_seconds"],
        "profile_effective_audit_timeout_seconds": 180.0,
        "profile_section_labels": plan["section_labels"],
        "profile_section_enabled_by_profile": plan["enabled_by_profile"],
        "profile_section_enabled_by_manual_flag": plan["enabled_by_manual_flag"],
        "profile_section_skipped_reasons": plan["skipped_reasons"],
    }


def test_windows_demo_result_includes_demo_mode_and_sections() -> None:
    result = build_windows_demo_result(
        target="demo-windows",
        profile_summary=_profile_summary(),
        audit_timeout_seconds=180.0,
    )

    assert result["demo_mode"] is True
    assert result["demo_notice"] == DEMO_NOTICE
    assert result["windows_audit_sections"]
    assert result["summary"]["windows_host_info"]["hostname"] == "WIN-DEMO-01"
    serialized = str(result).lower()
    assert "secret123" not in serialized
    assert "authorization:" not in serialized
    assert "private key" not in serialized
    assert "token=" not in serialized


def test_windows_demo_findings_use_standard_finding_model() -> None:
    result = build_windows_demo_result(
        target="demo-windows",
        profile_summary=_profile_summary(),
        audit_timeout_seconds=180.0,
    )

    assert result["findings"]
    assert all(isinstance(finding, Finding) for finding in result["findings"])
    assert {finding.source for finding in result["findings"]} >= {
        "windows_demo",
        "windows_audit",
        "windows_security_audit",
        "windows_policy_audit",
        "windows_registry_audit",
    }


def test_windows_demo_cli_does_not_call_network_or_windows_audit(monkeypatch) -> None:
    def fail_scan_tcp_ports(*args, **kwargs):
        raise AssertionError("scan_tcp_ports must not be called in Windows demo mode")

    def fail_audit_windows_host(*args, **kwargs):
        raise AssertionError("audit_windows_host must not be called in Windows demo mode")

    monkeypatch.setattr("scanner.main.scan_tcp_ports", fail_scan_tcp_ports)
    monkeypatch.setattr("scanner.main.audit_windows_host", fail_audit_windows_host)
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["scan", "--target", "demo-windows", "--windows-audit", "--windows-demo"],
    )

    assert result.exit_code == 0
    assert "DEMO MODE: No real target was scanned." in result.output
    assert "Demo Mode Notice" in result.output


def test_windows_demo_cli_does_not_require_credentials(monkeypatch) -> None:
    monkeypatch.setattr(
        "scanner.main.scan_tcp_ports",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network scan called")),
    )
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["scan", "--target", "demo-windows", "--windows-audit", "--windows-demo", "--windows-audit-profile", "detailed"],
    )

    assert result.exit_code == 0
    assert "WIN-DEMO-01" in result.output
