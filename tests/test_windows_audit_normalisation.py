from scanner.main import _build_windows_audit_summary, _windows_profile_summary_fields
from scanner.windows_audit_profiles import resolve_windows_audit_profile
from scanner.windows_result import build_windows_audit_sections


def test_windows_audit_sections_appears_when_windows_audit_used() -> None:
    profile_plan = resolve_windows_audit_profile(profile_name="standard", auth_method="winrm")
    scan_result = {
        "host": "127.0.0.1",
        "windows_findings": [],
        "windows_audit": {
            "enabled": True,
            "status": "success",
            "summary": {
                **_windows_profile_summary_fields(profile_plan=profile_plan, audit_timeout_seconds=120.0),
                "sections": {
                    "service_reachability": {"status": "success", "checks_planned": 5, "checks_completed": 5},
                    "winrm_authentication": {"status": "skipped", "checks_planned": 0, "checks_completed": 0},
                }
            },
            "findings": [],
            "errors": [],
        },
    }
    scan_result["windows_audit_sections"] = build_windows_audit_sections(
        windows_result=scan_result["windows_audit"],
        windows_findings=[],
    )
    summary = _build_windows_audit_summary(scan_result)

    assert scan_result["windows_audit_sections"]
    assert summary["windows_audit_sections"][0]["section_id"] == "windows_service_reachability"
    assert summary["windows_audit_profile"] == "standard"
    assert "windows_host_info" in summary["profile_enabled_sections"]


def test_windows_audit_sections_include_profile_enablement_metadata() -> None:
    profile_plan = resolve_windows_audit_profile(
        profile_name="foundation",
        auth_method="winrm",
        manual_registry_audit=True,
    )
    sections = build_windows_audit_sections(
        windows_result={
            "enabled": True,
            "summary": {
                **_windows_profile_summary_fields(profile_plan=profile_plan, audit_timeout_seconds=45.0),
                "sections": {
                    "service_reachability": {"status": "success", "checks_planned": 5, "checks_completed": 5},
                    "registry_audit": {"status": "success", "checks_planned": 1, "checks_completed": 1},
                },
            },
            "findings": [],
            "errors": [],
        }
    )

    by_id = {section["section_id"]: section for section in sections}
    assert by_id["windows_service_reachability"]["enabled_by_profile"] is True
    assert by_id["windows_registry_audit"]["enabled_by_profile"] is False
    assert by_id["windows_registry_audit"]["enabled_by_manual_flag"] is True
    assert by_id["windows_policy_status"]["skipped_reason"] == "not enabled by selected profile"


def test_existing_windows_findings_list_remains_intact() -> None:
    finding = {
        "id": "FINDING-0001",
        "title": "Windows Firewall Reviewed",
        "severity": "Informational",
        "category": "Windows Security Status",
        "source": "windows_security_audit",
        "risk_score": 0,
        "risk_label": "Informational",
    }
    sections = build_windows_audit_sections(
        windows_result={
            "enabled": True,
            "summary": {"sections": {"security_status": {"status": "success", "checks_planned": 3, "checks_completed": 3}}},
            "findings": [finding],
            "errors": [],
        },
        windows_findings=[finding],
    )

    security = next(section for section in sections if section["section_id"] == "windows_security_status")
    assert security["findings"][0]["title"] == "Windows Firewall Reviewed"
    assert finding["title"] == "Windows Firewall Reviewed"
