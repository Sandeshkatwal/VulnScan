from scanner.main import _build_windows_audit_summary
from scanner.windows_result import build_windows_audit_sections


def test_windows_audit_sections_appears_when_windows_audit_used() -> None:
    scan_result = {
        "host": "127.0.0.1",
        "windows_findings": [],
        "windows_audit": {
            "enabled": True,
            "status": "success",
            "summary": {
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
