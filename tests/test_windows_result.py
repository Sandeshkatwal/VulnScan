from scanner.windows_result import (
    WindowsAuditSectionResult,
    WindowsCheckResult,
    build_windows_audit_sections,
)


def test_windows_audit_section_result_serialises_to_dictionary() -> None:
    result = WindowsAuditSectionResult(
        section_id="windows_security_status",
        section_name="Windows Security Status",
        source="windows_security_audit",
        status="success",
        checks_planned=3,
        checks_completed=3,
    ).to_dict()

    assert result["section_id"] == "windows_security_status"
    assert result["status"] == "success"
    assert result["checks_completed"] == 3


def test_windows_check_result_serialises_to_dictionary_without_raw_output() -> None:
    result = WindowsCheckResult(
        check_id="defender_status",
        check_name="Defender status",
        source="windows_security_audit",
        status="success",
        command_name="Get-MpComputerStatus",
        command_used_safe_label="Get-MpComputerStatus selected status fields",
        evidence_summary="Defender status fields collected.",
    ).to_dict()

    assert result["check_id"] == "defender_status"
    assert result["command_used_safe_label"] == "Get-MpComputerStatus selected status fields"
    assert "raw_output" not in result


def test_password_is_never_present_in_section_result() -> None:
    section = WindowsAuditSectionResult(
        section_id="winrm_authentication",
        section_name="WinRM Authentication",
        source="windows_audit",
        status="failed",
        errors=[
            {
                "error_code": "WINDOWS_AUTH_FAILED",
                "message": "Password=Secret123 failed",
                "safe_detail": "password Secret123",
                "source": "windows_audit",
                "section_id": "winrm_authentication",
            }
        ],
    ).to_dict()

    serialized = str(section)
    assert "Secret123" not in serialized
    assert "Password=" not in serialized


def test_build_windows_audit_sections_from_fake_result() -> None:
    sections = build_windows_audit_sections(
        windows_result={
            "enabled": True,
            "summary": {
                "sections": {
                    "service_reachability": {"status": "success", "checks_planned": 5, "checks_completed": 5},
                    "winrm_authentication": {"status": "success", "checks_planned": 1, "checks_completed": 1},
                    "host_information": {"status": "success", "checks_planned": 6, "checks_completed": 6},
                }
            },
            "findings": [],
            "errors": [],
        }
    )

    by_id = {section["section_id"]: section for section in sections}
    assert by_id["windows_service_reachability"]["status"] == "success"
    assert by_id["winrm_authentication"]["status"] == "success"
    assert by_id["windows_host_info"]["checks_completed"] == 6
