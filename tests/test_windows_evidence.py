from scanner.finding import finding_to_dict
from scanner.windows_audit import _security_status_findings, _winrm_auth_finding
from scanner.windows_policy_audit import build_windows_policy_findings
from scanner.windows_registry_audit import build_registry_findings, evaluate_registry_audit, load_registry_template


def test_windows_firewall_finding_evidence_is_concise() -> None:
    findings = _security_status_findings(
        "192.0.2.10",
        {
            "authenticated": True,
            "security_status_status": "checked",
            "security_status": {
                "firewall_profiles": [{"name": "Domain", "enabled": "False"}],
                "defender_service": {"status": "Running", "start_type": "Automatic"},
                "defender_status": {},
            },
        },
    )
    payload = [finding_to_dict(finding) for finding in findings]
    firewall = next(item for item in payload if item["title"] == "Windows Firewall Profile Disabled")

    assert firewall["evidence"] == "Firewall Domain profile observed Enabled=False; expected Enabled=True."
    assert len(firewall["evidence"]) <= 300
    assert firewall["evidence_details"]["raw_output_included"] is False


def test_windows_defender_finding_evidence_is_concise() -> None:
    findings = _security_status_findings(
        "192.0.2.10",
        {
            "authenticated": True,
            "security_status_status": "checked",
            "security_status": {
                "firewall_profiles": [],
                "defender_service": {"status": "Stopped", "start_type": "Automatic"},
                "defender_status": {"real_time_protection_enabled": "False"},
            },
        },
    )
    payload = [finding_to_dict(finding) for finding in findings]

    assert any(
        item["evidence"] == "WinDefend service observed Status=Stopped; expected Running."
        for item in payload
    )
    assert any(
        item["evidence"] == "RealTimeProtectionEnabled=False; expected True."
        for item in payload
    )
    assert all(len(item["evidence"]) <= 300 for item in payload)


def test_windows_policy_finding_evidence_is_concise() -> None:
    findings = build_windows_policy_findings(
        "192.0.2.10",
        {
            "checked": True,
            "minimum_password_age_days": 1,
            "maximum_password_age_days": 90,
            "minimum_password_length": 8,
            "password_history_length": 10,
            "lockout_threshold": 5,
            "lockout_duration_minutes": 15,
            "lockout_observation_window_minutes": 15,
            "computer_role": "WORKSTATION",
        },
    )
    payload = [finding_to_dict(finding) for finding in findings]

    assert any(
        item["evidence"] == "Minimum password length observed 8; expected at least 12."
        for item in payload
    )
    assert all(len(item["evidence"]) <= 300 for item in payload)


def test_windows_registry_finding_evidence_is_concise() -> None:
    template = load_registry_template("templates/windows_registry/basic_security_indicators.json")
    registry_audit = evaluate_registry_audit(
        template,
        {
            "WIN-REG-001": {"present": True, "observed_value": 0},
            "WIN-REG-002": {"present": True, "observed_value": 1},
            "WIN-REG-003": {"present": True, "observed_value": 0},
            "WIN-REG-004": {"present": True, "observed_value": 1},
            "WIN-REG-005": {"present": True, "observed_value": 0},
        },
    )
    payload = [finding_to_dict(finding) for finding in build_registry_findings("192.0.2.10", registry_audit)]
    mismatch = next(item for item in payload if item["title"] == "Remote Desktop NLA Setting Indicator")

    assert "Registry value HKLM\\" in mismatch["evidence"]
    assert "observed 0; expected 1" in mismatch["evidence"]
    assert len(mismatch["evidence"]) <= 300
    assert mismatch["evidence_details"]["raw_output_included"] is False


def test_winrm_auth_failure_evidence_redacts_secret_detail() -> None:
    finding = _winrm_auth_finding(
        "192.0.2.10",
        {
            "status": "auth_failed",
            "safe_detail": "Password=Secret123",
        },
    )
    payload = finding_to_dict(finding)

    assert payload["evidence"] == "WinRM authentication attempt failed."
    assert "Secret123" not in str(payload)
