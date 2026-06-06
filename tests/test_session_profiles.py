from scanner.session_profiles import load_session_profile, validate_session_profile


def test_load_redacted_sample_session_profile() -> None:
    profile = load_session_profile("data/auth_profiles/sample_session_profile.redacted.json")
    validation = validate_session_profile(profile)

    assert validation["valid"] is True
    assert validation["session_profile"]["role_label"] == "standard_user"
    assert validation["session_profile"]["cookie_names"] == ["sessionid"]
    assert "REDACTED" not in str(validation["session_profile"].get("headers", ""))
