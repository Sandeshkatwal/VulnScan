from scanner.audit_profiles import AuditProfileError, get_audit_profile


def test_standard_profile_is_default() -> None:
    profile = get_audit_profile(None)

    assert profile.name == "standard"
    assert profile.checks["package_checks"] is True
    assert profile.checks["password_policy_checks"] is False


def test_basic_profile_skips_deeper_checks() -> None:
    profile = get_audit_profile("basic")

    assert profile.checks["ssh_hardening"] is True
    assert profile.checks["package_checks"] is False
    assert profile.checks["firewall_checks"] is False
    assert profile.default_audit_timeout_seconds == 30.0
    assert profile.checks_skipped


def test_detailed_profile_enables_deeper_checks() -> None:
    profile = get_audit_profile("detailed")

    assert profile.checks["password_policy_checks"] is True
    assert profile.checks["temp_directory_checks"] is True
    assert profile.checks["cleartext_service_checks"] is True
    assert profile.default_audit_timeout_seconds == 90.0


def test_invalid_profile_raises_friendly_error() -> None:
    try:
        get_audit_profile("unsafe")
    except AuditProfileError as exc:
        assert exc.error_code == "SSH_PROFILE_INVALID"
        assert "Allowed values" in str(exc)
    else:
        raise AssertionError("Expected invalid audit profile to raise")
