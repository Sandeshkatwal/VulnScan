from scanner.auth_redaction import (
    detect_secret_like_auth_material,
    redact_auth_header,
    redact_cookie_value,
    redact_session_profile,
    safe_profile_summary,
)


def test_redacts_bearer_basic_cookie_and_jwt() -> None:
    assert redact_auth_header("Bearer abcdefghijklmnopqrstuvwxyz123456") == "Bearer [REDACTED]"
    assert redact_auth_header("Basic dXNlcjpwYXNz") == "Basic [REDACTED]"
    assert redact_cookie_value("session-value") == "[REDACTED]"
    profile = redact_session_profile({"cookies": {"sessionid": "abc"}, "headers": {"Authorization": "Bearer abc"}, "notes": "jwt eyJaaaaaaaa.eyJbbbbbbbb.cccccccccc"})
    assert profile["cookies"]["sessionid"] == "[REDACTED]"
    assert profile["headers"]["Authorization"] == "Bearer [REDACTED]"
    assert "[REDACTED-JWT]" in profile["notes"]


def test_safe_profile_summary_contains_names_only() -> None:
    summary = safe_profile_summary({"profile_name": "Demo", "target_base_url": "http://127.0.0.1:8000", "cookies": {"sessionid": "abc"}, "headers": {"X-API-Key": "secret"}, "role_label": "standard_user"})
    assert summary["cookie_names"] == ["sessionid"]
    assert summary["header_names"] == ["X-API-Key"]
    assert "abc" not in str(summary)
    assert "secret" not in str(summary)


def test_detect_secret_like_auth_material() -> None:
    assert detect_secret_like_auth_material("Bearer abcdefghijklmnopqrstuvwxyz123456")
    assert detect_secret_like_auth_material("password=something")
