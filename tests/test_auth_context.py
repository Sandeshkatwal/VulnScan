from scanner.auth_context import build_auth_context, validate_auth_context_scope
from scanner.session_profiles import load_session_profile


def test_build_auth_context_redacted() -> None:
    context = build_auth_context(load_session_profile("data/auth_profiles/sample_session_profile.redacted.json"))
    assert context["enabled"] is True
    assert context["role_label"] == "standard_user"
    assert context["cookie_names"] == ["sessionid"]
    assert "Bearer [REDACTED]" not in str(context)


def test_validate_auth_context_scope() -> None:
    result = validate_auth_context_scope(load_session_profile("data/auth_profiles/sample_session_profile.redacted.json"), "http://127.0.0.1:8000/dashboard")
    assert result["allowed_by_profile"] is True
