from scanner.authenticated_scope import classify_auth_boundary, classify_auth_required_endpoint, is_auth_blocked_path, is_url_allowed_by_auth_profile
from scanner.session_profiles import load_session_profile


def _profile():
    return load_session_profile("data/auth_profiles/sample_session_profile.redacted.json")


def test_allowed_host_and_dashboard_path() -> None:
    result = classify_auth_boundary("http://127.0.0.1:8000/dashboard", _profile())
    assert result["allowed_by_profile"] is True
    assert is_url_allowed_by_auth_profile("http://127.0.0.1:8000/dashboard", _profile())


def test_unknown_host_is_blocked() -> None:
    result = classify_auth_boundary("http://example.com/dashboard", _profile())
    assert result["allowed_by_profile"] is False


def test_logout_and_delete_paths_are_blocked() -> None:
    assert is_auth_blocked_path("http://127.0.0.1:8000/logout", _profile())
    assert is_auth_blocked_path("http://127.0.0.1:8000/account/delete", _profile())


def test_auth_required_endpoint_detection_status_and_redirect() -> None:
    assert classify_auth_required_endpoint({"url": "http://127.0.0.1:8000/private", "status_code": 401}, _profile())["auth_required_classification"] == "auth_required_likely"
    assert classify_auth_required_endpoint({"url": "http://127.0.0.1:8000/private", "status_code": 302, "redirect_url": "/login"}, _profile())["auth_required_classification"] == "auth_required_likely"


def test_authenticated_crawl_source_classifies_authenticated_likely() -> None:
    result = classify_auth_required_endpoint(
        {"url": "http://127.0.0.1:8000/help", "status_code": 200, "source": "authenticated_crawl"},
        _profile(),
    )

    assert result["auth_required_classification"] == "authenticated_likely"
    assert result["auth_required_likely"] is False
