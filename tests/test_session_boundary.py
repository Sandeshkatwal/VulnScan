from scanner.session_boundary import classify_session_boundary
from scanner.session_profiles import load_session_profile


PROFILE = load_session_profile("data/auth_profiles/sample_session_profile.redacted.json")


def test_session_boundary_allows_allowed_host_path() -> None:
    result = classify_session_boundary("http://127.0.0.1:8000/dashboard", PROFILE, start_url="http://127.0.0.1:8000/dashboard")

    assert result["allowed"] is True


def test_session_boundary_blocks_unknown_host() -> None:
    result = classify_session_boundary("http://example.test/dashboard", PROFILE, start_url="http://127.0.0.1:8000/dashboard")

    assert result["allowed"] is False
    assert result["event_type"] == "cross_host_skipped"


def test_session_boundary_blocks_logout_delete_and_payment_paths() -> None:
    for path in ("/logout", "/account/delete", "/checkout"):
        result = classify_session_boundary(f"http://127.0.0.1:8000{path}", PROFILE, start_url="http://127.0.0.1:8000/dashboard")
        assert result["allowed"] is False
        assert result["event_type"] in {"logout_path_skipped", "destructive_path_skipped", "blocked_path"}


def test_session_boundary_blocks_non_get_methods() -> None:
    result = classify_session_boundary("http://127.0.0.1:8000/dashboard", PROFILE, start_url="http://127.0.0.1:8000/dashboard", method="POST")

    assert result["allowed"] is False
    assert result["matched_rule"] == "method"
