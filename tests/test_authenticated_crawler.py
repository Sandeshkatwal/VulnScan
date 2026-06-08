from scanner.authenticated_crawler import authenticated_crawl, detect_session_expiry
from scanner.session_profiles import load_session_profile


class FakeResponse:
    def __init__(self, url: str, status_code: int = 200, text: str = "", headers: dict[str, str] | None = None):
        self.url = url
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"Content-Type": "text/html"}
        self.history = []


class FakeSession:
    def __init__(self, responses: dict[str, FakeResponse]):
        self.responses = responses
        self.requests: list[dict[str, object]] = []

    def get(self, url: str, **kwargs):
        self.requests.append({"method": "GET", "url": url, **kwargs})
        return self.responses.get(url, FakeResponse(url, 404, "<title>Not Found</title>"))


def _profile() -> dict:
    return load_session_profile("data/auth_profiles/sample_session_profile.redacted.json")


def test_authenticated_crawl_get_only_skips_destructive_links_and_redacts() -> None:
    session = FakeSession(
        {
            "http://127.0.0.1:8000/dashboard": FakeResponse(
                "http://127.0.0.1:8000/dashboard",
                200,
                "<title>Dashboard</title><a href='/account'>Account</a><a href='/logout'>Logout</a><form method='post' action='/update'><input name='token' value='form-secret-marker'></form>",
            ),
            "http://127.0.0.1:8000/account": FakeResponse("http://127.0.0.1:8000/account", 401, "<title>Login</title>Please log in"),
        }
    )

    result = authenticated_crawl(
        "http://127.0.0.1:8000/dashboard",
        _profile(),
        {"max_pages": 5, "max_depth": 2, "request_delay": 0, "dry_run": False},
        session=session,
    )

    assert {request["method"] for request in session.requests} == {"GET"}
    assert result["authenticated_crawl_summary"]["pages_crawled"] == 2
    assert result["authenticated_crawl_summary"]["skipped_destructive_count"] >= 1
    assert result["authenticated_crawl_summary"]["session_expiry_indicators_count"] == 1
    assert "Logout" not in [request["url"] for request in session.requests]
    assert "form-secret-marker" not in str(result).lower()
    assert "[REDACTED]" in str(result)


def test_authenticated_crawl_respects_max_pages_and_max_depth() -> None:
    session = FakeSession(
        {
            "http://127.0.0.1:8000/dashboard": FakeResponse("http://127.0.0.1:8000/dashboard", 200, "<a href='/account'>Account</a>"),
            "http://127.0.0.1:8000/account": FakeResponse("http://127.0.0.1:8000/account", 200, "<a href='/settings'>Settings</a>"),
        }
    )

    result = authenticated_crawl(
        "http://127.0.0.1:8000/dashboard",
        _profile(),
        {"max_pages": 1, "max_depth": 0, "request_delay": 0},
        session=session,
    )

    assert result["authenticated_crawl_summary"]["pages_crawled"] == 1
    assert len(session.requests) == 1


def test_authenticated_crawl_respects_same_origin_only() -> None:
    session = FakeSession(
        {
            "http://127.0.0.1:8000/dashboard": FakeResponse("http://127.0.0.1:8000/dashboard", 200, "<a href='http://127.0.0.1:9000/account'>Other</a>"),
        }
    )

    result = authenticated_crawl("http://127.0.0.1:8000/dashboard", _profile(), {"request_delay": 0}, session=session)

    assert any(event["event_type"] == "cross_host_skipped" for event in result["authenticated_boundary_events"])


def test_authenticated_crawl_enforces_program_scope_before_request() -> None:
    session = FakeSession(
        {
            "http://outside.example/dashboard": FakeResponse("http://outside.example/dashboard", 200, "<title>Other</title>"),
        }
    )
    profile = _profile()
    profile["allowed_hosts"] = ["outside.example"]

    result = authenticated_crawl(
        "http://outside.example/dashboard",
        profile,
        {"request_delay": 0, "scope_file": "data/programs/sample_program_scope.json", "enforce_scope": True, "same_origin_only": False},
        session=session,
    )

    assert session.requests == []
    assert result["authenticated_crawl_summary"]["pages_crawled"] == 0
    assert any(event["event_type"] == "out_of_scope_skipped" for event in result["authenticated_boundary_events"])


def test_authenticated_crawl_detects_login_location_redirect_without_following() -> None:
    session = FakeSession(
        {
            "http://127.0.0.1:8000/dashboard": FakeResponse(
                "http://127.0.0.1:8000/dashboard",
                302,
                "",
                {"Content-Type": "text/html", "Location": "/login"},
            ),
        }
    )

    result = authenticated_crawl("http://127.0.0.1:8000/dashboard", _profile(), {"request_delay": 0}, session=session)

    assert result["authenticated_crawl_results"][0]["session_expiry_indicator"] is True
    assert result["authenticated_crawl_results"][0]["final_url"] == "http://127.0.0.1:8000/login"
    assert any(event["event_type"] == "auth_redirect_detected" for event in result["authenticated_boundary_events"])


def test_session_expiry_detection_signals() -> None:
    assert detect_session_expiry(FakeResponse("http://127.0.0.1:8000/account", 401), "http://127.0.0.1:8000/account", "", "")["session_expiry_indicator"]
    assert detect_session_expiry(FakeResponse("http://127.0.0.1:8000/login", 302), "http://127.0.0.1:8000/login", "", "")["session_expiry_indicator"]
    assert detect_session_expiry(FakeResponse("http://127.0.0.1:8000/account", 200), "http://127.0.0.1:8000/account", "Sign in", "sign in to continue")["session_expiry_indicator"]
