from scanner.finding import Finding
from scanner.web_crawler import crawl_web
from scanner.web_form_audit import audit_web_forms


class FakeResponse:
    def __init__(self, text: str) -> None:
        self.text = text
        self.status_code = 200
        self.headers = {"Content-Type": "text/html"}


class FakeSession:
    def __init__(self, html: str, url: str = "https://example.test/") -> None:
        self.responses = {url: FakeResponse(html)}
        self.get_calls: list[str] = []
        self.post_calls: list[str] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.get_calls.append(url)
        return self.responses[url]

    def post(self, url: str, **kwargs: object) -> None:
        self.post_calls.append(url)
        raise AssertionError("Forms must not be submitted.")


def _forms_from_html(html: str, url: str = "https://example.test/") -> tuple[dict[str, object], FakeSession]:
    session = FakeSession(html=html, url=url)
    crawl = crawl_web(start_url=url, max_pages=1, session=session)
    result = audit_web_forms(crawl["crawled_pages"])
    return result, session


def test_extracts_method_and_resolves_relative_action() -> None:
    result, _session = _forms_from_html('<form method="post" action="/login"><input name="username"></form>')

    form = result["web_form_results"][0]
    assert form["method"] == "POST"
    assert form["action"] == "/login"
    assert form["resolved_action_url"] == "https://example.test/login"


def test_detects_external_action_host() -> None:
    result, _session = _forms_from_html('<form action="https://forms.example.net/submit"><input name="email"></form>')

    form = result["web_form_results"][0]
    assert form["is_internal_action"] is False
    assert form["action_host"] == "forms.example.net"
    assert "External Form Action Discovered" in form["issues"]


def test_detects_https_page_submitting_to_http_action() -> None:
    result, _session = _forms_from_html('<form method="post" action="http://example.test/login"><input type="password" name="password"></form>')

    form = result["web_form_results"][0]
    assert form["sends_to_http_from_https"] is True
    assert "HTTPS Page Form Submits to HTTP" in form["issues"]


def test_detects_password_file_hidden_and_csrf_fields_without_values() -> None:
    result, session = _forms_from_html(
        """
        <form method="post" action="/upload" enctype="multipart/form-data">
          <input type="hidden" name="csrf_token" value="DoNotStore">
          <input type="hidden" name="session_secret" value="AlsoDoNotStore">
          <input type="password" name="password">
          <input type="file" name="avatar">
        </form>
        """
    )

    form = result["web_form_results"][0]
    assert form["has_password_field"] is True
    assert form["has_file_upload"] is True
    assert form["hidden_input_count"] == 2
    assert form["csrf_token_like_fields"] == ["csrf_token"]
    assert "session_secret" in form["sensitive_field_names"]
    assert "DoNotStore" not in str(form)
    assert "AlsoDoNotStore" not in str(form)
    assert session.post_calls == []


def test_detects_missing_csrf_for_post_form() -> None:
    result, _session = _forms_from_html('<form method="post" action="/save"><input name="email"></form>')

    assert "Form Missing CSRF Token Indicator" in result["web_form_results"][0]["issues"]
    assert result["web_form_summary"]["forms_missing_csrf_indicator"] == 1


def test_classifies_login_search_and_upload_forms() -> None:
    login, _ = _forms_from_html('<form method="post"><input type="password" name="password"></form>')
    search, _ = _forms_from_html('<form method="get"><input name="q" type="search"></form>')
    upload, _ = _forms_from_html('<form method="post" enctype="multipart/form-data"><input type="file" name="file"></form>')

    assert login["web_form_results"][0]["classification"] == "login_form"
    assert search["web_form_results"][0]["classification"] == "search_form"
    assert upload["web_form_results"][0]["classification"] == "upload_form"


def test_builds_summary_and_standard_findings() -> None:
    result, _session = _forms_from_html(
        """
        <form method="post" action="/login"><input type="password" name="password"></form>
        <form method="get" action="/search"><input name="q"></form>
        """
    )

    summary = result["web_form_summary"]
    assert summary["enabled"] is True
    assert summary["forms_discovered"] == 2
    assert summary["login_forms"] == 1
    assert summary["search_forms"] == 1
    assert summary["findings_count"] == len(result["findings"])
    assert all(isinstance(finding, Finding) for finding in result["findings"])


def test_input_values_and_hidden_values_are_not_stored() -> None:
    result, _session = _forms_from_html(
        '<form><input name="token" type="hidden" value="NeverStore"><input name="email" value="person@example.test"></form>'
    )

    form = result["web_form_results"][0]
    assert form["input_fields"][0]["value_present"] is True
    assert "NeverStore" not in str(form)
    assert "person@example.test" not in str(form)
