from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from scanner.report_html import save_html_report
from scanner.report_json import save_json_report
from scanner.safe_active_validation import (
    SAFE_MARKER,
    SAFE_ORIGIN,
    SAFE_REDIRECT_PATH,
    load_validation_targets,
    run_safe_active_validation,
)


class FakeResponse:
    def __init__(self, status_code: int = 200, headers: dict[str, str] | None = None, body: str = "") -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self._body = body.encode("utf-8")

    def iter_content(self, chunk_size: int = 8192):
        yield self._body


class FakeRequester:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def __call__(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        return self.response


def test_load_validation_targets_file() -> None:
    targets = load_validation_targets("data/bug_bounty/validation/sample_validation_targets.json")
    assert len(targets) == 4
    assert targets[0]["candidate_type"] == "open_redirect"


def test_enforce_scope_blocks_out_of_scope_url_before_request() -> None:
    requester = FakeRequester(FakeResponse())
    result = run_safe_active_validation(
        [{"url": "https://payments.demo-web.local/search?q=test", "candidate_type": "reflected_input", "parameter": "q"}],
        scope_file="data/bug_bounty/sample_program_scope.json",
        enforce_scope=True,
        requester=requester,
    )
    assert requester.calls == []
    assert result["safe_active_validation_skipped"][0]["reason"].startswith("Out-of-scope")


def test_reflected_marker_check_uses_harmless_marker_and_detects_reflection() -> None:
    requester = FakeRequester(FakeResponse(body=f"hello {SAFE_MARKER}"))
    result = run_safe_active_validation(
        [{"url": "http://127.0.0.1:8000/search?q=test", "candidate_type": "reflected_input", "parameter": "q"}],
        checks=["reflected_input_observation"],
        requester=requester,
        sleeper=lambda _: None,
    )
    assert SAFE_MARKER in requester.calls[0]["url"]
    assert "<script" not in requester.calls[0]["url"].lower()
    assert result["safe_active_validation_results"][0]["indicator_found"] is True
    assert result["safe_active_validation_results"][0]["evidence_summary"]["marker_reflected"] is True


def test_open_redirect_check_uses_same_origin_path_only() -> None:
    requester = FakeRequester(FakeResponse(status_code=302, headers={"Location": SAFE_REDIRECT_PATH}))
    result = run_safe_active_validation(
        [{"url": "http://127.0.0.1:8000/redirect?next=/dashboard", "candidate_type": "open_redirect", "parameter": "next"}],
        checks=["open_redirect_indicator"],
        requester=requester,
        sleeper=lambda _: None,
    )
    assert SAFE_REDIRECT_PATH in unquote(requester.calls[0]["url"])
    assert "https://evil" not in requester.calls[0]["url"]
    assert result["safe_active_validation_results"][0]["evidence_summary"]["same_origin_only"] is True


def test_cors_check_sends_harmless_origin() -> None:
    requester = FakeRequester(FakeResponse(headers={"Access-Control-Allow-Origin": SAFE_ORIGIN}))
    result = run_safe_active_validation(
        [{"url": "http://127.0.0.1:8000/", "candidate_type": "cors"}],
        checks=["cors_indicator"],
        requester=requester,
        sleeper=lambda _: None,
    )
    assert requester.calls[0]["headers"]["Origin"] == SAFE_ORIGIN
    assert result["safe_active_validation_results"][0]["indicator_found"] is True


def test_directory_listing_detects_index_of() -> None:
    requester = FakeRequester(FakeResponse(body="<title>Index of /uploads</title>Parent Directory"))
    result = run_safe_active_validation(
        [{"url": "http://127.0.0.1:8000/uploads/", "candidate_type": "directory_listing"}],
        checks=["directory_listing_indicator"],
        requester=requester,
        sleeper=lambda _: None,
    )
    assert result["safe_active_validation_results"][0]["indicator_found"] is True


def test_default_file_check_only_checks_allowed_files() -> None:
    requester = FakeRequester(FakeResponse(status_code=200, headers={"Content-Type": "text/plain"}))
    result = run_safe_active_validation(
        [{"url": "http://127.0.0.1:8000/.env", "candidate_type": "default_file"}],
        checks=["default_file_exposure_indicator"],
        requester=requester,
        sleeper=lambda _: None,
    )
    assert requester.calls[0]["url"].endswith("/robots.txt")
    assert ".env" not in requester.calls[0]["url"]
    assert result["safe_active_validation_results"][0]["request_method"] == "GET"


def test_http_methods_check_uses_options_only() -> None:
    requester = FakeRequester(FakeResponse(headers={"Allow": "GET, OPTIONS"}))
    result = run_safe_active_validation(
        [{"url": "http://127.0.0.1:8000/", "candidate_type": "http_methods"}],
        checks=["http_methods_indicator"],
        requester=requester,
        sleeper=lambda _: None,
    )
    assert requester.calls[0]["method"] == "OPTIONS"
    assert result["safe_active_validation_results"][0]["evidence_summary"]["methods_observed"] == ["GET", "OPTIONS"]


def test_unsupported_candidate_type_is_skipped() -> None:
    requester = FakeRequester(FakeResponse())
    result = run_safe_active_validation(
        [{"url": "http://127.0.0.1:8000/", "candidate_type": "sql_injection"}],
        requester=requester,
        sleeper=lambda _: None,
    )
    assert requester.calls == []
    assert result["safe_active_validation_skipped"][0]["reason"] == "Unsupported candidate type or check."


def test_response_body_and_cookies_are_not_stored() -> None:
    requester = FakeRequester(FakeResponse(headers={"Set-Cookie": "session=secret"}, body="SECRET_BODY"))
    result = run_safe_active_validation(
        [{"url": "http://127.0.0.1:8000/", "candidate_type": "cors"}],
        checks=["cors_indicator"],
        requester=requester,
        sleeper=lambda _: None,
    )
    text = str(result)
    assert "SECRET_BODY" not in text
    assert "session=secret" not in text


def test_rate_limit_and_request_count_are_tracked() -> None:
    requester = FakeRequester(FakeResponse())
    result = run_safe_active_validation(
        [{"url": "http://127.0.0.1:8000/", "candidate_type": "cors"}],
        checks=["cors_indicator"],
        request_delay=0,
        requester=requester,
        sleeper=lambda _: None,
    )
    assert result["safe_active_validation"]["request_count"] == 1


def test_json_report_includes_safe_validation_section(tmp_path: Path) -> None:
    payload = run_safe_active_validation(
        [{"url": "http://127.0.0.1:8000/", "candidate_type": "cors"}],
        checks=["cors_indicator"],
        requester=FakeRequester(FakeResponse()),
        sleeper=lambda _: None,
    )
    path = save_json_report(_scan_result(payload), "VulScan", "test", datetime.now(), datetime.now(), reports_dir=tmp_path)
    assert '"safe_active_validation"' in path.read_text(encoding="utf-8")


def test_html_report_renders_safe_validation_section(tmp_path: Path) -> None:
    payload = run_safe_active_validation(
        [{"url": "http://127.0.0.1:8000/", "candidate_type": "cors"}],
        checks=["cors_indicator"],
        requester=FakeRequester(FakeResponse()),
        sleeper=lambda _: None,
    )
    path = save_html_report(_scan_result(payload), "VulScan", "test", datetime.now(), datetime.now(), reports_dir=tmp_path)
    assert "Safe Active Validation" in path.read_text(encoding="utf-8")


def _scan_result(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "host": "safe-active-validation",
        "resolved_ip": "",
        "scan_mode": "safe-active-validation",
        "duration_seconds": 0,
        "open_ports": [],
        "findings": payload["findings"],
        "safe_active_validation": payload["safe_active_validation"],
        "safe_active_validation_results": payload["safe_active_validation_results"],
        "safe_active_validation_skipped": payload["safe_active_validation_skipped"],
    }
