from __future__ import annotations

from dataclasses import dataclass

import pytest

from scanner.finding import Finding
from scanner.web_crawler import (
    build_web_findings,
    crawl_web,
    normalize_url,
    should_skip_url,
)
from scanner.web_header_audit import audit_web_headers
from scanner.web_scope import build_web_scope


@dataclass
class FakeResponse:
    text: str
    status_code: int = 200
    content_type: str = "text/html; charset=utf-8"
    extra_headers: dict[str, str] | None = None

    @property
    def headers(self) -> dict[str, str]:
        headers = {"Content-Type": self.content_type}
        headers.update(self.extra_headers or {})
        return headers


class FakeSession:
    def __init__(self, responses: dict[str, FakeResponse]) -> None:
        self.responses = responses
        self.get_calls: list[str] = []
        self.post_calls: list[str] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.get_calls.append(url)
        if url not in self.responses:
            raise RuntimeError(f"Unexpected URL {url}")
        return self.responses[url]

    def post(self, url: str, **kwargs: object) -> None:
        self.post_calls.append(url)
        raise AssertionError("Crawler must not submit forms.")


def test_normalize_url_removes_fragments_and_default_ports() -> None:
    assert normalize_url("HTTP://Example.COM:80/a/../b?x=1#frag") == "http://example.com/b?x=1"
    assert normalize_url("/login#section", "https://example.com:443/app/") == "https://example.com/login"


def test_skip_unsafe_schemes_and_static_extensions() -> None:
    assert should_skip_url("javascript:void(0)")
    assert should_skip_url("mailto:security@example.test")
    assert should_skip_url("https://example.test/app.js")
    assert not should_skip_url("https://example.test/app")


def test_crawler_extracts_title_links_and_forms_without_submitting() -> None:
    session = FakeSession(
        {
            "https://example.test/": FakeResponse(
                """
                <html>
                  <head><title> Demo Home </title></head>
                  <body>
                    <a href="/account">Account</a>
                    <a href="https://portal.example.test/help">External</a>
                    <a href="mailto:security@example.test">Mail</a>
                    <form method="post" action="/login">
                      <input name="username">
                      <input name="password" type="password">
                      <input name="avatar" type="file">
                    </form>
                  </body>
                </html>
                """
            ),
            "https://example.test/account": FakeResponse("<title>Account</title>"),
        }
    )

    result = crawl_web(
        start_url="https://example.test/",
        max_pages=2,
        max_depth=1,
        session=session,
    )

    page = result["crawled_pages"][0]
    form = result["discovered_forms"][0]
    assert page["title"] == "Demo Home"
    assert page["internal_links"] == ["https://example.test/account"]
    assert page["external_links"] == ["https://portal.example.test/help"]
    assert form["method"] == "POST"
    assert form["action"] == "https://example.test/login"
    assert form["input_names"] == ["username", "password", "avatar"]
    assert form["has_password_field"] is True
    assert form["has_file_upload"] is True
    assert page["response_headers"]["Content-Type"] == "text/html; charset=utf-8"
    assert session.post_calls == []


def test_crawler_records_cookie_flag_metadata_without_cookie_values() -> None:
    session = FakeSession(
        {
            "https://example.test/": FakeResponse(
                "<title>Home</title>",
                content_type="text/html",
                extra_headers={"Set-Cookie": "sessionid=fake; Path=/; HttpOnly"},
            ),
        }
    )

    result = crawl_web(start_url="https://example.test/", max_pages=1, session=session)
    page = result["crawled_pages"][0]

    assert page["response_headers"]["Set-Cookie"] == "[set-cookie present]"
    assert page["cookie_flags"] == [{"secure": False, "httponly": True, "samesite": False}]
    assert page["cookies"][0]["name"] == "sessionid"
    assert "fake" not in str(page["cookies"])


def test_crawler_skips_external_domains() -> None:
    session = FakeSession(
        {
            "https://example.test/": FakeResponse(
                '<a href="https://other.example.test/page">External</a><a href="/local">Local</a>'
            ),
            "https://example.test/local": FakeResponse("<title>Local</title>"),
        }
    )

    result = crawl_web(start_url="https://example.test/", max_depth=1, session=session)

    assert "https://other.example.test/page" not in session.get_calls
    assert "https://example.test/local" in session.get_calls
    assert result["web_scan_summary"]["unique_external_links"] == 1


def test_crawler_respects_max_pages() -> None:
    session = FakeSession(
        {
            "https://example.test/": FakeResponse('<a href="/one">One</a><a href="/two">Two</a>'),
            "https://example.test/one": FakeResponse("<title>One</title>"),
            "https://example.test/two": FakeResponse("<title>Two</title>"),
        }
    )

    result = crawl_web(start_url="https://example.test/", max_pages=2, max_depth=1, session=session)

    assert result["web_scan_summary"]["pages_crawled"] == 2
    assert len(session.get_calls) == 2
    assert result["web_scope_summary"]["skipped_page_limit_count"] >= 1


def test_crawler_respects_max_depth() -> None:
    session = FakeSession(
        {
            "https://example.test/": FakeResponse('<a href="/one">One</a>'),
            "https://example.test/one": FakeResponse('<a href="/two">Two</a>'),
            "https://example.test/two": FakeResponse("<title>Two</title>"),
        }
    )

    result = crawl_web(start_url="https://example.test/", max_pages=5, max_depth=1, session=session)

    assert "https://example.test/two" not in session.get_calls
    assert result["web_scan_summary"]["pages_crawled"] == 2
    assert result["web_scope_summary"]["skipped_depth_limit_count"] >= 1


def test_crawler_does_not_fetch_out_of_scope_urls() -> None:
    session = FakeSession(
        {
            "https://example.test/docs": FakeResponse(
                '<a href="/docs/page">Docs</a><a href="/admin">Admin</a><a href="https://other.test/page">Other</a>'
            ),
            "https://example.test/docs/page": FakeResponse("<title>Docs</title>"),
        }
    )
    scope = build_web_scope(start_url="https://example.test/docs", allow_paths=["/docs"])

    result = crawl_web(
        start_url="https://example.test/docs",
        max_pages=5,
        max_depth=1,
        session=session,
        scope=scope,
    )

    assert "https://example.test/admin" not in session.get_calls
    assert "https://other.test/page" not in session.get_calls
    assert "https://example.test/docs/page" in session.get_calls
    assert result["web_scope_summary"]["skipped_not_allowed_paths_count"] == 1
    assert result["web_scope_summary"]["skipped_external_hosts_count"] == 1


def test_passive_checks_use_only_in_scope_pages() -> None:
    session = FakeSession(
        {
            "https://example.test/docs": FakeResponse('<a href="/docs/page">Docs</a><a href="/admin">Admin</a>'),
            "https://example.test/docs/page": FakeResponse("<title>Docs</title>"),
        }
    )
    scope = build_web_scope(start_url="https://example.test/docs", allow_paths=["/docs"])
    crawl = crawl_web(
        start_url="https://example.test/docs",
        max_pages=5,
        max_depth=1,
        session=session,
        scope=scope,
    )

    header_result = audit_web_headers(crawl["crawled_pages"])
    checked_urls = {result["url"] for result in header_result["web_header_results"]}

    assert checked_urls == {"https://example.test/docs", "https://example.test/docs/page"}


def test_crawler_requires_absolute_http_url() -> None:
    with pytest.raises(ValueError):
        crawl_web(start_url="ftp://example.test/", session=FakeSession({}))


def test_generate_standard_web_findings() -> None:
    summary = {
        "normalized_start_url": "https://example.test/",
        "pages_crawled": 1,
        "forms_discovered": 1,
        "unique_external_links": 1,
    }
    forms = [
        {
            "page_url": "https://example.test/login",
            "has_password_field": True,
            "has_file_upload": True,
        }
    ]

    findings = build_web_findings(summary=summary, forms=forms, pages=[], errors=[])

    assert all(isinstance(finding, Finding) for finding in findings)
    assert {finding.title for finding in findings} == {
        "Web Crawl Completed",
        "Password Form Discovered",
        "File Upload Form Discovered",
        "External Links Discovered",
    }
    assert all(finding.source == "web_crawler" for finding in findings)
