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


@dataclass
class FakeResponse:
    text: str
    status_code: int = 200
    content_type: str = "text/html; charset=utf-8"

    @property
    def headers(self) -> dict[str, str]:
        return {"Content-Type": self.content_type}


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
    assert session.post_calls == []


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
