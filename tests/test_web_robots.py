from __future__ import annotations

from dataclasses import dataclass

import requests

from scanner.finding import Finding
from scanner.web_crawler import crawl_web
from scanner.web_rate_limit import build_web_rate_limiter
from scanner.web_robots import (
    build_robots_findings,
    build_robots_url,
    fetch_robots_policy,
    parse_robots_text,
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class FakeResponse:
    text: str = ""
    status_code: int = 200
    headers: dict[str, str] | None = None

    def __post_init__(self) -> None:
        if self.headers is None:
            self.headers = {"Content-Type": "text/plain"}


class FakeSession:
    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses
        self.get_calls: list[str] = []

    def get(self, url: str, **kwargs: object) -> object:
        self.get_calls.append(url)
        response = self.responses[url]
        if isinstance(response, Exception):
            raise response
        return response


def _limiter() -> object:
    fake = FakeClock()
    return build_web_rate_limiter(request_delay=0, retry_limit=0, sleeper=fake.sleep, clock=fake.clock)


def test_build_robots_url_from_https_start_url() -> None:
    assert build_robots_url("https://example.test/app/page") == "https://example.test/robots.txt"


def test_build_robots_url_from_http_start_url() -> None:
    assert build_robots_url("http://example.test/app/page") == "http://example.test/robots.txt"


def test_parse_disallow_rules() -> None:
    parsed = parse_robots_text(
        robots_url="https://example.test/robots.txt",
        text="User-agent: *\nDisallow: /private\n",
        robots_user_agent="VulScan-WebDAST",
    )

    assert parsed["disallow_rules_count"] == 1
    assert "/private" in parsed["disallowed_samples"]


def test_parse_allow_rules() -> None:
    parsed = parse_robots_text(
        robots_url="https://example.test/robots.txt",
        text="User-agent: *\nAllow: /public\n",
        robots_user_agent="VulScan-WebDAST",
    )

    assert parsed["allow_rules_count"] == 1
    assert "/public" in parsed["allowed_samples"]


def test_parse_sitemap_entries() -> None:
    parsed = parse_robots_text(
        robots_url="https://example.test/robots.txt",
        text="Sitemap: https://example.test/sitemap.xml\n",
        robots_user_agent="VulScan-WebDAST",
    )

    assert parsed["sitemap_urls"] == ["https://example.test/sitemap.xml"]


def test_parse_crawl_delay_if_present() -> None:
    parsed = parse_robots_text(
        robots_url="https://example.test/robots.txt",
        text="User-agent: *\nCrawl-delay: 3\n",
        robots_user_agent="VulScan-WebDAST",
    )

    assert parsed["crawl_delay"] == 3.0


def test_handle_robots_404_as_not_found() -> None:
    session = FakeSession({"https://example.test/robots.txt": FakeResponse(status_code=404)})

    policy = fetch_robots_policy(
        start_url="https://example.test/",
        session=session,
        headers={},
        timeout=1,
        limiter=_limiter(),
        enabled=True,
        respect_robots=True,
    )

    assert policy.summary()["fetch_status"] == "not_found"
    assert policy.summary()["robots_found"] is False


def test_handle_robots_timeout_gracefully() -> None:
    session = FakeSession({"https://example.test/robots.txt": requests.Timeout("timeout")})

    policy = fetch_robots_policy(
        start_url="https://example.test/",
        session=session,
        headers={},
        timeout=1,
        limiter=_limiter(),
        enabled=True,
        respect_robots=True,
    )

    assert policy.summary()["fetch_status"] == "WEB_REQUEST_TIMEOUT"
    assert policy.summary()["robots_found"] is False


def test_skip_disallowed_urls_when_respect_robots_enabled() -> None:
    session = FakeSession(
        {
            "https://example.test/": FakeResponse(
                text='<a href="/private">Private</a><a href="/public">Public</a>',
                headers={"Content-Type": "text/html"},
            ),
            "https://example.test/public": FakeResponse(text="<title>Public</title>", headers={"Content-Type": "text/html"}),
        }
    )
    policy = parse_policy("User-agent: *\nDisallow: /private\n", respect=True)

    result = crawl_web(
        start_url="https://example.test/",
        max_pages=5,
        max_depth=1,
        session=session,
        rate_limiter=_limiter(),
        robots_policy=policy,
    )

    assert "https://example.test/private" not in session.get_calls
    assert "https://example.test/public" in session.get_calls
    assert result["web_scope_summary"]["skipped_by_robots_count"] == 1


def test_do_not_skip_disallowed_urls_when_no_respect_robots_used() -> None:
    session = FakeSession(
        {
            "https://example.test/": FakeResponse(
                text='<a href="/private">Private</a>',
                headers={"Content-Type": "text/html"},
            ),
            "https://example.test/private": FakeResponse(text="<title>Private</title>", headers={"Content-Type": "text/html"}),
        }
    )
    policy = parse_policy("User-agent: *\nDisallow: /private\n", respect=False)

    result = crawl_web(
        start_url="https://example.test/",
        max_pages=5,
        max_depth=1,
        session=session,
        rate_limiter=_limiter(),
        robots_policy=policy,
    )

    assert "https://example.test/private" in session.get_calls
    assert result["web_scope_summary"]["skipped_by_robots_count"] == 0


def test_generate_robots_reviewed_finding() -> None:
    summary = parse_policy("User-agent: *\nDisallow: /private\n", respect=True).summary()
    findings = build_robots_findings(summary)

    assert any(finding.title == "robots.txt Reviewed" for finding in findings)
    assert all(isinstance(finding, Finding) for finding in findings)


def test_generate_robots_not_found_finding() -> None:
    summary = {
        "enabled": True,
        "robots_url": "https://example.test/robots.txt",
        "robots_found": False,
        "sitemap_urls": [],
        "urls_skipped_by_robots": 0,
        "respect_robots": True,
    }

    findings = build_robots_findings(summary)

    assert any(finding.title == "robots.txt Not Found" for finding in findings)


def test_generate_urls_skipped_due_to_robots_finding() -> None:
    policy = parse_policy("User-agent: *\nDisallow: /private\n", respect=True)
    policy.record_skip("https://example.test/private")

    findings = build_robots_findings(policy.summary())

    assert any(finding.title == "URLs Skipped Due to robots.txt" for finding in findings)


def parse_policy(text: str, *, respect: bool) -> object:
    parsed = parse_robots_text(
        robots_url="https://example.test/robots.txt",
        text=text,
        robots_user_agent="VulScan-WebDAST",
    )
    from scanner.web_robots import WebRobotsPolicy

    return WebRobotsPolicy(
        enabled=True,
        robots_url="https://example.test/robots.txt",
        respect_robots=respect,
        robots_found=True,
        fetch_status="found",
        http_status_code=200,
        user_agents_seen=parsed["user_agents_seen"],
        disallow_rules_count=parsed["disallow_rules_count"],
        allow_rules_count=parsed["allow_rules_count"],
        sitemap_urls=parsed["sitemap_urls"],
        crawl_delay=parsed["crawl_delay"],
        disallowed_samples=parsed["disallowed_samples"],
        allowed_samples=parsed["allowed_samples"],
        parser=parsed["parser"],
    )
