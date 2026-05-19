from __future__ import annotations

from dataclasses import dataclass

import pytest
import requests

from scanner.finding import Finding
from scanner.web_crawler import crawl_web
from scanner.web_cookie_audit import audit_web_cookies
from scanner.web_form_audit import audit_web_forms
from scanner.web_header_audit import audit_web_headers
from scanner.web_rate_limit import (
    WebRateLimitConfigurationError,
    build_politeness_findings,
    build_web_rate_limiter,
    safe_get,
    validate_web_politeness_options,
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@dataclass
class FakeResponse:
    text: str = "<title>OK</title>"
    status_code: int = 200
    headers: dict[str, str] | None = None

    def __post_init__(self) -> None:
        if self.headers is None:
            self.headers = {"Content-Type": "text/html"}


class FakeSession:
    def __init__(self, outcomes: list[object]) -> None:
        self.outcomes = list(outcomes)
        self.get_calls: list[str] = []

    def get(self, url: str, **kwargs: object) -> object:
        self.get_calls.append(url)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def test_validate_request_delay_bounds() -> None:
    with pytest.raises(WebRateLimitConfigurationError):
        validate_web_politeness_options(
            request_delay=-0.1,
            max_requests_per_minute=60,
            retry_limit=1,
            retry_backoff=2,
            max_errors=10,
        )


def test_validate_max_requests_per_minute_bounds() -> None:
    with pytest.raises(WebRateLimitConfigurationError):
        validate_web_politeness_options(
            request_delay=0.5,
            max_requests_per_minute=0,
            retry_limit=1,
            retry_backoff=2,
            max_errors=10,
        )


def test_validate_retry_limit_bounds() -> None:
    with pytest.raises(WebRateLimitConfigurationError):
        validate_web_politeness_options(
            request_delay=0.5,
            max_requests_per_minute=60,
            retry_limit=6,
            retry_backoff=2,
            max_errors=10,
        )


def test_rate_limiter_tracks_total_requests() -> None:
    fake = FakeClock()
    limiter = build_web_rate_limiter(request_delay=0, sleeper=fake.sleep, clock=fake.clock)

    limiter.before_request()
    limiter.before_request()

    assert limiter.total_requests == 2


def test_rate_limiter_tracks_total_sleep_time() -> None:
    fake = FakeClock()
    limiter = build_web_rate_limiter(request_delay=1, sleeper=fake.sleep, clock=fake.clock)

    limiter.before_request()
    limiter.before_request()

    assert limiter.total_sleep_time_seconds == 1
    assert limiter.throttled_requests == 1


def test_request_wrapper_retries_timeout_once_when_retry_limit_is_one() -> None:
    fake = FakeClock()
    limiter = build_web_rate_limiter(request_delay=0, retry_limit=1, retry_backoff=0, sleeper=fake.sleep, clock=fake.clock)
    session = FakeSession([requests.Timeout("timed out"), FakeResponse()])

    result = safe_get(session=session, url="https://example.test/", headers={}, timeout=1, limiter=limiter)

    assert result["success"] is True
    assert result["retries_attempted"] == 1
    assert limiter.retries_attempted == 1
    assert len(session.get_calls) == 2


def test_request_wrapper_does_not_exceed_retry_limit() -> None:
    fake = FakeClock()
    limiter = build_web_rate_limiter(request_delay=0, retry_limit=1, retry_backoff=0, sleeper=fake.sleep, clock=fake.clock)
    session = FakeSession([requests.Timeout("one"), requests.Timeout("two"), FakeResponse()])

    result = safe_get(session=session, url="https://example.test/", headers={}, timeout=1, limiter=limiter)

    assert result["success"] is False
    assert result["retries_attempted"] == 1
    assert len(session.get_calls) == 2


def test_retry_after_is_respected_and_capped() -> None:
    fake = FakeClock()
    limiter = build_web_rate_limiter(request_delay=0, retry_limit=1, sleeper=fake.sleep, clock=fake.clock)
    session = FakeSession(
        [
            FakeResponse(status_code=429, headers={"Content-Type": "text/html", "Retry-After": "120"}),
            FakeResponse(),
        ]
    )

    result = safe_get(session=session, url="https://example.test/", headers={}, timeout=1, limiter=limiter)

    assert result["success"] is True
    assert result["retry_after_observed"] is True
    assert limiter.retry_after_events == 1
    assert fake.sleeps == [30.0]


def test_max_errors_marks_summary() -> None:
    fake = FakeClock()
    limiter = build_web_rate_limiter(request_delay=0, retry_limit=0, max_errors=1, sleeper=fake.sleep, clock=fake.clock)
    session = FakeSession([requests.ConnectionError("down")])

    crawl = crawl_web(
        start_url="https://example.test/",
        max_pages=1,
        session=session,
        rate_limiter=limiter,
    )

    assert crawl["web_politeness_summary"]["max_errors_reached"] is True
    assert crawl["web_politeness_summary"]["request_errors"] == 1


def test_shared_response_avoids_duplicate_requests_for_passive_checks() -> None:
    fake = FakeClock()
    limiter = build_web_rate_limiter(request_delay=0, sleeper=fake.sleep, clock=fake.clock)
    session = FakeSession(
        [
            FakeResponse(
                text='<form method="get" action="/search"><input name="q"></form>',
                headers={"Content-Type": "text/html", "Set-Cookie": "prefs=fake; Path=/"},
            )
        ]
    )

    crawl = crawl_web(
        start_url="https://example.test/",
        crawl=False,
        max_pages=1,
        session=session,
        rate_limiter=limiter,
    )
    audit_web_headers(crawl["crawled_pages"])
    audit_web_cookies(crawl["crawled_pages"])
    audit_web_forms(crawl["crawled_pages"])

    assert len(session.get_calls) == 1
    assert crawl["web_politeness_summary"]["total_requests"] == 1


def test_web_politeness_summary_is_created() -> None:
    fake = FakeClock()
    limiter = build_web_rate_limiter(request_delay=0, sleeper=fake.sleep, clock=fake.clock)
    session = FakeSession([FakeResponse()])

    crawl = crawl_web(start_url="https://example.test/", max_pages=1, session=session, rate_limiter=limiter)

    assert crawl["web_politeness_summary"]["enabled"] is True
    assert crawl["web_politeness_summary"]["total_requests"] == 1


def test_politeness_findings_use_standard_model() -> None:
    fake = FakeClock()
    limiter = build_web_rate_limiter(request_delay=0, sleeper=fake.sleep, clock=fake.clock)
    limiter.before_request()

    findings = build_politeness_findings(limiter.summary())

    assert all(isinstance(finding, Finding) for finding in findings)
    assert findings[0].source == "web_rate_limit"
