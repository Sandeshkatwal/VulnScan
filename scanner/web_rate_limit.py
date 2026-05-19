"""Web DAST rate limiting, retries, and polite request handling."""

from __future__ import annotations

from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from time import monotonic, sleep
from typing import Any

import requests

from scanner.finding import Finding, create_finding


SOURCE = "web_rate_limit"
RETRYABLE_STATUS_CODES = {429, 503}
RETRY_AFTER_CAP_SECONDS = 30.0
ERROR_SAMPLE_LIMIT = 20
LIMITATIONS = [
    "Rate limits reduce request volume but do not replace explicit permission.",
    "Retry and backoff behaviour applies only to safe GET requests.",
    "Network errors or server throttling may still reduce crawl coverage.",
]


class WebRateLimitConfigurationError(ValueError):
    """Raised when Web DAST politeness settings are invalid."""


@dataclass
class WebPolitenessConfig:
    request_delay: float = 0.5
    max_requests_per_minute: int = 60
    retry_limit: int = 1
    retry_backoff: float = 2.0
    max_errors: int = 10
    respect_retry_after: bool = True


@dataclass
class WebRateLimiter:
    """Simple process-local limiter for Web DAST requests."""

    config: WebPolitenessConfig
    sleeper: Any = sleep
    clock: Any = monotonic
    total_requests: int = 0
    total_sleep_time_seconds: float = 0.0
    throttled_requests: int = 0
    retries_attempted: int = 0
    retry_after_events: int = 0
    request_errors: int = 0
    max_errors_reached: bool = False
    request_error_samples: list[dict[str, Any]] = field(default_factory=list)
    _last_request_time: float | None = None
    _window_start_time: float | None = None
    _window_request_count: int = 0

    def before_request(self) -> bool:
        if self.max_errors_reached:
            return False
        now = float(self.clock())
        if self._window_start_time is None or now - self._window_start_time >= 60:
            self._window_start_time = now
            self._window_request_count = 0
        if self._last_request_time is not None:
            delay_remaining = self.config.request_delay - (now - self._last_request_time)
            if delay_remaining > 0:
                self._sleep(delay_remaining)
                now = float(self.clock())
        if self._window_request_count >= self.config.max_requests_per_minute:
            wait_seconds = max(0.0, 60.0 - (now - float(self._window_start_time)))
            if wait_seconds > 0:
                self._sleep(wait_seconds)
                now = float(self.clock())
            self._window_start_time = now
            self._window_request_count = 0
        self.total_requests += 1
        self._window_request_count += 1
        self._last_request_time = float(self.clock())
        return True

    def record_retry(self) -> None:
        self.retries_attempted += 1

    def record_retry_after(self, wait_seconds: float) -> None:
        self.retry_after_events += 1
        self._sleep(min(max(0.0, wait_seconds), RETRY_AFTER_CAP_SECONDS))

    def record_error(self, sample: dict[str, Any]) -> None:
        self.request_errors += 1
        if len(self.request_error_samples) < ERROR_SAMPLE_LIMIT:
            self.request_error_samples.append(sample)
        if self.request_errors >= self.config.max_errors:
            self.max_errors_reached = True

    def summary(self) -> dict[str, Any]:
        average_interval = (
            round(self.total_sleep_time_seconds / max(1, self.total_requests), 3)
            if self.total_requests
            else 0.0
        )
        return {
            "enabled": True,
            "request_delay_seconds": self.config.request_delay,
            "max_requests_per_minute": self.config.max_requests_per_minute,
            "retry_limit": self.config.retry_limit,
            "retry_backoff": self.config.retry_backoff,
            "max_errors": self.config.max_errors,
            "respect_retry_after": self.config.respect_retry_after,
            "total_requests": self.total_requests,
            "retries_attempted": self.retries_attempted,
            "throttled_requests": self.throttled_requests,
            "retry_after_events": self.retry_after_events,
            "request_errors": self.request_errors,
            "max_errors_reached": self.max_errors_reached,
            "total_sleep_time_seconds": round(self.total_sleep_time_seconds, 3),
            "average_request_interval_seconds": average_interval,
            "limitations": list(LIMITATIONS),
        }

    def _sleep(self, seconds: float) -> None:
        wait_seconds = max(0.0, float(seconds))
        if wait_seconds <= 0:
            return
        self.throttled_requests += 1
        self.total_sleep_time_seconds += wait_seconds
        self.sleeper(wait_seconds)


def validate_web_politeness_options(
    *,
    request_delay: float,
    max_requests_per_minute: int,
    retry_limit: int,
    retry_backoff: float,
    max_errors: int,
) -> None:
    if request_delay < 0 or request_delay > 30:
        raise WebRateLimitConfigurationError("--request-delay must be between 0 and 30 seconds.")
    if max_requests_per_minute < 1 or max_requests_per_minute > 600:
        raise WebRateLimitConfigurationError("--max-requests-per-minute must be between 1 and 600.")
    if retry_limit < 0 or retry_limit > 5:
        raise WebRateLimitConfigurationError("--retry-limit must be between 0 and 5.")
    if retry_backoff < 0 or retry_backoff > 60:
        raise WebRateLimitConfigurationError("--retry-backoff must be between 0 and 60 seconds.")
    if max_errors < 1 or max_errors > 100:
        raise WebRateLimitConfigurationError("--max-errors must be between 1 and 100.")


def build_web_rate_limiter(
    *,
    request_delay: float = 0.5,
    max_requests_per_minute: int = 60,
    retry_limit: int = 1,
    retry_backoff: float = 2.0,
    max_errors: int = 10,
    respect_retry_after: bool = True,
    sleeper: Any = sleep,
    clock: Any = monotonic,
) -> WebRateLimiter:
    validate_web_politeness_options(
        request_delay=request_delay,
        max_requests_per_minute=max_requests_per_minute,
        retry_limit=retry_limit,
        retry_backoff=retry_backoff,
        max_errors=max_errors,
    )
    return WebRateLimiter(
        config=WebPolitenessConfig(
            request_delay=float(request_delay),
            max_requests_per_minute=int(max_requests_per_minute),
            retry_limit=int(retry_limit),
            retry_backoff=float(retry_backoff),
            max_errors=int(max_errors),
            respect_retry_after=bool(respect_retry_after),
        ),
        sleeper=sleeper,
        clock=clock,
    )


def safe_get(
    *,
    session: Any,
    url: str,
    headers: dict[str, str],
    timeout: float,
    limiter: WebRateLimiter,
) -> dict[str, Any]:
    """Run a safe GET request with rate limiting and bounded retries."""
    if limiter.max_errors_reached:
        return _error_result(
            url=url,
            error_code="WEB_MAX_ERRORS_REACHED",
            error_message="Maximum web request errors reached before this request.",
        )
    attempts_allowed = 1 + limiter.config.retry_limit
    retries_attempted = 0
    retry_after_observed = False
    for attempt in range(attempts_allowed):
        if not limiter.before_request():
            return _error_result(
                url=url,
                error_code="WEB_MAX_ERRORS_REACHED",
                error_message="Maximum web request errors reached before this request.",
                retries_attempted=retries_attempted,
            )
        started = monotonic()
        try:
            response = session.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            )
            elapsed = round(monotonic() - started, 3)
            status_code = int(getattr(response, "status_code", 0) or 0)
            retry_after_seconds = _retry_after_seconds(response.headers if hasattr(response, "headers") else {})
            if _should_retry_status(status_code) and attempt < attempts_allowed - 1:
                retries_attempted += 1
                limiter.record_retry()
                if limiter.config.respect_retry_after and retry_after_seconds is not None:
                    retry_after_observed = True
                    limiter.record_retry_after(retry_after_seconds)
                elif limiter.config.retry_backoff:
                    limiter._sleep(limiter.config.retry_backoff * max(1, retries_attempted))
                continue
            success = status_code < 400
            result = {
                "url": url,
                "method": "GET",
                "success": success,
                "status_code": status_code,
                "headers": getattr(response, "headers", {}) or {},
                "text": str(getattr(response, "text", "") or ""),
                "content_type": str((getattr(response, "headers", {}) or {}).get("Content-Type") or (getattr(response, "headers", {}) or {}).get("content-type") or ""),
                "elapsed_seconds": elapsed,
                "error_code": "" if success else "WEB_HTTP_ERROR",
                "error_message": "" if success else f"HTTP status {status_code}",
                "retries_attempted": retries_attempted,
                "retry_after_observed": retry_after_observed,
                "rate_limited": limiter.throttled_requests > 0,
            }
            if not success:
                limiter.record_error(_request_error_sample(result))
            return result
        except requests.Timeout as exc:
            error_code = "WEB_REQUEST_TIMEOUT"
            error_message = str(exc)[:200]
        except requests.TooManyRedirects as exc:
            error_code = "WEB_TOO_MANY_REDIRECTS"
            error_message = str(exc)[:200]
        except requests.ConnectionError as exc:
            error_code = "WEB_CONNECTION_ERROR"
            error_message = str(exc)[:200]
        except Exception as exc:
            error_code = "WEB_UNKNOWN_ERROR"
            error_message = str(exc)[:200]

        if attempt < attempts_allowed - 1 and error_code in {"WEB_REQUEST_TIMEOUT", "WEB_CONNECTION_ERROR"}:
            retries_attempted += 1
            limiter.record_retry()
            if limiter.config.retry_backoff:
                limiter._sleep(limiter.config.retry_backoff * max(1, retries_attempted))
            continue
        result = _error_result(
            url=url,
            error_code=error_code,
            error_message=error_message,
            retries_attempted=retries_attempted,
        )
        limiter.record_error(_request_error_sample(result))
        return result
    return _error_result(url=url, error_code="WEB_UNKNOWN_ERROR", error_message="Request did not complete.")


def build_politeness_findings(summary: dict[str, Any]) -> list[Finding]:
    findings = [
        create_finding(
            title="Web DAST Politeness Controls Applied",
            severity="Informational",
            category="Web DAST Politeness",
            evidence="Request delay and request-per-minute controls were applied.",
            confidence="High",
            impact="Politeness controls reduce request pressure during authorised passive checks.",
            recommendation="Tune rate limits according to written authorisation and target capacity.",
            verification="Review the Web DAST Politeness report section.",
            limitation="Rate limits reduce request volume but do not replace explicit permission.",
            source=SOURCE,
            service="http",
        )
    ]
    if summary.get("max_errors_reached"):
        findings.append(
            create_finding(
                title="Web Scan Stopped After Maximum Errors",
                severity="Low",
                category="Web DAST Reliability",
                evidence="Web scan reached the configured maximum error threshold.",
                confidence="High",
                impact="Web scan coverage may be incomplete.",
                recommendation="Review target availability, scope, and timeout settings before retrying.",
                verification="Review request error samples and retry the scan if authorised.",
                limitation="Scan coverage may be incomplete.",
                source=SOURCE,
                service="http",
            )
        )
    if int(summary.get("retry_after_events") or 0):
        findings.append(
            create_finding(
                title="Retry-After Header Respected",
                severity="Informational",
                category="Web DAST Politeness",
                evidence="Target returned Retry-After and VulScan delayed further requests.",
                confidence="High",
                impact="Respecting server throttling signals supports polite authorised testing.",
                recommendation="Keep Retry-After handling enabled for polite scanning.",
                verification="Review Retry-After event counts in the politeness summary.",
                limitation="Retry-After behaviour depends on server response.",
                source=SOURCE,
                service="http",
            )
        )
    return findings


def _should_retry_status(status_code: int) -> bool:
    return status_code in RETRYABLE_STATUS_CODES


def _retry_after_seconds(headers: Any) -> float | None:
    value = ""
    for key, candidate in dict(headers or {}).items():
        if str(key).lower() == "retry-after":
            value = str(candidate).strip()
            break
    if not value:
        return None
    try:
        return min(float(value), RETRY_AFTER_CAP_SECONDS)
    except ValueError:
        try:
            retry_time = parsedate_to_datetime(value)
            return min(max(0.0, retry_time.timestamp() - monotonic()), RETRY_AFTER_CAP_SECONDS)
        except Exception:
            return RETRY_AFTER_CAP_SECONDS


def _error_result(
    *,
    url: str,
    error_code: str,
    error_message: str,
    retries_attempted: int = 0,
) -> dict[str, Any]:
    return {
        "url": url,
        "method": "GET",
        "success": False,
        "status_code": 0,
        "headers": {},
        "text": "",
        "content_type": "",
        "elapsed_seconds": 0.0,
        "error_code": error_code,
        "error_message": error_message[:200],
        "retries_attempted": retries_attempted,
        "retry_after_observed": error_code == "WEB_RETRY_AFTER_RESPECTED",
        "rate_limited": False,
    }


def _request_error_sample(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "url": str(result.get("url") or ""),
        "method": "GET",
        "status_code": int(result.get("status_code") or 0),
        "error_code": str(result.get("error_code") or ""),
        "error_message": str(result.get("error_message") or "")[:200],
        "retries_attempted": int(result.get("retries_attempted") or 0),
        "retry_after_observed": bool(result.get("retry_after_observed")),
    }
