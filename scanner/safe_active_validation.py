"""Safe active validation checks for authorised bug bounty workflows.

The checks in this module are intentionally limited and non-destructive. They
observe simple behaviours only and never confirm exploitability.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from scanner.bug_bounty_scope import get_scope_decision, load_bug_bounty_scope
from scanner.finding import assign_sequential_finding_ids, create_finding


VALIDATION_INPUT_DIR = Path("data") / "bug_bounty" / "validation"
VALIDATION_REPORTS_DIR = Path("reports") / "validation"
DEFAULT_VALIDATION_USER_AGENT = "VulScan-SafeActiveValidation"
SAFE_MARKER = "VULSCAN_SAFE_MARKER_12345"
SAFE_ORIGIN = "https://vulscan-safe.local"
SAFE_REDIRECT_PATH = "/vulscan-safe-redirect-check"
MAX_RESPONSE_BYTES = 256 * 1024
SUPPORTED_CHECKS = {
    "reflected_input_observation",
    "open_redirect_indicator",
    "cors_indicator",
    "directory_listing_indicator",
    "default_file_exposure_indicator",
    "http_methods_indicator",
}
ALLOWED_DEFAULT_FILE_PATHS = {
    "/robots.txt": "robots.txt",
    "/sitemap.xml": "sitemap.xml",
    "/.well-known/security.txt": "security.txt",
    "/security.txt": "security.txt",
}
CHECKS_BY_CANDIDATE_TYPE = {
    "reflected_input": ["reflected_input_observation"],
    "open_redirect": ["open_redirect_indicator"],
    "cors": ["cors_indicator"],
    "directory_listing": ["directory_listing_indicator"],
    "default_file": ["default_file_exposure_indicator"],
    "http_methods": ["http_methods_indicator"],
}
VALIDATION_LIMITATIONS = [
    "Safe validation is non-destructive and does not prove exploitability.",
    "All results are indicators only and require manual validation within authorised scope.",
    "Response bodies, cookies, session tokens, passwords, and private keys are not stored.",
]


class SafeActiveValidationError(ValueError):
    """Raised for friendly validation configuration errors."""


Requester = Callable[..., Any]


@dataclass
class ValidationLimiter:
    request_delay: float = 1.0
    max_requests_per_minute: int = 20
    max_validation_requests: int = 100
    sleeper: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    request_count: int = 0
    throttled_requests: int = 0
    _last_request_time: float | None = None
    _window_start_time: float | None = None
    _window_request_count: int = 0

    def before_request(self) -> bool:
        if self.request_count >= self.max_validation_requests:
            return False
        now = self.clock()
        if self._window_start_time is None or now - self._window_start_time >= 60:
            self._window_start_time = now
            self._window_request_count = 0
        if self._last_request_time is not None:
            remaining = self.request_delay - (now - self._last_request_time)
            if remaining > 0:
                self.throttled_requests += 1
                self.sleeper(remaining)
                now = self.clock()
        if self._window_request_count >= self.max_requests_per_minute:
            wait_seconds = max(0.0, 60.0 - (now - float(self._window_start_time)))
            if wait_seconds > 0:
                self.throttled_requests += 1
                self.sleeper(wait_seconds)
                now = self.clock()
            self._window_start_time = now
            self._window_request_count = 0
        self.request_count += 1
        self._window_request_count += 1
        self._last_request_time = self.clock()
        return True


def load_validation_targets(path: str | Path) -> list[dict[str, Any]]:
    target_path = Path(path)
    try:
        payload = json.loads(target_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SafeActiveValidationError(f"Validation targets file was not found: {target_path}") from exc
    except json.JSONDecodeError as exc:
        raise SafeActiveValidationError(f"Validation targets file is not valid JSON: {target_path}") from exc
    targets = payload.get("targets")
    if not isinstance(targets, list):
        raise SafeActiveValidationError("Validation targets file must contain a targets list.")
    return [_normalise_target(item) for item in targets if isinstance(item, dict)]


def run_safe_active_validation(
    targets: list[dict[str, Any]],
    scope_file: str | Path | None = None,
    enforce_scope: bool = False,
    checks: list[str] | None = None,
    request_delay: float = 1.0,
    max_requests_per_minute: int = 20,
    timeout: float = 5.0,
    max_validation_requests: int = 100,
    max_redirects: int = 3,
    safe_active_confirm: bool = True,
    requester: Requester | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    _validate_options(request_delay, max_requests_per_minute, timeout, max_validation_requests, max_redirects, safe_active_confirm)
    requested_checks = _normalise_checks(checks)
    scope = load_bug_bounty_scope(scope_file) if scope_file else None
    limiter = ValidationLimiter(request_delay, max_requests_per_minute, max_validation_requests, sleeper=sleeper)
    request_callable = requester or requests.request
    results: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for raw_target in targets:
        target = _normalise_target(raw_target)
        decision = get_scope_decision(target["url"], scope) if scope else _unscoped_decision(target["url"])
        if scope and enforce_scope and not decision.get("in_scope"):
            skipped.append({"url": target["url"], "candidate_type": target["candidate_type"], "reason": "Out-of-scope target skipped before request.", "scope_reason": decision.get("reason") or ""})
            continue
        checks_to_run = _checks_for_target(target, requested_checks)
        if not checks_to_run:
            skipped.append({"url": target["url"], "candidate_type": target["candidate_type"], "reason": "Unsupported candidate type or check.", "scope_reason": decision.get("reason") or ""})
            continue
        for check_name in checks_to_run:
            if not _check_supports_target(check_name, target):
                skipped.append({"url": target["url"], "candidate_type": target["candidate_type"], "reason": f"Check {check_name} is not supported for this target.", "scope_reason": decision.get("reason") or ""})
                continue
            if limiter.request_count >= max_validation_requests:
                skipped.append({"url": target["url"], "candidate_type": target["candidate_type"], "reason": "Maximum validation request count reached.", "scope_reason": decision.get("reason") or ""})
                continue
            results.append(
                _run_check(
                    target=target,
                    check_name=check_name,
                    requester=request_callable,
                    limiter=limiter,
                    timeout=timeout,
                    max_redirects=max_redirects,
                )
            )

    summary = _build_summary(targets, results, skipped, requested_checks, limiter, scope is not None)
    findings = _build_findings(summary, results)
    return {
        "safe_active_validation": summary,
        "safe_active_validation_results": results,
        "safe_active_validation_skipped": skipped,
        "findings": assign_sequential_finding_ids(findings),
    }


def _run_check(
    target: dict[str, Any],
    check_name: str,
    requester: Requester,
    limiter: ValidationLimiter,
    timeout: float,
    max_redirects: int,
) -> dict[str, Any]:
    started = time.monotonic()
    method, url, headers = _request_for_check(target, check_name)
    base = _base_result(target, check_name, method)
    if not limiter.before_request():
        base.update({"status": "skipped", "evidence_summary": {"reason": "Maximum validation request count reached."}})
        return base
    try:
        response = requester(
            method,
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
        body = _read_limited_text(response)
        status_code = int(getattr(response, "status_code", 0) or 0)
        response_headers = dict(getattr(response, "headers", {}) or {})
        evidence = _evidence_for_check(check_name, target, url, response_headers, body, status_code)
        base.update(
            {
                "status": "checked",
                "indicator_found": bool(evidence.pop("indicator_found", False)),
                "confidence": "Medium" if evidence.get("confidence_hint") == "medium" else "Low",
                "evidence_summary": {key: value for key, value in evidence.items() if key != "confidence_hint"},
                "status_code": status_code,
                "response_time_ms": int((time.monotonic() - started) * 1000),
            }
        )
    except requests.RequestException as exc:
        base.update(
            {
                "status": "error",
                "indicator_found": False,
                "evidence_summary": {"error": _safe_error(exc)},
                "response_time_ms": int((time.monotonic() - started) * 1000),
            }
        )
    base["owasp_categories"] = _owasp_for_validation_result(base)
    return base


def _request_for_check(target: dict[str, Any], check_name: str) -> tuple[str, str, dict[str, str]]:
    headers = {"User-Agent": DEFAULT_VALIDATION_USER_AGENT}
    if check_name == "reflected_input_observation":
        return "GET", _replace_query_parameter(target["url"], target.get("parameter") or "", SAFE_MARKER), headers
    if check_name == "open_redirect_indicator":
        return "GET", _replace_query_parameter(target["url"], target.get("parameter") or "", SAFE_REDIRECT_PATH), headers
    if check_name == "cors_indicator":
        headers["Origin"] = SAFE_ORIGIN
        return "GET", target["url"], headers
    if check_name == "default_file_exposure_indicator":
        return "GET", _default_file_url(target["url"]), headers
    if check_name == "http_methods_indicator":
        return "OPTIONS", target["url"], headers
    return "GET", target["url"], headers


def _evidence_for_check(check_name: str, target: dict[str, Any], request_url: str, headers: dict[str, Any], body: str, status_code: int) -> dict[str, Any]:
    if check_name == "reflected_input_observation":
        reflected = SAFE_MARKER in body
        return {
            "indicator_found": reflected,
            "marker_reflected": reflected,
            "reflection_context": _reflection_context(body) if reflected else "",
            "result": "Reflected input indicator" if reflected else "No reflected marker observed",
            "limitation": "Does not confirm XSS or injection.",
            "confidence_hint": "medium" if reflected else "low",
        }
    if check_name == "open_redirect_indicator":
        location = str(_header(headers, "location") or "")
        changed = SAFE_REDIRECT_PATH in location
        return {
            "indicator_found": changed,
            "location_header_changed": changed,
            "redirect_target": location,
            "same_origin_only": True,
            "result": "Open redirect behaviour indicator" if changed else "No same-origin redirect behaviour observed",
            "limitation": "Does not confirm exploitable open redirect.",
            "confidence_hint": "medium" if changed else "low",
        }
    if check_name == "cors_indicator":
        allow_origin = str(_header(headers, "access-control-allow-origin") or "")
        allow_credentials = str(_header(headers, "access-control-allow-credentials") or "")
        found = bool(allow_origin or allow_credentials)
        return {
            "indicator_found": found,
            "allow_origin_value": allow_origin,
            "allow_credentials_value": allow_credentials,
            "result": "CORS configuration indicator" if found else "No CORS headers observed",
            "limitation": "Does not confirm exploitability.",
            "confidence_hint": "medium" if found else "low",
        }
    if check_name == "directory_listing_indicator":
        found = any(token.lower() in body.lower() for token in ("Index of /", "Parent Directory", "<title>Index of"))
        return {
            "indicator_found": found,
            "result": "Directory listing indicator" if found else "No directory listing indicator observed",
            "limitation": "Must be manually verified.",
            "confidence_hint": "medium" if found else "low",
        }
    if check_name == "default_file_exposure_indicator":
        parsed = urlsplit(request_url)
        found = status_code == 200 and parsed.path in ALLOWED_DEFAULT_FILE_PATHS
        return {
            "indicator_found": found,
            "status_code": status_code,
            "content_type": str(_header(headers, "content-type") or ""),
            "content_length": _content_length(headers),
            "file_type": ALLOWED_DEFAULT_FILE_PATHS.get(parsed.path, ""),
            "result": "Default public file observed" if found else "Default public file not observed",
            "limitation": "Public file presence is not necessarily a vulnerability.",
            "confidence_hint": "low",
        }
    allow = str(_header(headers, "allow") or "")
    methods = [item.strip().upper() for item in allow.split(",") if item.strip()]
    return {
        "indicator_found": bool(methods),
        "allow_header": allow,
        "methods_observed": methods,
        "result": "HTTP methods indicator" if methods else "No Allow header observed",
        "limitation": "OPTIONS header may be inaccurate and does not confirm method exploitability.",
        "confidence_hint": "low",
    }


def _base_result(target: dict[str, Any], check_name: str, method: str) -> dict[str, Any]:
    return {
        "url": target["url"],
        "candidate_type": target["candidate_type"],
        "parameter": target.get("parameter") or "",
        "check_name": check_name,
        "status": "checked",
        "indicator_found": False,
        "confidence": "Low",
        "evidence_summary": {},
        "request_method": method,
        "status_code": None,
        "response_time_ms": 0,
        "owasp_categories": [],
        "manual_validation_note": "Indicator only. Manual validation required. No exploitability confirmed.",
        "limitation": "Non-destructive check. Scope must be authorised.",
    }


def _build_summary(targets: list[dict[str, Any]], results: list[dict[str, Any]], skipped: list[dict[str, Any]], requested_checks: list[str], limiter: ValidationLimiter, scoped: bool) -> dict[str, Any]:
    return {
        "enabled": True,
        "input_targets_count": len(targets),
        "in_scope_targets_count": len(targets) - len([item for item in skipped if item.get("scope_reason")]),
        "out_of_scope_targets_count": len([item for item in skipped if item.get("scope_reason")]),
        "checks_requested": requested_checks,
        "checks_run": len(results),
        "checks_skipped": len(skipped),
        "indicators_found": sum(1 for item in results if item.get("indicator_found")),
        "request_count": limiter.request_count,
        "rate_limit_applied": limiter.throttled_requests > 0 or limiter.request_delay > 0 or limiter.max_requests_per_minute <= 20,
        "scope_enforced_available": scoped,
        "limitations": VALIDATION_LIMITATIONS,
    }


def _build_findings(summary: dict[str, Any], results: list[dict[str, Any]]) -> list[Any]:
    findings = [
        create_finding(
            title="Safe Active Validation Completed",
            severity="Informational",
            category="Bug Bounty Safe Validation",
            affected_host="safe-active-validation",
            evidence=f"Safe validation ran {summary.get('checks_run', 0)} checks and found {summary.get('indicators_found', 0)} indicators.",
            recommendation="Manually validate indicators within program rules before reporting.",
            source="safe_active_validation",
            confidence="High",
            impact="Limited non-destructive validation indicators were collected for manual review.",
            verification="Review safe_active_validation_results in the report.",
            limitation="Safe validation is non-destructive and does not prove exploitability.",
        )
    ]
    if any(item.get("indicator_found") and item.get("check_name") == "reflected_input_observation" for item in results):
        findings.append(create_finding(title="Reflected Input Indicator Observed", severity="Low", category="Bug Bounty Safe Validation", affected_host="safe-active-validation", evidence="Harmless marker was reflected in response for a GET parameter.", recommendation="Manually review output encoding and context.", source="safe_active_validation", confidence="Medium", impact="Reflected input may require manual review.", verification="Review evidence summaries for reflected marker observations.", limitation="Reflection alone does not confirm XSS."))
    if any(item.get("indicator_found") and item.get("check_name") == "cors_indicator" for item in results):
        findings.append(create_finding(title="CORS Configuration Indicator Observed", severity="Informational", category="Bug Bounty Safe Validation", affected_host="safe-active-validation", evidence="CORS headers were observed that may require review.", recommendation="Verify CORS policy and credential handling manually.", source="safe_active_validation", confidence="Low", impact="CORS headers can affect browser access controls depending on context.", verification="Review Access-Control response headers.", limitation="CORS headers alone do not confirm exploitability."))
    if any(item.get("indicator_found") and item.get("check_name") == "directory_listing_indicator" for item in results):
        findings.append(create_finding(title="Directory Listing Indicator Observed", severity="Low", category="Bug Bounty Safe Validation", affected_host="safe-active-validation", evidence="Response contained directory listing indicators.", recommendation="Manually verify whether sensitive files are exposed.", source="safe_active_validation", confidence="Medium", impact="Directory listings may expose files depending on content.", verification="Review the authorised URL manually.", limitation="Directory listing indicator may be false positive."))
    return findings


def _normalise_target(item: dict[str, Any]) -> dict[str, Any]:
    url = str(item.get("url") or "").strip()
    if not url or urlsplit(url).scheme not in {"http", "https"}:
        raise SafeActiveValidationError("Validation target URL must be http or https.")
    return {
        "url": url,
        "candidate_type": str(item.get("candidate_type") or "manual").strip().lower(),
        "parameter": str(item.get("parameter") or "").strip(),
        "source": str(item.get("source") or "manual").strip(),
    }


def _normalise_checks(checks: list[str] | None) -> list[str]:
    if not checks:
        return sorted(SUPPORTED_CHECKS)
    normalised = [str(check).strip() for check in checks if str(check).strip()]
    return [check for check in normalised if check in SUPPORTED_CHECKS]


def _checks_for_target(target: dict[str, Any], requested_checks: list[str]) -> list[str]:
    candidate_checks = CHECKS_BY_CANDIDATE_TYPE.get(target["candidate_type"], [])
    if target["candidate_type"] == "manual":
        candidate_checks = requested_checks
    return [check for check in requested_checks if check in candidate_checks]


def _check_supports_target(check_name: str, target: dict[str, Any]) -> bool:
    if check_name in {"reflected_input_observation", "open_redirect_indicator"}:
        return bool(target.get("parameter")) and any(name == target.get("parameter") for name, _ in parse_qsl(urlsplit(target["url"]).query, keep_blank_values=True))
    return True


def _validate_options(request_delay: float, max_requests_per_minute: int, timeout: float, max_validation_requests: int, max_redirects: int, safe_active_confirm: bool) -> None:
    if not safe_active_confirm:
        raise SafeActiveValidationError("Safe active validation requires --safe-active-confirm.")
    if request_delay < 0 or request_delay > 30:
        raise SafeActiveValidationError("--request-delay must be between 0 and 30 seconds.")
    if max_requests_per_minute < 1 or max_requests_per_minute > 120:
        raise SafeActiveValidationError("--max-requests-per-minute must be between 1 and 120.")
    if timeout <= 0 or timeout > 30:
        raise SafeActiveValidationError("--timeout must be greater than 0 and no more than 30 seconds.")
    if max_validation_requests < 1 or max_validation_requests > 500:
        raise SafeActiveValidationError("--max-validation-requests must be between 1 and 500.")
    if max_redirects < 0 or max_redirects > 10:
        raise SafeActiveValidationError("--max-redirects must be between 0 and 10.")


def _replace_query_parameter(url: str, parameter: str, value: str) -> str:
    parsed = urlsplit(url)
    pairs = [(name, value if name == parameter else current) for name, current in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(pairs), ""))


def _default_file_url(url: str) -> str:
    parsed = urlsplit(url)
    path = parsed.path if parsed.path in ALLOWED_DEFAULT_FILE_PATHS else "/robots.txt"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _read_limited_text(response: Any) -> str:
    content = b""
    if hasattr(response, "iter_content"):
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            content += chunk
            if len(content) >= MAX_RESPONSE_BYTES:
                content = content[:MAX_RESPONSE_BYTES]
                break
    else:
        raw = getattr(response, "content", b"") or b""
        content = raw[:MAX_RESPONSE_BYTES] if isinstance(raw, bytes) else str(raw).encode("utf-8")[:MAX_RESPONSE_BYTES]
    return content.decode("utf-8", errors="replace")


def _header(headers: dict[str, Any], name: str) -> Any:
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return value
    return ""


def _content_length(headers: dict[str, Any]) -> int | None:
    value = _header(headers, "content-length")
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _reflection_context(body: str) -> str:
    marker_index = body.find(SAFE_MARKER)
    if marker_index < 0:
        return "unknown"
    prefix = body[max(0, marker_index - 40):marker_index].lower()
    suffix = body[marker_index + len(SAFE_MARKER):marker_index + len(SAFE_MARKER) + 40].lower()
    if "<" not in prefix and "<" not in suffix:
        return "html_text"
    if "=" in prefix[-20:]:
        return "attribute_like"
    return "unknown"


def _owasp_for_validation_result(result: dict[str, Any]) -> list[dict[str, Any]]:
    mapping = {
        "reflected_input_observation": ("A05:2025", "Injection", "Low"),
        "cors_indicator": ("A02:2025", "Security Misconfiguration", "Low"),
        "directory_listing_indicator": ("A02:2025", "Security Misconfiguration", "Medium"),
        "default_file_exposure_indicator": ("A02:2025", "Security Misconfiguration", "Low"),
        "http_methods_indicator": ("A02:2025", "Security Misconfiguration", "Low"),
        "open_redirect_indicator": ("A06:2025", "Insecure Design", "Low"),
    }
    if not result.get("indicator_found"):
        return []
    owasp_id, name, confidence = mapping.get(str(result.get("check_name")), ("", "", "Low"))
    if not owasp_id:
        return []
    return [
        {
            "owasp_id": owasp_id,
            "owasp_name": name,
            "confidence": confidence,
            "mapping_reason": "Safe active validation observed a potential indicator.",
            "manual_validation_required": True,
        }
    ]


def _unscoped_decision(url: str) -> dict[str, Any]:
    return {"target": url, "in_scope": True, "reason": "No bug bounty scope configured.", "matched_rule": ""}


def _safe_error(exc: Exception) -> str:
    return exc.__class__.__name__
