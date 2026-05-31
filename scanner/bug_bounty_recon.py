"""Safe bug bounty recon foundation.

Version 18.1 only imports provided targets, validates scope, and performs
gentle HTTP/HTTPS metadata probes. It does not brute-force subdomains, query
third-party APIs, submit forms, send payloads, or store response bodies/cookies.
"""

from __future__ import annotations

import ipaddress
import re
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import requests
from bs4 import BeautifulSoup

from scanner.bug_bounty_scope import get_scope_decision, load_bug_bounty_scope
from scanner.finding import assign_sequential_finding_ids, create_finding


RECON_INPUT_DIR = Path("data") / "bug_bounty" / "recon"
RECON_REPORTS_DIR = Path("reports") / "recon"
DEFAULT_RECON_USER_AGENT = "VulScan-BugBounty-Recon"
MAX_RESPONSE_BYTES = 512 * 1024


class BugBountyReconError(ValueError):
    """Raised for friendly recon configuration errors."""


def load_recon_targets(path: str | Path) -> list[str]:
    """Load newline-delimited manual recon targets from a local text file."""
    target_path = Path(path)
    try:
        lines = target_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise BugBountyReconError(f"Recon targets file was not found: {target_path}") from exc
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def normalise_recon_target(raw: str) -> dict[str, Any]:
    """Normalise a raw target into a target type and probe candidate URLs."""
    value = str(raw or "").strip()
    target_type = classify_target_type(value)
    if target_type == "url":
        return {"target": value, "target_type": "url", "probe_candidates": [_normalise_url(value)]}
    if target_type in {"domain", "ip"}:
        host = _normalise_host(value)
        return {
            "target": host,
            "target_type": target_type,
            "probe_candidates": [f"http://{host}", f"https://{host}"],
        }
    return {"target": value, "target_type": "unknown", "probe_candidates": []}


def deduplicate_recon_targets(targets: list[str]) -> list[str]:
    """Deduplicate targets while preserving order."""
    seen: set[str] = set()
    deduped: list[str] = []
    for target in targets:
        key = str(target or "").strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(str(target).strip())
    return deduped


def classify_target_type(target: str) -> str:
    """Classify a raw recon target as url, domain, ip, or unknown."""
    value = str(target or "").strip()
    if not value:
        return "unknown"
    if "://" in value:
        parsed = urlsplit(value)
        return "url" if parsed.scheme in {"http", "https"} and parsed.netloc else "unknown"
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"(?=.{1,253}$)([a-zA-Z0-9_-]+\.)*[a-zA-Z0-9_-]+", value):
        return "domain"
    return "unknown"


def run_bug_bounty_recon(
    raw_targets: list[str],
    scope_file: str | Path | None = None,
    enforce_scope: bool = False,
    request_delay: float = 1.0,
    max_requests_per_minute: int = 30,
    timeout: float = 5.0,
    max_redirects: int = 5,
    user_agent: str = DEFAULT_RECON_USER_AGENT,
    http_get: Callable[..., Any] | None = None,
    input_source: str = "manual",
) -> dict[str, Any]:
    """Run safe recon against provided targets only."""
    _validate_recon_options(request_delay, max_requests_per_minute, timeout, max_redirects)
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    unique_targets = deduplicate_recon_targets(raw_targets)
    normalised = [normalise_recon_target(target) for target in unique_targets]
    scope = load_bug_bounty_scope(scope_file) if scope_file else None
    effective_max_rpm = _effective_max_requests_per_minute(max_requests_per_minute, scope)
    effective_delay = _effective_request_delay(request_delay, scope)
    getter = http_get or requests.get
    results: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    last_request_at = 0.0

    for item in normalised:
        candidates = item["probe_candidates"]
        if not candidates:
            skipped.append({"target": item["target"], "reason": "Unsupported target format.", "scope_reason": "", "matched_rule": ""})
            continue
        for probe_url in candidates:
            decision = get_scope_decision(probe_url, scope) if scope else _unscoped_decision(probe_url)
            if scope and not decision.get("in_scope"):
                skipped.append(
                    {
                        "target": item["target"],
                        "probe_url": probe_url,
                        "reason": "Out-of-scope target skipped.",
                        "scope_reason": decision.get("reason") or "",
                        "matched_rule": decision.get("matched_rule") or "",
                    }
                )
                continue
            last_request_at = _pace_request(last_request_at, effective_delay, effective_max_rpm)
            results.append(
                probe_http_url(
                    target=item["target"],
                    target_type=item["target_type"],
                    probe_url=probe_url,
                    scope_decision=decision,
                    timeout=timeout,
                    max_redirects=max_redirects,
                    user_agent=user_agent,
                    http_get=getter,
                )
            )

    summary = build_recon_summary(
        scope=scope,
        input_source=input_source,
        input_targets_count=len(raw_targets),
        normalised_targets_count=len(normalised),
        results=results,
        skipped=skipped,
    )
    summary["started_at"] = started_at
    summary["completed_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
    findings = build_recon_findings(summary, results, skipped)
    return {
        "bug_bounty_recon": summary,
        "bug_bounty_recon_results": results,
        "bug_bounty_recon_skipped": skipped,
        "findings": assign_sequential_finding_ids(findings),
    }


def probe_http_url(
    target: str,
    target_type: str,
    probe_url: str,
    scope_decision: dict[str, Any],
    timeout: float = 5.0,
    max_redirects: int = 5,
    user_agent: str = DEFAULT_RECON_USER_AGENT,
    http_get: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Probe one URL safely and return metadata only."""
    getter = http_get or requests.get
    started = time.perf_counter()
    base = {
        "target": target,
        "target_type": target_type,
        "probe_url": probe_url,
        "final_url": "",
        "status_code": None,
        "live": False,
        "page_title": "",
        "server_header": "",
        "x_powered_by": "",
        "content_type": "",
        "content_length": None,
        "redirect_chain": [],
        "response_time_ms": 0,
        "in_scope": bool(scope_decision.get("in_scope")),
        "scope_reason": scope_decision.get("reason") or "",
        "technology_hints": [],
        "security_header_presence": _security_header_presence({}),
        "error_code": "",
        "error_message": "",
    }
    try:
        response = getter(
            probe_url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": user_agent},
            stream=True,
        )
        if hasattr(response, "history") and len(response.history) > max_redirects:
            raise requests.TooManyRedirects(f"Redirect limit exceeded: {max_redirects}")
        body = _read_limited_text(response)
        headers = dict(getattr(response, "headers", {}) or {})
        final_url = str(getattr(response, "url", "") or probe_url)
        status_code = int(getattr(response, "status_code", 0) or 0)
        base.update(
            {
                "final_url": final_url,
                "status_code": status_code,
                "live": 200 <= status_code < 500,
                "page_title": _extract_title(body),
                "server_header": _safe_header(headers, "server"),
                "x_powered_by": _safe_header(headers, "x-powered-by"),
                "content_type": _safe_header(headers, "content-type"),
                "content_length": _content_length(headers),
                "redirect_chain": [str(getattr(item, "url", "") or "") for item in getattr(response, "history", [])],
                "technology_hints": _technology_hints(headers, body),
                "security_header_presence": _security_header_presence(headers),
            }
        )
    except requests.Timeout as exc:
        base.update({"error_code": "timeout", "error_message": "Request timed out.", "live": False})
    except requests.TooManyRedirects as exc:
        base.update({"error_code": "too_many_redirects", "error_message": str(exc), "live": False})
    except requests.RequestException as exc:
        base.update({"error_code": "request_error", "error_message": _safe_error_message(exc), "live": False})
    finally:
        base["response_time_ms"] = int((time.perf_counter() - started) * 1000)
    return base


def build_recon_summary(
    scope: dict[str, Any] | None,
    input_source: str,
    input_targets_count: int,
    normalised_targets_count: int,
    results: list[dict[str, Any]],
    skipped: list[dict[str, Any]],
) -> dict[str, Any]:
    technologies = sorted({hint["name"] for result in results for hint in result.get("technology_hints", []) if hint.get("name")})
    status_counts = Counter(str(result.get("status_code")) for result in results if result.get("status_code") is not None)
    content_type_counts = Counter(str(result.get("content_type") or "unknown").split(";")[0] for result in results if result.get("content_type"))
    return {
        "enabled": True,
        "program_id": (scope or {}).get("program_id") or "",
        "program_name": (scope or {}).get("program_name") or "",
        "input_source": input_source,
        "input_targets_count": input_targets_count,
        "normalised_targets_count": normalised_targets_count,
        "in_scope_targets_count": sum(1 for result in results if result.get("in_scope")),
        "out_of_scope_targets_count": len([item for item in skipped if "scope" in str(item.get("reason", "")).lower()]),
        "probe_candidates_count": len(results) + len(skipped),
        "probed_count": len(results),
        "live_count": sum(1 for result in results if result.get("live")),
        "error_count": sum(1 for result in results if result.get("error_code")),
        "skipped_count": len(skipped),
        "technologies_observed": technologies,
        "status_code_distribution": dict(status_counts),
        "content_type_distribution": dict(content_type_counts),
        "limitations": [
            "Recon only uses provided/imported targets and does not brute-force discovery.",
            "HTTP probing stores metadata only and does not store response bodies or cookies.",
            "Scope decisions depend on local scope file accuracy.",
        ],
    }


def build_recon_findings(
    summary: dict[str, Any],
    results: list[dict[str, Any]],
    skipped: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings = [
        create_finding(
            title="Bug Bounty Recon Completed",
            severity="Informational",
            category="Bug Bounty Recon",
            evidence=f"Recon evaluated {summary.get('normalised_targets_count', 0)} targets and found {summary.get('live_count', 0)} live services.",
            confidence="High",
            impact="Provided targets were safely checked for live HTTP/HTTPS metadata.",
            recommendation="Review live in-scope assets before deeper authorised testing.",
            verification="Review bug_bounty_recon_results in the report.",
            limitation="Recon only uses provided/imported targets and does not brute-force discovery.",
            source="bug_bounty_recon",
        )
    ]
    if skipped:
        findings.append(
            create_finding(
                title="Out-of-Scope Recon Target Skipped",
                severity="Informational",
                category="Bug Bounty Scope",
                evidence=f"{len(skipped)} target probe candidate(s) were skipped before probing.",
                confidence="High",
                impact="Out-of-scope targets were not probed by recon.",
                recommendation="Confirm bug bounty scope before testing.",
                verification="Review bug_bounty_recon_skipped in the report.",
                limitation="Scope depends on local scope file accuracy.",
                source="bug_bounty_recon",
            )
        )
    live_samples = [result for result in results if result.get("live")][:5]
    if live_samples:
        sample_text = ", ".join(f"{item.get('probe_url')} ({item.get('status_code')})" for item in live_samples)
        findings.append(
            create_finding(
                title="Live Web Asset Discovered",
                severity="Informational",
                category="Bug Bounty Recon",
                evidence=f"Live web service sample: {sample_text}",
                confidence="Medium",
                impact="One or more provided in-scope targets responded to HTTP/HTTPS probing.",
                recommendation="Consider this asset for authorised passive Web DAST and manual review.",
                verification="Review status codes, final URLs, titles, and headers in recon results.",
                limitation="Live service discovery does not indicate a vulnerability.",
                source="bug_bounty_recon",
            )
        )
    return findings


def _validate_recon_options(request_delay: float, max_requests_per_minute: int, timeout: float, max_redirects: int) -> None:
    if request_delay < 0 or request_delay > 30:
        raise BugBountyReconError("request_delay must be between 0 and 30 seconds.")
    if max_requests_per_minute < 1 or max_requests_per_minute > 120:
        raise BugBountyReconError("max_requests_per_minute must be between 1 and 120.")
    if timeout <= 0 or timeout > 30:
        raise BugBountyReconError("timeout must be greater than 0 and no more than 30 seconds.")
    if max_redirects < 0 or max_redirects > 10:
        raise BugBountyReconError("max_redirects must be between 0 and 10.")


def _effective_max_requests_per_minute(configured: int, scope: dict[str, Any] | None) -> int:
    scoped = (scope or {}).get("rate_limits", {}).get("max_requests_per_minute")
    try:
        return min(configured, int(scoped)) if scoped is not None else configured
    except (TypeError, ValueError):
        return configured


def _effective_request_delay(configured: float, scope: dict[str, Any] | None) -> float:
    scoped = (scope or {}).get("rate_limits", {}).get("request_delay_seconds")
    try:
        return max(configured, float(scoped)) if scoped is not None else configured
    except (TypeError, ValueError):
        return configured


def _pace_request(last_request_at: float, request_delay: float, max_requests_per_minute: int) -> float:
    minimum_delay = max(request_delay, 60.0 / max_requests_per_minute)
    elapsed = time.monotonic() - last_request_at if last_request_at else minimum_delay
    if elapsed < minimum_delay:
        time.sleep(minimum_delay - elapsed)
    return time.monotonic()


def _read_limited_text(response: Any) -> str:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=8192, decode_unicode=False):
        if not chunk:
            continue
        remaining = MAX_RESPONSE_BYTES - total
        if remaining <= 0:
            break
        chunks.append(chunk[:remaining])
        total += len(chunk[:remaining])
        if total >= MAX_RESPONSE_BYTES:
            break
    if hasattr(response, "close"):
        response.close()
    encoding = getattr(response, "encoding", None) or "utf-8"
    return b"".join(chunks).decode(encoding, errors="replace")


def _extract_title(html: str) -> str:
    if not html:
        return ""
    soup = BeautifulSoup(html[:MAX_RESPONSE_BYTES], "html.parser")
    title = soup.title.string if soup.title and soup.title.string else ""
    return re.sub(r"\s+", " ", title).strip()[:200]


def _technology_hints(headers: dict[str, Any], html: str) -> list[dict[str, str]]:
    hints: list[dict[str, str]] = []
    server = _safe_header(headers, "server").lower()
    powered = _safe_header(headers, "x-powered-by").lower()
    for needle, name in (("nginx", "nginx"), ("apache", "apache"), ("cloudflare", "cloudflare"), ("iis", "iis")):
        if needle in server:
            hints.append({"name": name, "source": "server_header", "confidence": "Medium"})
    for needle, name in (("php", "php"), ("express", "express"), ("asp.net", "asp.net")):
        if needle in powered:
            hints.append({"name": name, "source": "x_powered_by", "confidence": "Medium"})
    soup = BeautifulSoup(html[:MAX_RESPONSE_BYTES], "html.parser") if html else None
    if soup:
        generator = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
        content = str(generator.get("content") or "") if generator else ""
        if content:
            hints.append({"name": content[:80], "source": "generator_meta", "confidence": "Low"})
        title = _extract_title(html).lower()
        if "wordpress" in title:
            hints.append({"name": "wordpress", "source": "page_title", "confidence": "Low"})
    return _dedupe_hints(hints)


def _dedupe_hints(hints: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, str]] = []
    for hint in hints:
        key = (hint.get("name", "").lower(), hint.get("source", ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(hint)
    return deduped


def _security_header_presence(headers: dict[str, Any]) -> dict[str, bool]:
    lower = {str(key).lower(): value for key, value in headers.items()}
    return {
        "hsts_present": "strict-transport-security" in lower,
        "csp_present": "content-security-policy" in lower,
        "x_frame_options_present": "x-frame-options" in lower,
        "x_content_type_options_present": "x-content-type-options" in lower,
    }


def _safe_header(headers: dict[str, Any], name: str) -> str:
    for key, value in headers.items():
        if str(key).lower() == name.lower():
            return str(value or "")[:300]
    return ""


def _content_length(headers: dict[str, Any]) -> int | None:
    value = _safe_header(headers, "content-length")
    try:
        return int(value) if value else None
    except ValueError:
        return None


def _normalise_url(value: str) -> str:
    parsed = urlsplit(str(value).strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise BugBountyReconError(f"Unsupported URL target: {value}")
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}{query}"


def _normalise_host(value: str) -> str:
    return str(value or "").strip().lower().rstrip("/")


def _safe_error_message(exc: Exception) -> str:
    message = str(exc)
    return message[:300] if message else exc.__class__.__name__


def _unscoped_decision(target: str) -> dict[str, Any]:
    return {
        "target": target,
        "in_scope": True,
        "reason": "No bug bounty scope file was configured; caller remains responsible for authorisation.",
        "matched_rule": "",
        "program_id": "",
        "program_name": "",
    }
