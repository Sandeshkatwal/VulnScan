"""Authenticated Scope boundary and Auth-Required Endpoint classification."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from scanner.auth_redaction import safe_profile_summary


DEFAULT_BLOCKED_KEYWORDS = ("logout", "delete", "remove", "destroy", "payment", "checkout", "transfer", "admin/delete", "account/delete")


def is_auth_blocked_path(url: str, profile: dict[str, Any]) -> bool:
    path = _path(url).lower()
    blocked = [str(item).lower() for item in profile.get("blocked_paths") or []]
    for rule in [*blocked, *DEFAULT_BLOCKED_KEYWORDS]:
        if not rule:
            continue
        normalized = rule if rule.startswith("/") else f"/{rule}"
        if path == normalized or path.startswith(normalized.rstrip("/") + "/") or rule.strip("/") in path:
            return True
    return False


def is_url_allowed_by_auth_profile(url: str, profile: dict[str, Any]) -> bool:
    return bool(classify_auth_boundary(url, profile).get("allowed_by_profile"))


def classify_auth_boundary(url: str, profile: dict[str, Any]) -> dict[str, Any]:
    summary = safe_profile_summary(profile)
    parsed = urlsplit(str(url or ""))
    host = (parsed.hostname or "").lower()
    allowed_hosts = [str(item).lower() for item in summary.get("allowed_hosts") or []]
    if not allowed_hosts:
        target_host = urlsplit(str(summary.get("target_base_url") or "")).hostname
        allowed_hosts = [target_host.lower()] if target_host else []
    if not host or host not in allowed_hosts:
        return _boundary(url, summary, False, False, "Host is outside the Authenticated Scope.", "allowed_hosts")
    if is_auth_blocked_path(url, summary):
        return _boundary(url, summary, False, True, "Path is blocked by the Session Profile boundary.", "blocked_paths")
    allowed_paths = [str(item) for item in summary.get("allowed_paths") or ["/"]]
    path = _path(url)
    for rule in allowed_paths:
        normalized = rule if rule.startswith("/") else f"/{rule}"
        if path == normalized or path.startswith(normalized.rstrip("/") + "/") or normalized == "/":
            return _boundary(url, summary, True, False, "URL is inside the Authenticated Scope.", "allowed_paths")
    return _boundary(url, summary, False, False, "Path is outside the allowed Authenticated Crawl Boundary.", "allowed_paths")


def classify_auth_required_endpoint(endpoint: dict[str, Any], profile: dict[str, Any] | None = None) -> dict[str, Any]:
    item = dict(endpoint or {})
    url = str(item.get("normalised_url") or item.get("url") or item.get("affected_url") or item.get("path") or "")
    status = int(item.get("status_code") or item.get("status") or 0) if str(item.get("status_code") or item.get("status") or "0").isdigit() else 0
    text = " ".join(str(item.get(key) or "") for key in ("title", "page_title", "snippet", "evidence_summary", "redirect_url", "final_url")).lower()
    path = _path(url).lower()
    classification = "unknown"
    reason = "No authentication requirement signal was observed."
    if status in {401, 403}:
        classification = "auth_required_likely"
        reason = f"Observed HTTP {status} response."
    elif "login" in text or "sign in" in text or "signin" in text or "redirect" in text and "login" in text:
        classification = "auth_required_likely"
        reason = "Redirect-to-login or login-required content indicator observed."
    elif any(token in path for token in ("account", "profile", "settings", "dashboard", "orders", "billing")):
        classification = "auth_required_likely"
        reason = "Path suggests an Auth-Required Endpoint."
    elif status and status < 400:
        classification = "public_likely"
        reason = "Endpoint appears reachable from available metadata."
    boundary = classify_auth_boundary(url, profile) if profile and urlsplit(url).scheme else {}
    item.update(
        {
            "auth_required_classification": classification,
            "auth_required_likely": classification == "auth_required_likely",
            "auth_classification_reason": reason,
            "auth_profile_id": boundary.get("auth_profile_id", ""),
            "role_label": boundary.get("role_label", safe_profile_summary(profile or {}).get("role_label", "")),
            "allowed_by_auth_profile": boundary.get("allowed_by_profile"),
            "blocked_by_auth_profile": boundary.get("blocked_by_profile"),
        }
    )
    return item


def classify_auth_required_endpoints(endpoint_results: list[dict[str, Any]], profile: dict[str, Any] | None = None) -> dict[str, Any]:
    rows = [classify_auth_required_endpoint(item, profile) for item in endpoint_results or []]
    return {
        "auth_required_endpoint_classification": {
            "enabled": True,
            "total_endpoints": len(rows),
            "auth_required_likely_count": sum(1 for item in rows if item.get("auth_required_classification") == "auth_required_likely"),
            "public_likely_count": sum(1 for item in rows if item.get("auth_required_classification") == "public_likely"),
            "unknown_count": sum(1 for item in rows if item.get("auth_required_classification") == "unknown"),
            "role_label": safe_profile_summary(profile or {}).get("role_label", ""),
            "limitations": ["Classification only. VulScan does not bypass authentication or confirm access-control impact."],
        },
        "classified_endpoints": rows,
    }


def _boundary(url: str, profile: dict[str, Any], allowed: bool, blocked: bool, reason: str, matched_rule: str) -> dict[str, Any]:
    return {
        "url": url,
        "allowed_by_profile": allowed,
        "blocked_by_profile": blocked,
        "reason": reason,
        "matched_rule": matched_rule,
        "auth_profile_id": profile.get("profile_id") or "",
        "role_label": profile.get("role_label") or "",
    }


def _path(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    path = parsed.path or str(url or "") or "/"
    if not path.startswith("/"):
        path = "/" + PurePosixPath(path).as_posix().lstrip("/")
    return path or "/"
