"""Session Boundary Controls for Authenticated Crawl."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from scanner.authenticated_scope import classify_auth_boundary


DEFAULT_DESTRUCTIVE_KEYWORDS = (
    "logout",
    "signout",
    "delete",
    "remove",
    "destroy",
    "deactivate",
    "close-account",
    "payment",
    "checkout",
    "transfer",
    "purchase",
    "subscribe",
    "unsubscribe",
    "admin/delete",
    "account/delete",
    "reset-password/confirm",
    "password/change",
)
DEFAULT_DESTRUCTIVE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def is_destructive_path(url: str) -> bool:
    path = (urlsplit(str(url or "")).path or "/").lower()
    return any(keyword in path for keyword in DEFAULT_DESTRUCTIVE_KEYWORDS)


def classify_session_boundary(
    url: str,
    profile: dict[str, Any],
    *,
    start_url: str | None = None,
    same_origin_only: bool = True,
    method: str = "GET",
) -> dict[str, Any]:
    """Classify a URL before an Authenticated Crawl request is attempted."""
    method_name = str(method or "GET").upper()
    if method_name in DEFAULT_DESTRUCTIVE_METHODS and method_name != "GET":
        return _blocked(url, "destructive_method_skipped", "Authenticated Crawl uses GET-only requests.", "method", "high")
    if method_name != "GET":
        return _blocked(url, "destructive_method_skipped", "Authenticated Crawl uses GET-only requests.", "method", "high")
    if same_origin_only and start_url and _origin(url) != _origin(start_url):
        return _blocked(url, "cross_host_skipped", "URL is outside the same-origin Authenticated Crawl boundary.", "same_origin_only", "medium")
    if is_destructive_path(url):
        event_type = "logout_path_skipped" if any(token in (urlsplit(url).path or "").lower() for token in ("logout", "signout")) else "destructive_path_skipped"
        return _blocked(url, event_type, "Path matches the default destructive path blocklist.", "default_blocklist", "high")
    boundary = classify_auth_boundary(url, profile)
    if boundary.get("blocked_by_profile"):
        return {
            **boundary,
            "allowed": False,
            "event_type": "blocked_path",
            "severity": "high",
            "action_taken": "skipped",
            "boundary_status": "blocked",
        }
    if not boundary.get("allowed_by_profile"):
        event_type = "cross_host_skipped" if "Host is outside" in str(boundary.get("reason") or "") else "out_of_scope_skipped"
        return {
            **boundary,
            "allowed": False,
            "event_type": event_type,
            "severity": "medium",
            "action_taken": "skipped",
            "boundary_status": "blocked",
        }
    return {
        **boundary,
        "allowed": True,
        "event_type": "allowed",
        "severity": "info",
        "action_taken": "allowed",
        "boundary_status": "allowed",
    }


def boundary_event_from_decision(decision: dict[str, Any]) -> dict[str, Any]:
    return {
        "url": decision.get("url") or "",
        "event_type": decision.get("event_type") or "blocked_path",
        "reason": decision.get("reason") or "",
        "matched_rule": decision.get("matched_rule") or "",
        "severity": decision.get("severity") or "medium",
        "action_taken": decision.get("action_taken") or "skipped",
    }


def _blocked(url: str, event_type: str, reason: str, matched_rule: str, severity: str) -> dict[str, Any]:
    return {
        "url": url,
        "allowed_by_profile": False,
        "blocked_by_profile": True,
        "allowed": False,
        "reason": reason,
        "matched_rule": matched_rule,
        "event_type": event_type,
        "severity": severity,
        "action_taken": "skipped",
        "boundary_status": "blocked",
        "auth_profile_id": "",
        "role_label": "",
    }


def _origin(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
