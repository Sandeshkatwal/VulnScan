"""API helpers for GET-only Authenticated Crawl."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scanner.auth_redaction import safe_profile_summary
from scanner.authenticated_crawler import AUTHENTICATED_CRAWL_REPORTS_DIR, authenticated_crawl
from scanner.session_profiles import validate_session_profile


def api_run_authenticated_crawl(request: Any) -> dict[str, Any]:
    profile = dict(request.profile or {})
    validation = validate_session_profile(profile)
    if not validation.get("valid"):
        return {
            "authenticated_crawl_summary": {"enabled": False, "errors": validation.get("errors", [])},
            "authenticated_crawl_results": [],
            "authenticated_crawl_skipped": [],
            "authenticated_boundary_events": [],
        }
    result = authenticated_crawl(
        request.url,
        profile,
        {
            "max_pages": request.max_pages,
            "max_depth": request.max_depth,
            "request_delay": request.request_delay,
            "timeout": request.timeout,
            "max_redirects": request.max_redirects,
            "same_origin_only": request.same_origin_only,
            "dry_run": request.dry_run,
            "scope_file": request.scope_file,
            "enforce_scope": request.enforce_scope,
        },
    )
    result["profile"] = safe_profile_summary(profile)
    return result


def api_list_authenticated_crawls() -> dict[str, Any]:
    root = AUTHENTICATED_CRAWL_REPORTS_DIR
    reports = []
    if root.exists():
        for path in sorted(root.glob("*.json"), reverse=True):
            reports.append({"report_id": path.stem, "path": str(path), "updated_at": _mtime(path)})
    return {"authenticated_crawl_reports": reports}


def _mtime(path: Path) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat(timespec="seconds")
