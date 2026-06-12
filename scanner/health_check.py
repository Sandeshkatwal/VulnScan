"""Safe local health checks for VulScan public beta readiness."""

from __future__ import annotations

import importlib
import os
import tempfile
from pathlib import Path
from typing import Any

from scanner.version import APP_NAME, AUTHORISED_USE_ONLY, VERSION


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_IMPORTS = ("fastapi", "typer", "rich", "requests")
REQUIRED_PATHS = (
    "data",
    "data/demo",
    "data/findings/sample_finding.json",
    "reports",
    "scanner",
    "dashboard",
)


def _path_exists(relative_path: str) -> dict[str, Any]:
    path = ROOT / relative_path
    return {"path": relative_path, "exists": path.exists(), "is_dir": path.is_dir()}


def _reports_writable() -> bool:
    reports_dir = ROOT / "reports"
    reports_dir.mkdir(exist_ok=True)
    try:
        with tempfile.NamedTemporaryFile(prefix=".vulscan-health-", dir=reports_dir, delete=True) as handle:
            handle.write(b"ok")
        return True
    except OSError:
        return False


def _package_checks() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for package in REQUIRED_IMPORTS:
        try:
            importlib.import_module(package)
        except Exception as exc:  # pragma: no cover - exact import errors vary by environment
            checks.append({"package": package, "available": False, "error": exc.__class__.__name__})
        else:
            checks.append({"package": package, "available": True})
    return checks


def _obvious_secret_files() -> list[str]:
    suspicious_names = (".env", "cookies.txt")
    suspicious_suffixes = (".pem", ".key")
    matches: list[str] = []
    ignored_parts = {".git", ".venv", ".venv311", "venv", "env", "node_modules"}
    for path in ROOT.rglob("*"):
        if any(part in ignored_parts for part in path.parts):
            continue
        if path.is_file() and (path.name in suspicious_names or path.suffix.lower() in suspicious_suffixes):
            matches.append(str(path.relative_to(ROOT)))
    return sorted(matches)


def run_health_checks() -> dict[str, Any]:
    """Run lightweight checks without printing secrets or reading auth profile content."""
    path_checks = [_path_exists(path) for path in REQUIRED_PATHS]
    package_checks = _package_checks()
    secret_files = _obvious_secret_files()
    warnings: list[str] = []
    if secret_files:
        warnings.append("Potential local secret files are present and should not be committed.")
    if not (ROOT / "dashboard" / "dist").exists():
        warnings.append("Dashboard build output was not found; run npm run build before release verification.")

    passed = (
        all(item["exists"] for item in path_checks)
        and all(item["available"] for item in package_checks)
        and _reports_writable()
    )
    return {
        "status": "ok" if passed else "warning",
        "app_name": APP_NAME,
        "scanner": APP_NAME,
        "version": VERSION,
        "authorised_use_only": AUTHORISED_USE_ONLY,
        "safety_statement": "Authorised testing only.",
        "python_compatible": os.sys.version_info >= (3, 11),
        "reports_writable": _reports_writable(),
        "paths": path_checks,
        "packages": package_checks,
        "demo_data_exists": (ROOT / "data" / "demo").exists(),
        "safe_sample_files_exist": (ROOT / "data" / "findings" / "sample_finding.json").exists(),
        "database_note": "SQLite history database is optional and created during local use.",
        "api_start_note": "API startup is verified by running scanner.main api in local development or CI smoke checks.",
        "dashboard_build_status_note": "dist present" if (ROOT / "dashboard" / "dist").exists() else "not built",
        "obvious_secret_file_count": len(secret_files),
        "warnings": warnings,
    }
