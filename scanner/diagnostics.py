"""Safe diagnostics for VulScan public beta checks."""

from __future__ import annotations

import platform
from pathlib import Path
from typing import Any

from scanner.health_check import ROOT, run_health_checks
from scanner.version import version_metadata


KEY_PATHS = (
    "scanner",
    "tests",
    "data",
    "data/demo",
    "reports",
    "docs",
    "docs/beta",
    "dashboard",
    ".github/workflows",
)


def build_diagnostics() -> dict[str, Any]:
    """Return diagnostics without environment variables, auth content, cookies, or tokens."""
    health = run_health_checks()
    missing_optional = [
        path for path in ("reports/diagnostics", "dashboard/dist")
        if not (ROOT / path).exists()
    ]
    warnings = list(health.get("warnings") or [])
    if missing_optional:
        warnings.append("Some optional generated directories are missing.")
    failed_checks = [
        item["path"] for item in health.get("paths", [])
        if not item.get("exists")
    ]
    failed_checks.extend(
        item["package"] for item in health.get("packages", [])
        if not item.get("available")
    )
    return {
        "system": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "version": version_metadata(),
        "key_paths": {
            path: {"exists": (ROOT / path).exists(), "is_dir": (ROOT / path).is_dir()}
            for path in KEY_PATHS
        },
        "missing_optional_directories": missing_optional,
        "package_availability": health.get("packages", []),
        "safety_checks": {
            "authorised_use_only": True,
            "environment_variables_dumped": False,
            "auth_profiles_dumped": False,
            "secret_values_dumped": False,
            "obvious_secret_file_count": health.get("obvious_secret_file_count", 0),
        },
        "warnings": warnings,
        "summary": {
            "status": "pass" if not failed_checks else "fail",
            "passed": not failed_checks,
            "failed_checks": failed_checks,
        },
    }
