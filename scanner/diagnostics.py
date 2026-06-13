"""Safe diagnostics for VulScan public beta checks."""

from __future__ import annotations

import platform
from pathlib import Path
from typing import Any

from scanner.health_check import ROOT, run_health_checks
from scanner.query_helpers import directory_size_bytes
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
    performance = _performance_diagnostics()
    if performance["warnings"]:
        warnings.extend(performance["warnings"])
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
        "performance": performance,
        "warnings": warnings,
        "summary": {
            "status": "pass" if not failed_checks else "fail",
            "passed": not failed_checks,
            "failed_checks": failed_checks,
        },
    }


def _performance_diagnostics() -> dict[str, Any]:
    demo_large_dir = ROOT / "data" / "demo" / "large"
    reports_dir = ROOT / "reports"
    performance_dir = ROOT / "reports" / "performance"
    largest_demo_file = None
    largest_size = 0
    demo_files = list(demo_large_dir.glob("*.json")) if demo_large_dir.exists() else []
    for path in demo_files:
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > largest_size:
            largest_demo_file = path.name
            largest_size = size
    warnings: list[str] = []
    if largest_size > 2_000_000:
        warnings.append("Large Demo Dataset files may slow dashboard rendering without pagination.")
    return {
        "record_counts": {
            "large_demo_files": len(demo_files),
            "finding_files": _count_files(ROOT / "data" / "findings", "*.json"),
            "evidence_files": _count_files(ROOT / "data" / "evidence_vault", "*.json"),
            "report_files": _count_files(reports_dir, "*.json") + _count_files(reports_dir, "*.html"),
        },
        "largest_demo_file": {
            "filename": largest_demo_file,
            "size_bytes": largest_size,
        },
        "report_directory_size_bytes": directory_size_bytes(reports_dir),
        "dashboard_build_status_note": "dashboard/dist present" if (ROOT / "dashboard" / "dist").exists() else "dashboard/dist not present",
        "performance_baseline_path": str(performance_dir / "performance_baseline.json"),
        "warnings": warnings,
    }


def _count_files(path: Path, pattern: str) -> int:
    if not path.exists():
        return 0
    return sum(1 for item in path.rglob(pattern) if item.is_file())
