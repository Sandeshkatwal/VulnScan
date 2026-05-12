"""JSON report writer for VulScan scan results."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


REPORTS_DIR = Path("reports")


def save_json_report(
    scan_result: dict[str, Any],
    scanner_name: str,
    scanner_version: str,
    scan_start_time: datetime,
    scan_end_time: datetime,
    reports_dir: Path = REPORTS_DIR,
) -> Path:
    """Save a scan result as a Windows-safe JSON report file."""
    reports_dir.mkdir(parents=True, exist_ok=True)

    target = str(scan_result["host"])
    report = {
        "scanner_name": scanner_name,
        "scanner_version": scanner_version,
        "target": target,
        "resolved_ip": scan_result["resolved_ip"],
        "scan_mode": scan_result["scan_mode"],
        "scan_start_time": scan_start_time.isoformat(timespec="seconds"),
        "scan_end_time": scan_end_time.isoformat(timespec="seconds"),
        "duration_seconds": scan_result["duration_seconds"],
        "open_ports": scan_result["open_ports"],
        "summary": build_summary(scan_result),
    }

    report_path = reports_dir / _build_report_filename(target, scan_start_time)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report_path


def build_summary(scan_result: dict[str, Any]) -> dict[str, Any]:
    """Build a short defensive summary from a scan result."""
    open_ports = scan_result["open_ports"]
    services_detected = sorted(
        {
            str(port_result["service"])
            for port_result in open_ports
            if port_result.get("service") and port_result["service"] != "unknown"
        }
    )

    return {
        "total_open_ports": len(open_ports),
        "services_detected": services_detected,
        "highest_risk_level": "informational",
        "notes": "TCP connect scan of common ports only. Review exposed services for business need and network access controls.",
    }


def _build_report_filename(target: str, scan_start_time: datetime) -> str:
    timestamp = scan_start_time.strftime("%Y-%m-%d_%H%M%S")
    safe_target = _windows_safe_filename_part(target)
    return f"{safe_target}_{timestamp}.json"


def _windows_safe_filename_part(value: str) -> str:
    cleaned = re.sub(r'[<>:"/\\|?*\s]+', "_", value.strip())
    cleaned = cleaned.strip("._")
    return cleaned or "target"
