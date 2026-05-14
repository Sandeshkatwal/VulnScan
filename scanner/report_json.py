"""JSON report writer for VulScan scan results."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from scanner.finding import SEVERITY_ORDER, findings_to_dicts


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
        "findings": findings_to_dicts(scan_result.get("findings", [])),
        "http_findings": scan_result.get("http_findings", []),
        "tls_findings": scan_result.get("tls_findings", []),
        "ssh_audit": scan_result.get("ssh_audit", {"enabled": False, "status": "not_run"}),
        "ssh_audit_summary": scan_result.get(
            "ssh_audit_summary",
            {"enabled": False, "status": "skipped"},
        ),
        "ssh_findings": scan_result.get("ssh_findings", []),
        "summary": build_summary(scan_result),
    }

    report_path = reports_dir / _build_report_filename(target, scan_start_time)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report_path


def build_summary(scan_result: dict[str, Any]) -> dict[str, Any]:
    """Build a short defensive summary from a scan result."""
    open_ports = scan_result["open_ports"]
    findings = findings_to_dicts(scan_result.get("findings", []))
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
        "total_findings": len(findings),
        "total_http_findings": len(scan_result.get("http_findings", [])),
        "total_tls_findings": len(scan_result.get("tls_findings", [])),
        "total_ssh_findings": len(scan_result.get("ssh_findings", [])),
        "highest_risk_level": _highest_risk_level(findings),
        "notes": "TCP connect scan of common ports only. Review exposed services for business need and network access controls.",
    }


def _highest_risk_level(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "informational"

    highest = max(
        findings,
        key=lambda finding: int(finding.get("risk_score", 0)),
    )
    return str(highest.get("risk_label", "Informational")).lower()


def _build_report_filename(target: str, scan_start_time: datetime) -> str:
    timestamp = scan_start_time.strftime("%Y-%m-%d_%H%M%S")
    safe_target = _windows_safe_filename_part(target)
    return f"{safe_target}_{timestamp}.json"


def _windows_safe_filename_part(value: str) -> str:
    cleaned = re.sub(r'[<>:"/\\|?*\s]+', "_", value.strip())
    cleaned = cleaned.strip("._")
    return cleaned or "target"
