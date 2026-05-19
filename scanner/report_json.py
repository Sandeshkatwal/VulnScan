"""JSON report writer for VulScan scan results."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from scanner.evidence import redact_nested
from scanner.finding import SEVERITY_ORDER, findings_to_dicts
from scanner.windows_result import build_windows_consolidated_summary


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
        "demo_mode": bool(scan_result.get("demo_mode")),
        "demo_notice": scan_result.get("demo_notice") or "",
        "open_ports": scan_result["open_ports"],
        "findings": findings_to_dicts(scan_result.get("findings", [])),
        "http_findings": scan_result.get("http_findings", []),
        "tls_findings": scan_result.get("tls_findings", []),
        "ssh_audit": scan_result.get("ssh_audit", {"enabled": False, "status": "skipped"}),
        "ssh_audit_summary": scan_result.get(
            "ssh_audit_summary",
            {"enabled": False, "status": "skipped"},
        ),
        "windows_audit_summary": scan_result.get(
            "windows_audit_summary",
            {"enabled": False, "status": "skipped"},
        ),
        "windows_audit_sections": scan_result.get("windows_audit_sections", []),
        "windows_audit_consolidated_summary": _windows_consolidated_summary(scan_result),
        "web_scan_summary": scan_result.get(
            "web_scan_summary",
            {"enabled": False, "status": "skipped"},
        ),
        "web_header_summary": scan_result.get(
            "web_header_summary",
            {"enabled": False, "status": "skipped"},
        ),
        "web_header_results": scan_result.get("web_header_results", []),
        "web_cookie_summary": scan_result.get(
            "web_cookie_summary",
            {"enabled": False, "status": "skipped"},
        ),
        "web_cookie_results": scan_result.get("web_cookie_results", []),
        "web_form_summary": scan_result.get(
            "web_form_summary",
            {"enabled": False, "status": "skipped"},
        ),
        "web_form_results": scan_result.get("web_form_results", []),
        "web_passive_summary": scan_result.get(
            "web_passive_summary",
            {"enabled": False, "status": "skipped"},
        ),
        "crawled_pages": scan_result.get("crawled_pages", []),
        "discovered_forms": scan_result.get("discovered_forms", []),
        "web_findings": findings_to_dicts(scan_result.get("web_findings", [])),
        "credentialed_audits": credentialed_audits_to_dicts(
            scan_result.get("credentialed_audits", [])
        ),
        "ssh_findings": scan_result.get("ssh_findings", []),
        "windows_findings": scan_result.get("windows_findings", []),
        "summary": build_summary(scan_result),
    }
    report = redact_nested(report)

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

    notes = "TCP connect scan of common ports only. Review exposed services for business need and network access controls."
    if scan_result.get("web_scan_summary", {}).get("enabled"):
        notes = (
            "Web DAST crawler foundation only. Review discovered pages and forms before deeper testing; "
            "header checks are passive when enabled, and VulScan does not submit forms or test injection vulnerabilities."
        )
    if scan_result.get("web_passive_summary", {}).get("enabled"):
        notes = (
            "Web DAST passive risk summary consolidates crawler, header, cookie, and form indicators. "
            "It does not submit forms, authenticate, test SQL injection or XSS, or prove exploitability."
        )

    return {
        "total_open_ports": len(open_ports),
        "services_detected": services_detected,
        "total_findings": len(findings),
        "total_http_findings": len(scan_result.get("http_findings", [])),
        "total_tls_findings": len(scan_result.get("tls_findings", [])),
        "total_ssh_findings": len(scan_result.get("ssh_findings", [])),
        "total_windows_findings": len(scan_result.get("windows_findings", [])),
        "total_web_findings": len(scan_result.get("web_findings", [])),
        "highest_risk_level": _highest_risk_level(findings),
        "notes": notes,
    }


def _windows_consolidated_summary(scan_result: dict[str, Any]) -> dict[str, Any]:
    if scan_result.get("windows_audit_consolidated_summary"):
        return scan_result["windows_audit_consolidated_summary"]
    sections = scan_result.get("windows_audit_sections") or []
    if sections:
        return build_windows_consolidated_summary(
            sections=sections,
            windows_findings=scan_result.get("windows_findings", []),
            base_summary=scan_result.get("windows_audit_summary", {"enabled": False, "status": "skipped"}),
        )
    return scan_result.get("windows_audit_summary", {"enabled": False, "status": "skipped"})


def credentialed_audits_to_dicts(value: Any) -> list[dict[str, Any]]:
    audits: list[dict[str, Any]] = []
    for audit in value or []:
        audit_dict = audit.to_dict() if hasattr(audit, "to_dict") else dict(audit)
        audit_dict["findings"] = findings_to_dicts(audit_dict.get("findings", []))
        audits.append(audit_dict)
    return audits


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
