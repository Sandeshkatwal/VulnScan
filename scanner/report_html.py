"""HTML report writer for VulScan scan results."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from scanner.evidence import redact_nested
from scanner.finding import findings_to_dicts
from scanner.report_json import build_summary, credentialed_audits_to_dicts, _windows_consolidated_summary


REPORTS_DIR = Path("reports")
TEMPLATES_DIR = Path(__file__).parent / "templates"


def save_html_report(
    scan_result: dict[str, Any],
    scanner_name: str,
    scanner_version: str,
    scan_start_time: datetime,
    scan_end_time: datetime,
    reports_dir: Path = REPORTS_DIR,
) -> Path:
    """Save a scan result as a Windows-safe HTML report file."""
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

    environment = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=select_autoescape(("html", "xml")),
    )
    template = environment.get_template("report.html")
    rendered_report = template.render(report=report)

    report_path = reports_dir / _build_report_filename(target, scan_start_time)
    report_path.write_text(rendered_report, encoding="utf-8")
    return report_path


def _build_report_filename(target: str, scan_start_time: datetime) -> str:
    timestamp = scan_start_time.strftime("%Y-%m-%d_%H%M%S")
    safe_target = _windows_safe_filename_part(target)
    return f"{safe_target}_{timestamp}.html"


def _windows_safe_filename_part(value: str) -> str:
    cleaned = re.sub(r'[<>:"/\\|?*\s]+', "_", value.strip())
    cleaned = cleaned.strip("._")
    return cleaned or "target"
