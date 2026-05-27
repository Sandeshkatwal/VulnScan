"""Reusable safe scan runner for the local VulScan API foundation."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from scanner.asset_criticality import disabled_asset_context
from scanner.finding import assign_sequential_finding_ids, create_port_exposure_findings
from scanner.history import save_scan_result
from scanner.port_scan import scan_tcp_ports
from scanner.prioritisation import build_prioritisation
from scanner.prioritisation_report import build_fix_first_dashboard, disabled_fix_first_dashboard
from scanner.prioritisation_trends import disabled_prioritisation_trends
from scanner.report_html import save_html_report
from scanner.report_json import build_summary, save_json_report
from scanner.software_inventory import build_software_inventory
from scanner.vuln_intel import DEFAULT_RULES_PATH, disabled_vulnerability_intelligence_summary, run_vulnerability_intelligence


def run_scan_pipeline(
    *,
    target: str,
    scan_mode: str = "safe",
    json_report: bool = False,
    html_report: bool = False,
    save_db: bool = True,
    vuln_intel: bool = False,
    prioritise: bool = False,
    fix_first_dashboard: bool = False,
    scanner_name: str = "VulScan",
    scanner_version: str = "unknown",
) -> dict[str, Any]:
    """Run the Version 16.0 API-safe scan pipeline synchronously."""
    if str(scan_mode or "").lower() != "safe":
        raise ValueError("Version 16.0 API supports only safe scan_mode.")
    cleaned_target = str(target or "").strip()
    if not cleaned_target:
        raise ValueError("A target is required.")

    scan_start_time = datetime.now().astimezone()
    scan_result = scan_tcp_ports(cleaned_target)
    scan_result["scan_id"] = str(uuid4())
    scan_result["scan_mode"] = "safe"
    scan_result["http_findings"] = []
    scan_result["tls_findings"] = []
    scan_result["ssh_audit"] = {"enabled": False, "status": "not_available_in_api_15_0", "findings": []}
    scan_result["ssh_audit_summary"] = {"enabled": False, "status": "not_available_in_api_15_0"}
    scan_result["windows_audit"] = {"enabled": False, "status": "not_available_in_api_15_0", "findings": []}
    scan_result["windows_audit_summary"] = {"enabled": False, "status": "not_available_in_api_15_0"}
    scan_result["windows_audit_sections"] = []
    scan_result["windows_audit_consolidated_summary"] = {"enabled": False, "status": "not_available_in_api_15_0"}
    scan_result["credentialed_audits"] = []
    scan_result["ssh_findings"] = []
    scan_result["windows_findings"] = []
    scan_result["web_findings"] = []
    scan_result["vuln_intel_findings"] = []
    scan_result["asset_context"] = disabled_asset_context(cleaned_target)
    scan_result["prioritisation_summary"] = {"enabled": False}
    scan_result["prioritised_findings"] = []
    scan_result.update(disabled_fix_first_dashboard(cleaned_target))
    scan_result.update(disabled_prioritisation_trends(cleaned_target))

    findings = create_port_exposure_findings(scan_result.get("open_ports", []))
    scan_result["findings"] = assign_sequential_finding_ids(findings)
    scan_result["software_inventory"] = build_software_inventory(scan_result)
    scan_result["vulnerability_intelligence"] = disabled_vulnerability_intelligence_summary()

    if vuln_intel:
        inventory, vulnerability_intelligence, vuln_intel_findings = run_vulnerability_intelligence(
            scan_result=scan_result,
            rules_path=DEFAULT_RULES_PATH,
        )
        scan_result["software_inventory"] = inventory
        scan_result["vulnerability_intelligence"] = vulnerability_intelligence
        findings.extend(vuln_intel_findings)
        scan_result["findings"] = assign_sequential_finding_ids(findings)
        scan_result["vuln_intel_findings"] = [
            finding
            for finding in scan_result["findings"]
            if finding.get("source") in {"vuln_intel", "cve_feed", "epss_importer", "exploit_metadata"}
        ]

    if fix_first_dashboard:
        prioritise = True
    if prioritise:
        prioritisation_summary, prioritised_findings = build_prioritisation(
            scan_result["findings"],
            asset_context=scan_result.get("asset_context"),
            enabled=True,
        )
        scan_result["prioritisation_summary"] = prioritisation_summary
        scan_result["prioritised_findings"] = prioritised_findings
        scan_result.update(
            build_fix_first_dashboard(
                target=scan_result["host"],
                findings=scan_result["findings"],
                prioritised_findings=prioritised_findings,
            )
        )

    scan_end_time = datetime.now().astimezone()
    scan_result["scan_start_time"] = scan_start_time.isoformat(timespec="seconds")
    scan_result["scan_end_time"] = scan_end_time.isoformat(timespec="seconds")

    saved_scan_id = save_scan_result(scan_result) if save_db else str(scan_result["scan_id"])
    scan_result["scan_id"] = saved_scan_id

    json_path: Path | None = None
    html_path: Path | None = None
    if json_report:
        json_path = save_json_report(
            scan_result=scan_result,
            scanner_name=scanner_name,
            scanner_version=scanner_version,
            scan_start_time=scan_start_time,
            scan_end_time=scan_end_time,
        )
    if html_report:
        html_path = save_html_report(
            scan_result=scan_result,
            scanner_name=scanner_name,
            scanner_version=scanner_version,
            scan_start_time=scan_start_time,
            scan_end_time=scan_end_time,
        )

    return {
        "scan_id": saved_scan_id,
        "status": "completed",
        "target": scan_result["host"],
        "summary": build_summary(scan_result),
        "result_path": str(json_path) if json_path else None,
        "html_report_path": str(html_path) if html_path else None,
        "retrievable": bool(save_db),
        "scan_result": scan_result,
    }


def run_api_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8088,
    reload: bool = False,
) -> None:
    """Start the local FastAPI server with uvicorn."""
    import uvicorn

    if reload:
        uvicorn.run("scanner.api_app:app", host=host, port=port, reload=True)
        return

    from scanner.api_app import create_app

    uvicorn.run(create_app(), host=host, port=port, reload=False)
