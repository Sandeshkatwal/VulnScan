"""Build a safe Portfolio Demo Mode report."""

from __future__ import annotations

from typing import Any

from scanner.demo_data_loader import DEMO_REPORT_DIR, ensure_demo_dirs, load_demo_dataset
from scanner.report_composer import compose_report
import scanner.report_exporter as report_exporter
from scanner.evidence_vault import save_evidence_item


def build_demo_report(*, markdown: bool = False, html: bool = False, json_export: bool = False) -> dict[str, Any]:
    ensure_demo_dirs()
    dataset = load_demo_dataset()
    evidence_items = ((dataset.get("evidence_vault") or {}).get("evidence_vault_items") or []) if isinstance(dataset.get("evidence_vault"), dict) else []
    for evidence_item in evidence_items:
        if isinstance(evidence_item, dict):
            save_evidence_item(evidence_item)
    report = compose_report(
        title="VulScan Portfolio Demo Report",
        target=str(dataset.get("target") or "https://demo.local"),
        findings=list(dataset.get("findings") or []),
        client_or_project_name="Local Demo Only",
        assessment_type="owasp_assessment",
        report_status="draft",
        scope_summary="Local Demo Only. Simulated demo.local and 127.0.0.1 style data only.",
        methodology_summary="Portfolio Demo Mode composes Redacted Demo Evidence, simulated OWASP indicators, manual plan records, and report-ready findings. No real scan is performed.",
        owasp_summary=dataset.get("owasp_assessment") if isinstance(dataset.get("owasp_assessment"), dict) else None,
        limitations=["Safe Demo Dataset only. Findings are simulated and require authorised manual validation in real assessments."],
    )
    paths: dict[str, str] = {}
    original_dirs = (report_exporter.COMPOSED_DIR, report_exporter.MARKDOWN_DIR, report_exporter.HTML_DIR, report_exporter.JSON_DIR)
    report_exporter.COMPOSED_DIR = DEMO_REPORT_DIR
    report_exporter.MARKDOWN_DIR = DEMO_REPORT_DIR / "markdown"
    report_exporter.HTML_DIR = DEMO_REPORT_DIR / "html"
    report_exporter.JSON_DIR = DEMO_REPORT_DIR / "json"
    try:
        if markdown:
            paths["markdown"] = str(report_exporter.export_composed_report_markdown(report))
        if html:
            paths["html"] = str(report_exporter.export_composed_report_html(report))
        if json_export:
            paths["json"] = str(report_exporter.export_composed_report_json(report))
    finally:
        report_exporter.COMPOSED_DIR, report_exporter.MARKDOWN_DIR, report_exporter.HTML_DIR, report_exporter.JSON_DIR = original_dirs
    report["export_paths"] = paths
    return {"demo_report": report, "export_paths": paths, "simulated": True}


def demo_walkthrough_text(dataset: dict[str, Any] | None = None) -> str:
    data = dataset or load_demo_dataset()
    return "\n".join(str(step) for step in data.get("walkthrough") or [])
