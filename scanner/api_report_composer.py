"""API helpers for Professional Finding Builder and Report Composer."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scanner.finding_builder import (
    build_finding_from_evidence_vault_item,
    build_finding_from_manual_input,
    evidence_safety_for_references,
    list_findings,
    load_finding,
    load_findings_file,
    save_finding,
)
from scanner.evidence_vault import load_evidence_item
from scanner.report_composer import compose_report
from scanner.report_exporter import (
    COMPOSED_DIR,
    export_composed_report_html,
    export_composed_report_json,
    export_composed_report_markdown,
    export_safety_check,
)
from scanner.pagination import build_paginated_response
from scanner.response_limits import compact_record, truncate_text


FINDING_SUMMARY_FIELDS = (
    "finding_id",
    "title",
    "severity",
    "status",
    "validation_status",
    "retest_status",
    "risk_score",
    "risk_label",
    "source_modules",
    "owasp_categories",
    "evidence_strength",
    "created_at",
    "updated_at",
)


def api_finding_from_evidence(evidence_id: str, save: bool = True) -> dict[str, Any]:
    evidence = load_evidence_item(evidence_id)
    if evidence is None:
        raise ValueError("Evidence Item was not found.")
    finding = build_finding_from_evidence_vault_item(evidence)
    path = save_finding(finding) if save else None
    return {"finding": finding, "path": str(path) if path else None}


def api_create_or_update_finding(payload: dict[str, Any]) -> dict[str, Any]:
    finding = build_finding_from_manual_input(payload)
    path = save_finding(finding)
    return {"finding": finding, "path": str(path)}


def api_list_findings(
    *,
    page: int = 1,
    page_size: int = 25,
    sort_by: str | None = None,
    sort_direction: str = "asc",
    severity: str | None = None,
    status: str | None = None,
    owasp_category: str | None = None,
    source_module: str | None = None,
    evidence_strength: str | None = None,
    validation_status: str | None = None,
    search: str | None = None,
    summary_only: bool = True,
) -> dict[str, Any]:
    findings = list_findings()
    records = [_finding_summary(finding) for finding in findings] if summary_only else findings
    paginated = build_paginated_response(
        records,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_direction=sort_direction,
        filters={
            "severity": severity,
            "status": status,
            "owasp_category": owasp_category,
            "source_module": source_module,
            "evidence_strength": evidence_strength,
            "validation_status": validation_status,
            "search": search,
        },
    )
    return {
        "findings": paginated["items"],
        "total": paginated["total"],
        "paginated_response": paginated,
        "summary_only": summary_only,
    }


def api_get_finding(finding_id: str) -> dict[str, Any]:
    finding = load_finding(finding_id)
    if finding is None:
        raise ValueError("Finding was not found.")
    return {"finding": finding}


def api_compose_report(payload: dict[str, Any]) -> dict[str, Any]:
    findings = list(payload.get("findings") or [])
    if payload.get("findings_file"):
        findings.extend(load_findings_file(Path(str(payload["findings_file"]))))
    report = compose_report(
        title=str(payload.get("title") or "VulScan Assessment Report"),
        target=str(payload.get("target") or ""),
        findings=findings,
        client_or_project_name=str(payload.get("client_or_project_name") or ""),
        assessment_type=str(payload.get("assessment_type") or "owasp_assessment"),
        report_status=str(payload.get("report_status") or "draft"),
        scope_summary=str(payload.get("scope_summary") or ""),
        methodology_summary=str(payload.get("methodology_summary") or ""),
        owasp_summary=payload.get("owasp_summary") if isinstance(payload.get("owasp_summary"), dict) else None,
    )
    paths: dict[str, str] = {}
    if payload.get("markdown"):
        paths["markdown"] = str(export_composed_report_markdown(report))
    if payload.get("html"):
        paths["html"] = str(export_composed_report_html(report))
    if payload.get("json", payload.get("json_export")):
        paths["json"] = str(export_composed_report_json(report))
    report["export_paths"] = paths
    return {"report": report, "export_paths": paths}


def api_export_safety_check(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("report"):
        return export_safety_check(payload["report"])
    findings = list(payload.get("findings") or [])
    if payload.get("findings_file"):
        findings.extend(load_findings_file(Path(str(payload["findings_file"]))))
    report = compose_report(title="Export Safety Check", target=str(payload.get("target") or ""), findings=findings)
    return export_safety_check(report)


def resolve_composed_report_download(report_id: str, fmt: str | None = None) -> Path | None:
    safe_id = "".join(ch for ch in str(report_id) if ch.isalnum() or ch in {"-", "_"})
    if not safe_id:
        return None
    suffixes = [f".{fmt}"] if fmt in {"json", "html"} else [".md"] if fmt in {"md", "markdown"} else [".json", ".html", ".md"]
    root = COMPOSED_DIR.resolve()
    candidates: list[Path] = []
    for suffix in suffixes:
        candidates.extend(COMPOSED_DIR.glob(f"**/*{safe_id}*{suffix}"))
    for path in sorted(candidates, key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if root in resolved.parents and resolved.is_file():
            return resolved
    return None


def evidence_refs_safety(finding: dict[str, Any]) -> dict[str, Any]:
    return evidence_safety_for_references(list(finding.get("evidence_references") or []))


def _finding_summary(finding: dict[str, Any]) -> dict[str, Any]:
    summary = compact_record(finding, FINDING_SUMMARY_FIELDS)
    summary["technical_summary"] = truncate_text(finding.get("technical_summary"))
    summary["detail_url"] = f"/reports/findings/{finding.get('finding_id')}"
    return summary
