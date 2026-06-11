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


def api_list_findings() -> dict[str, Any]:
    findings = list_findings()
    return {"findings": findings, "total": len(findings)}


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

