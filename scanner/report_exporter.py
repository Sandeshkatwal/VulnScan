"""Safe Markdown, HTML, and JSON exporters for composed reports."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.evidence_redaction import redact_mapping_values, redact_secrets, validate_redaction
from scanner.finding_builder import evidence_safety_for_references
from scanner.report_sections import build_report_sections


COMPOSED_DIR = Path("reports") / "composed"
MARKDOWN_DIR = COMPOSED_DIR / "markdown"
HTML_DIR = COMPOSED_DIR / "html"
JSON_DIR = COMPOSED_DIR / "json"


def ensure_report_dirs() -> None:
    for path in (COMPOSED_DIR, MARKDOWN_DIR, HTML_DIR, JSON_DIR):
        path.mkdir(parents=True, exist_ok=True)


def composed_report_path(report_id: str, fmt: str) -> Path | None:
    safe_id = "".join(ch for ch in report_id if ch.isalnum() or ch in {"-", "_"})
    roots = {"markdown": MARKDOWN_DIR, "html": HTML_DIR, "json": JSON_DIR, "md": MARKDOWN_DIR}
    suffixes = {"markdown": ".md", "md": ".md", "html": ".html", "json": ".json"}
    root = roots.get(fmt)
    suffix = suffixes.get(fmt)
    if not root or not suffix:
        return None
    candidates = sorted(root.glob(f"*{safe_id}*{suffix}"))
    return candidates[-1] if candidates else None


def export_safety_check(report: dict[str, Any]) -> dict[str, Any]:
    blocked: list[dict[str, Any]] = []
    checked: list[dict[str, Any]] = []
    for finding in report.get("findings") or []:
        refs = list(finding.get("evidence_references") or [])
        safety = evidence_safety_for_references(refs)
        checked.append({"finding_id": finding.get("finding_id"), **safety})
        if not safety["export_allowed"]:
            blocked.append({"finding_id": finding.get("finding_id"), "blocked_evidence": safety["blocked_evidence"]})
    safe_report = redact_mapping_values(report)
    text_check = validate_redaction(json.dumps(_scalar_values(safe_report), sort_keys=True, default=str))
    if not text_check["passed"]:
        blocked.append({"finding_id": "report", "blocked_evidence": [{"reasons": ["Report content contains secret-like patterns after redaction."]}]})
    return {
        "export_allowed": not blocked,
        "status": "allowed" if not blocked else "blocked",
        "checked_findings": checked,
        "blocked_findings": blocked,
        "redaction_check": text_check,
    }


def export_composed_report_json(report: dict[str, Any]) -> Path:
    ensure_report_dirs()
    check = export_safety_check(report)
    if not check["export_allowed"]:
        raise ValueError("Composed report export blocked by evidence safety checks.")
    safe = redact_mapping_values(dict(report))
    safe["export_safety_status"] = "allowed"
    path = JSON_DIR / _filename(safe, "json")
    path.write_text(json.dumps(safe, indent=2), encoding="utf-8")
    return path


def export_composed_report_markdown(report: dict[str, Any]) -> Path:
    ensure_report_dirs()
    check = export_safety_check(report)
    if not check["export_allowed"]:
        raise ValueError("Composed report export blocked by evidence safety checks.")
    text = _render_markdown(redact_mapping_values(report))
    redaction = validate_redaction(text)
    if not redaction["passed"]:
        raise ValueError("Markdown export blocked because secret-like content remains.")
    path = MARKDOWN_DIR / _filename(report, "md")
    path.write_text(text, encoding="utf-8")
    return path


def export_composed_report_html(report: dict[str, Any]) -> Path:
    ensure_report_dirs()
    check = export_safety_check(report)
    if not check["export_allowed"]:
        raise ValueError("Composed report export blocked by evidence safety checks.")
    text = _render_html(redact_mapping_values(report))
    redaction = validate_redaction(text)
    if not redaction["passed"]:
        raise ValueError("HTML export blocked because secret-like content remains.")
    path = HTML_DIR / _filename(report, "html")
    path.write_text(text, encoding="utf-8")
    return path


def _filename(report: dict[str, Any], suffix: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    report_id = "".join(ch for ch in str(report.get("report_id") or "report") if ch.isalnum() or ch in {"-", "_"})
    return f"report_{stamp}_{report_id}.{suffix}"


def _scalar_values(value: Any) -> Any:
    if isinstance(value, dict):
        return [_scalar_values(item) for item in value.values()]
    if isinstance(value, list):
        return [_scalar_values(item) for item in value]
    return value


def _render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# {redact_secrets(str(report.get('title') or 'VulScan Assessment Report'))}",
        "",
        f"**Target:** {redact_secrets(str(report.get('target') or ''))}",
        f"**Assessment Type:** {report.get('assessment_type')}",
        f"**Generated:** {report.get('generated_at')}",
        f"**Status:** {report.get('report_status')}",
        "",
        "## Safe Testing Statement",
        str(report.get("safe_testing_statement") or ""),
        "",
    ]
    summary = report.get("executive_summary") or {}
    lines.extend(["## Executive Summary", str(summary.get("summary") if isinstance(summary, dict) else summary), ""])
    overview = report.get("risk_overview") or {}
    lines.extend(["## Findings Summary", f"Total findings: {overview.get('total', len(report.get('findings') or []))}", ""])
    for finding in report.get("findings") or []:
        lines.extend(
            [
                f"## Technical Finding: {redact_secrets(str(finding.get('title') or 'Finding'))}",
                f"- Finding ID: {finding.get('finding_id')}",
                f"- Severity: {finding.get('severity')}",
                f"- Confidence: {finding.get('confidence')}",
                f"- Validation Status: {finding.get('validation_status')}",
                f"- Retest Status: {finding.get('retest_status')}",
                f"- Evidence References: {', '.join(finding.get('evidence_references') or []) or 'None'}",
                "",
                "### Technical Summary",
                redact_secrets(str(finding.get("technical_summary") or "")),
                "",
                "### Business Impact",
                redact_secrets(str(finding.get("business_impact") or "")),
                "",
                "### Technical Impact",
                redact_secrets(str(finding.get("technical_impact") or "")),
                "",
                "### Developer Remediation",
                redact_secrets(str(finding.get("remediation") or finding.get("developer_guidance") or "")),
                "",
                "### Limitations",
                "; ".join(finding.get("limitations") or []),
                "",
            ]
        )
    lines.extend(["## OWASP Mapping", json.dumps(report.get("owasp_summary") or {}, indent=2), "", "## Evidence Summary", json.dumps(report.get("evidence_summary") or {}, indent=2), "", "## Retest Summary", json.dumps(report.get("retest_summary") or {}, indent=2), "", "## Risk Acceptance", json.dumps(report.get("risk_acceptance_summary") or {}, indent=2), ""])
    return "\n".join(lines)


def _render_html(report: dict[str, Any]) -> str:
    sections = build_report_sections(report)
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'><title>VulScan Composed Report</title>",
        "<style>body{font-family:Arial,sans-serif;margin:32px;color:#17202a}h1,h2{color:#102a43}.finding{border:1px solid #d8dee9;padding:16px;margin:16px 0;border-radius:6px}.meta{color:#52606d}pre{white-space:pre-wrap;background:#f5f7fa;padding:12px;border-radius:6px}</style>",
        "</head><body>",
        f"<h1>{html.escape(redact_secrets(str(report.get('title') or 'VulScan Assessment Report')))}</h1>",
        f"<p class='meta'>Target: {html.escape(redact_secrets(str(report.get('target') or '')))} | Generated: {html.escape(str(report.get('generated_at') or ''))} | Status: {html.escape(str(report.get('report_status') or ''))}</p>",
    ]
    for section in sections:
        if section["section_id"] == "technical_findings":
            parts.append("<h2>Technical Findings</h2>")
            for finding in section["content"]:
                parts.append("<div class='finding'>")
                parts.append(f"<h3>{html.escape(redact_secrets(str(finding.get('title') or 'Finding')))}</h3>")
                parts.append(f"<p><strong>Severity:</strong> {html.escape(str(finding.get('severity') or ''))} <strong>Confidence:</strong> {html.escape(str(finding.get('confidence') or ''))}</p>")
                parts.append(f"<p><strong>Evidence References:</strong> {html.escape(', '.join(finding.get('evidence_references') or []) or 'None')}</p>")
                parts.append(f"<p>{html.escape(redact_secrets(str(finding.get('technical_summary') or '')))}</p>")
                parts.append(f"<p><strong>Developer Remediation:</strong> {html.escape(redact_secrets(str(finding.get('remediation') or finding.get('developer_guidance') or '')))}</p>")
                parts.append("</div>")
        else:
            parts.append(f"<h2>{html.escape(str(section['title']))}</h2>")
            content = section["content"]
            if isinstance(content, dict):
                parts.append(f"<pre>{html.escape(redact_secrets(json.dumps(content, indent=2, default=str)))}</pre>")
            else:
                parts.append(f"<p>{html.escape(redact_secrets(str(content or '')))}</p>")
    parts.append("</body></html>")
    return "".join(parts)
