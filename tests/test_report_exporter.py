import json

import pytest

from scanner.report_composer import compose_report
from scanner.report_exporter import export_composed_report_html, export_composed_report_json, export_composed_report_markdown, export_safety_check


def safe_report():
    finding = {"finding_id": "finding-001", "title": "Candidate", "severity": "Low", "confidence": "Low", "validation_status": "candidate", "owasp_categories": ["A02:2025"], "evidence_references": [], "technical_summary": "Safe summary."}
    return compose_report(title="Report", target="http://127.0.0.1", findings=[finding])


def test_export_markdown_html_json_reports(tmp_path, monkeypatch):
    import scanner.report_exporter as exporter

    monkeypatch.setattr(exporter, "MARKDOWN_DIR", tmp_path / "markdown")
    monkeypatch.setattr(exporter, "HTML_DIR", tmp_path / "html")
    monkeypatch.setattr(exporter, "JSON_DIR", tmp_path / "json")
    monkeypatch.setattr(exporter, "COMPOSED_DIR", tmp_path)
    report = safe_report()

    md = export_composed_report_markdown(report)
    html = export_composed_report_html(report)
    js = export_composed_report_json(report)

    assert md.exists()
    assert html.exists()
    assert js.exists()
    exported = md.read_text(encoding="utf-8") + html.read_text(encoding="utf-8") + json.dumps(json.loads(js.read_text(encoding="utf-8")))
    assert "Bearer " not in exported
    assert "password=" not in exported


def test_export_blocked_on_unsafe_evidence(monkeypatch):
    report = safe_report()
    report["findings"][0]["evidence_references"] = ["missing-evidence"]

    check = export_safety_check(report)

    assert check["export_allowed"] is False
    with pytest.raises(ValueError):
        export_composed_report_json(report)

