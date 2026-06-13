import json
from pathlib import Path

from scanner.report_composer import compose_report
from scanner.report_exporter import (
    export_composed_report_html,
    export_composed_report_json,
    export_composed_report_markdown,
    export_safety_check,
)


def _finding() -> dict[str, object]:
    return {
        "finding_id": "finding-regression-001",
        "title": "Candidate Missing Security Header",
        "severity": "Low",
        "validation_status": "candidate",
        "technical_summary": "Candidate indicator requiring manual validation.",
        "evidence_references": [],
    }


def test_markdown_html_json_exports_are_redacted_safe(tmp_path: Path, monkeypatch) -> None:
    import scanner.report_exporter as exporter

    monkeypatch.setattr(exporter, "MARKDOWN_DIR", tmp_path / "markdown")
    monkeypatch.setattr(exporter, "HTML_DIR", tmp_path / "html")
    monkeypatch.setattr(exporter, "JSON_DIR", tmp_path / "json")
    monkeypatch.setattr(exporter, "COMPOSED_DIR", tmp_path)
    report = compose_report(title="Regression Report", target="http://127.0.0.1:8000", findings=[_finding()])
    markdown = export_composed_report_markdown(report)
    html = export_composed_report_html(report)
    json_path = export_composed_report_json(report)
    assert markdown.read_text(encoding="utf-8").startswith("# Regression Report")
    assert "<html" in html.read_text(encoding="utf-8")
    assert json.loads(json_path.read_text(encoding="utf-8"))["export_safety_status"] == "allowed"


def test_candidate_wording_preserved_in_report() -> None:
    report = compose_report(title="Regression Report", target="http://127.0.0.1:8000", findings=[_finding()])
    assert report["findings"][0]["validation_status"] == "candidate"
    assert "manual validation" in " ".join(report["limitations"]).lower()


def test_unsafe_missing_evidence_blocks_export() -> None:
    finding = _finding()
    finding["evidence_references"] = ["missing-evidence-id"]
    report = compose_report(title="Regression Report", target="http://127.0.0.1:8000", findings=[finding])
    check = export_safety_check(report)
    assert check["export_allowed"] is False
    assert check["blocked_findings"]
