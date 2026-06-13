import json
from pathlib import Path

from scanner.report_composer import compose_report
from scanner.report_exporter import export_composed_report_json
from scripts.generate_large_demo_dataset import build_large_demo_dataset, write_large_demo_dataset
from scripts.check_large_dataset_performance import run_check


def test_report_export_with_many_findings_does_not_include_raw_secrets(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    findings = build_large_demo_dataset(120, 10, 1)["findings"]
    findings[0]["technical_summary"] = "Authorization: Bearer secret-demo-token"
    for finding in findings:
        finding["evidence_references"] = []
    report = compose_report(title="Large Dataset Regression", target="https://demo.local", findings=findings)
    path = export_composed_report_json(report)
    text = path.read_text(encoding="utf-8")
    assert "secret-demo-token" not in text
    assert "[REDACTED-BEARER]" in text


def test_large_dataset_check_uses_fake_local_data_only(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    write_large_demo_dataset(build_large_demo_dataset(20, 30, 2))
    payload = run_check()
    assert payload["passed"] is True
    assert "demo.local" in json.dumps(payload) or payload["simulated"] is True
