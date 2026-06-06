import json
from datetime import datetime

from scanner.integrity_indicators import (
    assess_import_export_candidates,
    assess_trusted_data_boundary_candidates,
    assess_update_workflow_candidates,
    assess_upload_workflow_candidates,
    assess_webhook_callback_candidates,
    build_a08_manual_validation_plan,
)
from scanner.owasp_a08_integrity import assess_a08_integrity, attach_a08_integrity, load_a08_rules
from scanner.owasp_assessment import attach_owasp_assessment
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report


def test_loads_a08_rules() -> None:
    rules = load_a08_rules()
    assert rules["owasp_id"] == "A08:2025"
    assert "subresource_integrity_indicators" in rules["rule_groups"]


def test_upload_import_webhook_update_and_boundary_indicators_are_passive() -> None:
    endpoints = [
        {"url": "http://example.test/upload"},
        {"url": "http://example.test/api/import?file&format"},
        {"url": "http://example.test/backup/restore"},
        {"url": "http://example.test/webhook?signature&timestamp"},
        {"url": "http://example.test/plugins/update"},
    ]
    params = [
        {"url": "http://example.test/callback?callback_url", "parameter_name": "callback_url"},
        {"url": "http://example.test/api/data?payload", "parameter_name": "payload"},
        {"url": "http://example.test/webhook?hmac", "parameter_name": "hmac"},
    ]
    forms = [{"action": "/upload", "enctype": "multipart/form-data", "fields": [{"name": "file", "type": "file"}]}]

    evidence = (
        assess_upload_workflow_candidates(endpoints, forms, params)
        + assess_import_export_candidates(endpoints, params)
        + assess_webhook_callback_candidates(endpoints, params)
        + assess_update_workflow_candidates(endpoints)
        + assess_trusted_data_boundary_candidates(params, endpoints)
    )
    rule_ids = {item["rule_id"] for item in evidence}
    assert "file_upload_endpoint_detected" in rule_ids
    assert "import_endpoint_detected" in rule_ids
    assert "backup_restore_endpoint_detected" in rule_ids
    assert "webhook_endpoint_detected" in rule_ids
    assert "signature_parameter_name_detected" in rule_ids
    assert "update_endpoint_detected" in rule_ids or "plugin_endpoint_detected" in rule_ids
    assert all(item["manual_validation_required"] is True for item in evidence)
    assert not any(item["evidence_strength"] == "confirmed_finding" for item in evidence)
    assert not any("secret-value" in str(item).lower() for item in evidence)


def test_a08_assessment_summary_manual_plans_owasp_and_reports(tmp_path) -> None:
    payload = assess_a08_integrity(
        target="http://example.test",
        endpoint_results=[{"url": "http://example.test/api/import?file"}, {"url": "http://example.test/webhook?signature"}],
        parameter_results=[{"url": "http://example.test/api/import?file=secret-value", "parameter_name": "file"}],
        forms=[{"action": "/upload", "enctype": "multipart/form-data", "fields": [{"name": "file", "type": "file"}]}],
        scripts=[{"src": "https://cdn.example.test/app.js"}],
        stylesheets=[{"href": "https://cdn.example.test/site.css", "integrity": "sha384-test"}],
    )
    summary = payload["a08_integrity_summary"]
    evidence = payload["a08_integrity_evidence"]
    assert summary["total_evidence_items"] >= 5
    assert summary["upload_candidate_count"] >= 1
    assert summary["webhook_callback_candidate_count"] >= 1
    assert summary["sri_indicator_count"] >= 2
    assert all("secret-value" not in str(item) for item in evidence)
    assert any(item.get("duplicate_fingerprint", {}).get("owasp_category") == "A08:2025" for item in evidence)

    upload_plan = build_a08_manual_validation_plan({"workflow_type": "upload"})
    webhook_plan = build_a08_manual_validation_plan({"workflow_type": "webhook_callback"})
    sri_plan = build_a08_manual_validation_plan({"workflow_type": "subresource_integrity"})
    assert "Verify file type validation." in upload_plan["safe_manual_steps"]
    assert "Verify signatures/HMAC are required." in webhook_plan["safe_manual_steps"]
    assert "Verify SRI and CSP strategy." in sri_plan["safe_manual_steps"]

    scan_result = {
        "host": "example.test",
        "resolved_ip": "",
        "scan_mode": "unit",
        "duration_seconds": 0.1,
        "open_ports": [],
        "findings": [],
        "endpoint_results": [{"url": "http://example.test/api/import?file"}],
        "parameter_results": [{"url": "http://example.test/api/import?file=secret-value", "parameter_name": "file"}],
        "demo_mode": False,
        "demo_notice": "",
    }
    attach_a08_integrity(scan_result)
    attach_owasp_assessment(scan_result)
    assert any(item["owasp_id"] == "A08:2025" for item in scan_result["owasp_evidence_items"])

    now = datetime.now()
    json_path = save_json_report(scan_result, "VulScan", "test", now, now, reports_dir=tmp_path)
    html_path = save_html_report(scan_result, "VulScan", "test", now, now, reports_dir=tmp_path)
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["a08_integrity_summary"]["enabled"] is True
    assert "A08 Software and Data Integrity Indicator Checks" in html_path.read_text(encoding="utf-8")
