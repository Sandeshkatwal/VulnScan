import json
from datetime import datetime, timezone

from scanner.owasp_a01_access_control import assess_a01_access_control, attach_a01_access_control, load_a01_rules
from scanner.owasp_assessment import build_owasp_assessment
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report


def test_load_a01_rules() -> None:
    rules = load_a01_rules()
    assert rules["owasp_id"] == "A01:2025"
    assert "object_level_authorization_candidates" in rules["rule_groups"]
    assert rules["safety"]["no_auth_bypass"] is True


def test_a01_summary_counts_and_owasp_assessment_feed() -> None:
    payload = assess_a01_access_control(
        target="http://example.test",
        endpoint_results=[
            {"url": "http://example.test/api/accounts/123/export?account_id=123"},
            {"url": "http://example.test/admin/users"},
        ],
        parameter_results=[
            {"url": "http://example.test/api/accounts/123/export?account_id=123", "parameter_name": "account_id"},
            {"url": "http://example.test/workspaces?workspace_id=abc", "parameter_name": "workspace_id"},
        ],
    )
    summary = payload["a01_access_control_summary"]
    assert summary["enabled"] is True
    assert summary["high_interest_count"] >= 1
    assert summary["object_id_candidate_count"] >= 1
    assert summary["tenant_boundary_candidate_count"] >= 1
    scan_result = {
        "host": "example.test",
        "a01_access_control_evidence": payload["a01_access_control_evidence"],
        "findings": [],
    }
    assessment = build_owasp_assessment(scan_result)
    a01_result = next(item for item in assessment["owasp_category_results"] if item["owasp_id"] == "A01:2025")
    assert a01_result["evidence_count"] >= 1
    assert a01_result["assessment_status"] in {"needs_manual_validation", "detected_indicator"}


def test_attach_a01_adds_grouped_findings_without_confirming() -> None:
    scan_result = {
        "host": "endpoint-discovery",
        "endpoint_results": [{"url": "http://example.test/admin/users/123"}],
        "parameter_results": [{"url": "http://example.test/users?id=123", "parameter_name": "id"}],
        "findings": [],
    }
    attach_a01_access_control(scan_result)
    assert scan_result["a01_access_control_summary"]["total_evidence_items"] >= 2
    assert any(item["source"] == "owasp_a01" for item in scan_result["findings"])
    assert not any(item.get("evidence_strength") == "confirmed_finding" for item in scan_result["a01_access_control_evidence"])


def test_a01_reports_include_json_and_html_sections(tmp_path) -> None:
    payload = assess_a01_access_control(
        target="http://example.test",
        endpoint_results=[{"url": "http://example.test/api/reports/export?report_id=123"}],
        parameter_results=[{"url": "http://example.test/api/reports/export?report_id=123", "parameter_name": "report_id"}],
    )
    scan_result = {
        "host": "example.test",
        "resolved_ip": "",
        "scan_mode": "endpoint-discovery",
        "duration_seconds": 0.1,
        "open_ports": [],
        "findings": [],
        "a01_access_control_summary": payload["a01_access_control_summary"],
        "a01_access_control_evidence": payload["a01_access_control_evidence"],
    }
    start = datetime.now(timezone.utc)
    json_path = save_json_report(scan_result, "VulScan", "test", start, start, reports_dir=tmp_path)
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["a01_access_control_summary"]["enabled"] is True
    assert report["a01_access_control_evidence"]
    html_path = save_html_report(scan_result, "VulScan", "test", start, start, reports_dir=tmp_path)
    html = html_path.read_text(encoding="utf-8")
    assert "A01 Broken Access Control Candidate Engine" in html
    assert "manual validation" in html.lower()
