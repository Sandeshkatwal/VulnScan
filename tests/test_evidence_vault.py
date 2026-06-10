from scanner.evidence_vault import (
    build_evidence_from_access_test_observation,
    build_evidence_from_authenticated_crawl_result,
    build_evidence_from_business_logic_observation,
    build_evidence_from_owasp_item,
    build_evidence_from_replay_observation,
    create_evidence_item,
    evidence_vault_summary,
    link_evidence_to_access_test,
    link_evidence_to_business_logic_plan,
    link_evidence_to_replay_plan,
    save_evidence_item,
)
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report
from datetime import datetime


def test_create_evidence_item_and_links(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    item = create_evidence_item(evidence_id="ev1", title="Manual", safe_summary="Safe", related_owasp_categories=["A01:2025"])
    save_evidence_item(item)
    assert link_evidence_to_access_test("ev1", "plan-1")["linked_test_plan_ids"] == ["plan-1"]
    assert link_evidence_to_replay_plan("ev1", "replay-1")["linked_replay_plan_ids"] == ["replay-1"]
    assert link_evidence_to_business_logic_plan("ev1", "business-1")["linked_business_logic_plan_ids"] == ["business-1"]


def test_builders_use_safe_fields_only() -> None:
    owasp = build_evidence_from_owasp_item({"title": "A01", "category": "A01:2025", "evidence_summary": "Cookie: secret=value"})
    crawl = build_evidence_from_authenticated_crawl_result({"url": "http://127.0.0.1:8000/dashboard", "status_code": 200, "headers": {"Cookie": "secret"}})
    access = build_evidence_from_access_test_observation({"test_plan_id": "p1", "observed_access_result": "denied_as_expected", "observed_message_summary": "Denied"})
    replay = build_evidence_from_replay_observation({"replay_plan_id": "r1", "observed_access_result": "unexpectedly_allowed", "observed_message_summary": "Allowed"})
    business = build_evidence_from_business_logic_observation({"review_plan_id": "b1", "observed_result": "unexpected_success", "observed_message_summary": "Unexpected"})
    assert "[REDACTED-COOKIE]" in owasp["safe_summary"]
    assert "Cookie" not in str(crawl)
    assert access["linked_test_plan_ids"] == ["p1"]
    assert replay["linked_replay_plan_ids"] == ["r1"]
    assert business["linked_business_logic_plan_ids"] == ["b1"]


def test_json_and_html_reports_include_evidence_vault(tmp_path) -> None:
    item = create_evidence_item(evidence_id="ev1", title="Manual", safe_summary="Safe", related_owasp_categories=["A01:2025"])
    summary = evidence_vault_summary([item])
    scan = {
        "host": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "scan_mode": "safe",
        "duration_seconds": 0,
        "open_ports": [],
        "findings": [],
        "evidence_vault_items": [item],
        "evidence_quality_summary": summary,
        "evidence_redaction_summary": summary,
        "blocked_evidence_export_count": summary["blocked_from_export"],
    }
    start = datetime.now()
    json_path = save_json_report(scan, "VulScan", "test", start, start, tmp_path)
    html_path = save_html_report(scan, "VulScan", "test", start, start, tmp_path)
    assert "evidence_vault_items" in json_path.read_text(encoding="utf-8")
    assert "Evidence Vault Summary" in html_path.read_text(encoding="utf-8")
