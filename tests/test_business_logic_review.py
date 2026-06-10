from datetime import datetime, timezone

from scanner.business_logic_review import build_business_logic_review_plan, build_report_ready_business_logic_template, build_review_plans_from_candidates, business_logic_plan_fingerprint, package_business_logic
from scanner.business_logic_retest import build_business_logic_observation
from scanner.owasp_a01_access_control import attach_a01_access_control
from scanner.owasp_a07_authentication import attach_a07_authentication
from scanner.owasp_a08_integrity import attach_a08_integrity
from scanner.owasp_assessment import build_owasp_assessment
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report
from scanner.workflow_candidates import assess_business_logic_workflow_candidates


def test_generate_checkout_and_approval_review_plans() -> None:
    candidates = assess_business_logic_workflow_candidates(
        [{"url": "http://127.0.0.1:8000/checkout", "method": "POST"}, {"url": "http://127.0.0.1:8000/approve", "method": "POST"}],
        [],
    )
    plans = build_review_plans_from_candidates(candidates, roles=[{"role_label": "standard_user"}])
    assert {plan["workflow_type"] for plan in plans} >= {"checkout_payment", "approval_rejection"}
    assert all(plan["validation_status"] == "planned" for plan in plans)


def test_report_template_candidate_and_issue_wording() -> None:
    plan = build_business_logic_review_plan({"workflow_candidate_id": "c1", "workflow_type": "checkout_payment", "affected_url": "http://127.0.0.1:8000/checkout"})
    candidate = build_report_ready_business_logic_template(plan)
    issue = build_report_ready_business_logic_template(plan, {"observed_result": "unexpected_success", "observed_message_summary": "Unexpected success with approved test labels."})
    assert candidate["Title"].startswith("Business Logic Review Plan:")
    assert issue["Title"].startswith("Manually Verified Business Logic Issue:")


def test_duplicate_fingerprint_prevents_duplicate_plans() -> None:
    candidate_a = {"workflow_candidate_id": "c1", "workflow_type": "checkout_payment", "affected_url": "http://127.0.0.1:8000/orders/123/checkout", "related_parameters": ["order_id"], "related_owasp_categories": ["A06"]}
    candidate_b = {"workflow_candidate_id": "c2", "workflow_type": "checkout_payment", "affected_url": "http://127.0.0.1:8000/orders/456/checkout", "related_parameters": ["order_id"], "related_owasp_categories": ["A06"]}
    plan_a = build_business_logic_review_plan(candidate_a)
    plan_b = build_business_logic_review_plan(candidate_b)
    assert business_logic_plan_fingerprint(plan_a) == business_logic_plan_fingerprint(plan_b)
    assert len(build_review_plans_from_candidates([candidate_a, candidate_b])) == 1


def test_owasp_integrations_and_a06_manual_coverage() -> None:
    plan = build_business_logic_review_plan({"workflow_candidate_id": "c1", "workflow_type": "password_reset", "affected_url": "http://127.0.0.1:8000/reset-password", "related_owasp_categories": ["A01", "A06", "A07", "A08"]})
    observation = build_business_logic_observation(review_plan_id=plan["review_plan_id"], observed_result="unexpected_success")
    scan = {"host": "127.0.0.1", "business_logic_review_plans": [plan], "business_logic_observations": [observation], "endpoint_results": [], "parameter_results": [], "findings": []}
    attach_a01_access_control(scan)
    attach_a07_authentication(scan)
    attach_a08_integrity(scan)
    assessment = build_owasp_assessment(scan)
    a06 = next(item for item in assessment["owasp_category_results"] if item["owasp_id"] == "A06:2025")
    assert scan["a01_access_control_summary"]["business_logic_review_plans_count"] == 1
    assert scan["a07_authentication_summary"]["business_logic_review_plans_count"] == 1
    assert scan["a08_integrity_summary"]["business_logic_review_plans_count"] == 1
    assert a06["coverage_status"] == "partially_assessed"


def test_json_and_html_report_include_business_logic(tmp_path) -> None:
    plan = build_business_logic_review_plan({"workflow_candidate_id": "c1", "workflow_type": "checkout_payment", "affected_url": "http://127.0.0.1:8000/checkout"})
    package = package_business_logic([], [plan], [], [])
    scan = {"host": "127.0.0.1", "resolved_ip": "", "scan_mode": "test", "duration_seconds": 0, "open_ports": [], "findings": [], **package}
    start = datetime.now(timezone.utc)
    json_path = save_json_report(scan, "VulScan", "21.5-test", start, start, reports_dir=tmp_path)
    html_path = save_html_report(scan, "VulScan", "21.5-test", start, start, reports_dir=tmp_path)
    assert "business_logic_review_plans" in json_path.read_text(encoding="utf-8")
    assert "Business Logic Review Workflow Assistant" in html_path.read_text(encoding="utf-8")
