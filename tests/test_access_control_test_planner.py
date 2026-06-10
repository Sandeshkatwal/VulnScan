from datetime import datetime

from scanner.a01_manual_tests import build_a01_observation
from scanner.access_control_test_planner import (
    build_a01_manual_validation_summary,
    build_a01_test_plan_from_candidate,
    build_report_ready_a01_template,
    build_test_plan_from_endpoint,
    build_test_plans_from_role_mapping,
)
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report


def test_create_plan_from_idor_candidate():
    plan = build_a01_test_plan_from_candidate({"evidence_id": "e1", "title": "Object identifier candidate", "rule_group": "object_level_authorization_candidates", "affected_url": "http://127.0.0.1:8000/account?id=1"})
    assert plan["test_type"] == "object_ownership_review"
    assert "objects they own" in plan["expected_secure_behaviour"]


def test_create_plan_from_tenant_boundary_candidate():
    plan = build_a01_test_plan_from_candidate({"evidence_id": "e2", "title": "Tenant boundary candidate", "rule_group": "tenant_boundary_candidates", "affected_url": "http://127.0.0.1:8000/tenant-b/reports"}, {"role_id": "tenant_a_user", "role_label": "Tenant A User", "tenant_label": "tenant-a"})
    assert plan["test_type"] == "tenant_boundary_review"
    assert "tenant/workspace" in plan["expected_secure_behaviour"]


def test_create_plan_from_admin_endpoint():
    plan = build_test_plan_from_endpoint({"url": "http://127.0.0.1:8000/admin/users", "method": "GET"}, None, "denied", {"role_id": "standard_user", "role_label": "Standard User"})
    assert plan["test_type"] == "vertical_access_control_review"
    assert plan["expected_permission"] == "denied"


def test_create_plan_from_export_download_endpoint():
    export_plan = build_test_plan_from_endpoint({"url": "http://127.0.0.1:8000/reports/export", "method": "GET"}, None, "denied", {})
    download_plan = build_test_plan_from_endpoint({"url": "http://127.0.0.1:8000/files/download", "method": "GET"}, None, "denied", {})
    assert export_plan["test_type"] == "sensitive_export_review"
    assert download_plan["test_type"] == "file_download_authorization_review"


def test_create_plan_from_role_permission_rule():
    plan = build_a01_test_plan_from_candidate({"evidence_id": "e3", "title": "Role permission parameter", "rule_group": "role_and_permission_indicators", "affected_url": "http://127.0.0.1:8000/account?role=admin"})
    assert plan["test_type"] == "role_permission_review"


def test_manual_steps_libraries_are_generated():
    object_plan = build_a01_test_plan_from_candidate({"title": "object id", "rule_group": "object_level_authorization_candidates"})
    tenant_plan = build_a01_test_plan_from_candidate({"title": "tenant id", "rule_group": "tenant_boundary_candidates"})
    admin_plan = build_test_plan_from_endpoint({"url": "http://127.0.0.1:8000/admin/users"}, None, "denied", {})
    assert any("approved test-owned objects" in step for step in object_plan["manual_steps"])
    assert any("approved test tenants" in step for step in tenant_plan["manual_steps"])
    assert any("lower-privileged authorised test role" in step for step in admin_plan["manual_steps"])


def test_observation_records_denied_as_expected_and_unexpectedly_allowed():
    denied = build_a01_observation(test_plan_id="p1", observed_access_result="denied_as_expected", observed_status_code=403, observed_message_summary="Access denied")
    allowed = build_a01_observation(test_plan_id="p2", observed_access_result="unexpectedly_allowed", observed_status_code=200, observed_message_summary="Admin page visible")
    assert denied["observed_access_result"] == "denied_as_expected"
    assert allowed["observed_access_result"] == "unexpectedly_allowed"


def test_observation_redacts_secret_like_fields():
    observation = build_a01_observation(test_plan_id="p1", observed_access_result="denied_as_expected", observed_message_summary="No secret values included")
    assert "token" not in observation
    assert observation["redaction_status"] == "redacted"


def test_report_template_candidate_vs_issue_wording():
    plan = build_test_plan_from_endpoint({"url": "http://127.0.0.1:8000/admin/users"}, None, "denied", {"role_label": "Standard User"})
    candidate = build_report_ready_a01_template(plan)
    issue_obs = build_a01_observation(test_plan_id=plan["test_plan_id"], observed_access_result="unexpectedly_allowed", observed_status_code=200, observed_message_summary="Admin page visible")
    issue = build_report_ready_a01_template(plan, issue_obs)
    assert "A01 Manual Validation Plan" in candidate["Title"]
    assert "Manually Verified A01 Issue" in issue["Title"]


def test_role_mapping_generates_plans_without_duplicates():
    role_mapping = {
        "role_profiles": [{"role_id": "standard_user", "role_label": "Standard User"}],
        "role_endpoint_matrix": [
            {"role_id": "standard_user", "role_label": "Standard User", "endpoint": "http://127.0.0.1:8000/admin/users", "inferred_action": "manage_users", "expected_permission": "denied"},
            {"role_id": "standard_user", "role_label": "Standard User", "endpoint": "http://127.0.0.1:8000/admin/users", "inferred_action": "manage_users", "expected_permission": "denied"},
        ],
    }
    plans = build_test_plans_from_role_mapping(role_mapping)
    assert len(plans) == 1


def test_json_and_html_reports_include_planner_section(tmp_path):
    plan = build_test_plan_from_endpoint({"url": "http://127.0.0.1:8000/admin/users"}, None, "denied", {"role_label": "Standard User"})
    summary = build_a01_manual_validation_summary([plan], [], [])
    scan_result = {
        "host": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "scan_mode": "safe",
        "duration_seconds": 0,
        "open_ports": [],
        "findings": [],
        "access_control_test_plans": [plan],
        "a01_manual_validation_summary": summary,
    }
    now = datetime(2026, 6, 10)
    json_path = save_json_report(scan_result, "VulScan", "21.3", now, now, reports_dir=tmp_path)
    html_path = save_html_report(scan_result, "VulScan", "21.3", now, now, reports_dir=tmp_path)
    assert "access_control_test_plans" in json_path.read_text(encoding="utf-8")
    assert "Access Control Manual Test Planner" in html_path.read_text(encoding="utf-8")
