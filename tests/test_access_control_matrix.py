from scanner.access_control_matrix import build_access_control_matrix_package, build_role_manual_validation_plan, infer_action_from_endpoint
from scanner.authenticated_crawler import authenticated_crawl
from scanner.owasp_a01_access_control import attach_a01_access_control
from scanner.permission_matrix import load_permission_matrix
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report
from scanner.role_profiles import load_role_profiles

from datetime import datetime


def test_infer_view_action_from_get_profile_endpoint():
    inferred = infer_action_from_endpoint({"url": "http://127.0.0.1:8000/profile", "method": "GET"})
    assert inferred["inferred_action"] == "view"


def test_infer_manage_users_from_admin_users():
    inferred = infer_action_from_endpoint({"url": "http://127.0.0.1:8000/admin/users", "method": "GET"})
    assert inferred["inferred_action"] == "manage_users"


def test_infer_export_action():
    inferred = infer_action_from_endpoint({"url": "http://127.0.0.1:8000/reports/export", "method": "GET"})
    assert inferred["inferred_action"] == "export"


def test_infer_upload_action():
    inferred = infer_action_from_endpoint({"url": "http://127.0.0.1:8000/upload", "method": "POST"})
    assert inferred["inferred_action"] == "upload"
    assert inferred["state_changing"] is True


def test_build_role_endpoint_matrix_and_denied_admin_plan():
    roles = load_role_profiles("data/roles/sample_roles.json")
    matrix = load_permission_matrix("data/roles/sample_permission_matrix.json")
    package = build_access_control_matrix_package(roles, matrix, [{"url": "http://127.0.0.1:8000/admin/users", "method": "GET"}])
    rows = package["role_endpoint_matrix"]
    standard = [row for row in rows if row["role_id"] == "standard_user"][0]
    assert standard["expected_permission"] == "denied"
    assert standard["manual_validation_required"] is True


def test_generate_tenant_boundary_manual_plan():
    role = [item for item in load_role_profiles("data/roles/sample_roles.json") if item["role_id"] == "tenant_a_user"][0]
    plan = build_role_manual_validation_plan(role, {"url": "http://127.0.0.1:8000/tenant-b/reports", "method": "GET"}, "denied")
    assert plan["tenant_label"] == "tenant-a"
    assert "tenant boundary" in plan["risk_if_failed"].lower()


def test_a01_enrichment_adds_role_label_and_expected_permission():
    scan_result = {
        "target": "http://127.0.0.1:8000",
        "endpoint_results": [{"url": "http://127.0.0.1:8000/admin/users", "endpoint_category": "admin"}],
        "role_endpoint_matrix": [{
            "endpoint": "http://127.0.0.1:8000/admin/users",
            "role_label": "Standard User",
            "expected_permission": "denied",
            "inferred_action": "manage_users",
            "validation_status": "not_tested",
            "manual_plan_id": "manual_plan_demo",
        }],
        "findings": [],
    }
    result = attach_a01_access_control(scan_result)
    assert any(item.get("role_label") == "Standard User" and item.get("expected_permission") == "denied" for item in result["a01_access_control_evidence"])


def test_authenticated_crawl_dry_run_uses_role_label_only():
    profile = {
        "profile_id": "p1",
        "profile_name": "Demo",
        "target_base_url": "http://127.0.0.1:8000",
        "auth_type": "manual",
        "role_label": "standard_user",
        "allowed_hosts": ["127.0.0.1"],
        "allowed_paths": ["/"],
        "blocked_paths": ["/logout"],
    }
    result = authenticated_crawl("http://127.0.0.1:8000/dashboard", profile, {"dry_run": True, "max_pages": 1})
    assert result["role_endpoint_map"]["role_label"] == "standard_user"
    assert "cookies" not in str(result["role_endpoint_map"]).lower()


def test_json_and_html_reports_do_not_include_credentials(tmp_path):
    scan_result = _minimal_scan_result()
    scan_result["role_profiles"] = [{"role_id": "standard_user", "role_name": "standard_user", "role_label": "Standard User", "user_type": "standard_user"}]
    scan_result["role_mapping_summary"] = {"enabled": True, "role_count": 1, "endpoint_count": 0, "role_endpoint_rows": 0, "manual_validation_plan_count": 0}
    start = datetime(2026, 6, 10, 0, 0, 0)
    json_path = save_json_report(scan_result, "VulScan", "21.2", start, start, reports_dir=tmp_path)
    html_path = save_html_report(scan_result, "VulScan", "21.2", start, start, reports_dir=tmp_path)
    combined = json_path.read_text(encoding="utf-8") + html_path.read_text(encoding="utf-8")
    assert "supersecret" not in combined.lower()
    assert "session_token" not in combined.lower()


def _minimal_scan_result():
    return {
        "host": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "scan_mode": "safe",
        "duration_seconds": 0,
        "open_ports": [],
        "findings": [],
    }
