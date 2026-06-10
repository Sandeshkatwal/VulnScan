from datetime import datetime, timezone

from scanner.owasp_a01_access_control import attach_a01_access_control
from scanner.owasp_a05_injection import attach_a05_injection
from scanner.owasp_a07_authentication import attach_a07_authentication
from scanner.parameter_replay_planner import build_replay_plan_from_parameter, build_replay_plans_from_candidates, classify_replay_intent, package_from_plans, replay_plan_fingerprint
from scanner.parameter_review_workflow import build_parameter_replay_observation
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report


def test_replay_plan_from_object_tenant_role_search_redirect_and_csrf_parameters() -> None:
    cases = {
        "user_id": "object_ownership_review",
        "tenant_id": "tenant_boundary_review",
        "role": "role_permission_review",
        "q": "input_validation_review",
        "redirect_uri": "redirect_callback_review",
        "csrf": "auth_session_review",
    }
    for name, intent in cases.items():
        plan = build_replay_plan_from_parameter({"parameter_name": name}, {"url": f"http://127.0.0.1:8000/path?{name}=1"})
        assert plan["replay_intent"] == intent
        assert plan["validation_status"] == "planned"
        assert "No Automatic Replay." in plan["safety_notes"]


def test_classify_export_download_and_duplicate_fingerprint() -> None:
    assert classify_replay_intent("export_id", "export") == "export_download_review"
    plan_a = build_replay_plan_from_parameter({"parameter_name": "user_id"}, {"url": "http://127.0.0.1/users/123?user_id=123"}, {"role_label": "standard_user"})
    plan_b = build_replay_plan_from_parameter({"parameter_name": "user_id"}, {"url": "http://127.0.0.1/users/456?user_id=456"}, {"role_label": "standard_user"})
    assert replay_plan_fingerprint(plan_a) == replay_plan_fingerprint(plan_b)


def test_build_replay_plans_from_candidates_deduplicates() -> None:
    plans = build_replay_plans_from_candidates(
        [{"url": "http://127.0.0.1/users/123?user_id=123", "parameter_name": "user_id"}, {"url": "http://127.0.0.1/users/456?user_id=456", "parameter_name": "user_id"}],
        [{"url": "http://127.0.0.1/users/123?user_id=123"}],
        roles=[{"role_label": "standard_user"}],
    )
    assert len(plans) == 1


def test_owasp_replay_summary_integrations() -> None:
    a01_plan = build_replay_plan_from_parameter({"parameter_name": "user_id"}, {"url": "http://127.0.0.1/users/123?user_id=123"})
    a05_plan = build_replay_plan_from_parameter({"parameter_name": "q"}, {"url": "http://127.0.0.1/search?q=demo"})
    a07_plan = build_replay_plan_from_parameter({"parameter_name": "csrf"}, {"url": "http://127.0.0.1/form?csrf=abc"})
    observation = build_parameter_replay_observation(replay_plan_id=a01_plan["replay_plan_id"], observed_access_result="unexpectedly_allowed")
    scan = {
        "host": "127.0.0.1",
        "parameter_replay_plans": [a01_plan, a05_plan, a07_plan],
        "parameter_replay_observations": [observation],
        "endpoint_results": [],
        "parameter_results": [],
        "findings": [],
    }
    attach_a01_access_control(scan)
    attach_a05_injection(scan)
    attach_a07_authentication(scan)
    assert scan["a01_access_control_summary"]["replay_verified_issue_count"] == 1
    assert scan["a05_injection_summary"]["reflection_review_plans_count"] == 1
    assert scan["a07_authentication_summary"]["auth_parameter_review_plans_count"] == 1
    assert scan["a07_authentication_summary"]["session_replay_review_count"] == 1


def test_json_and_html_report_include_replay_planner(tmp_path) -> None:
    plan = build_replay_plan_from_parameter({"parameter_name": "user_id"}, {"url": "http://127.0.0.1/users/123?user_id=123"})
    package = package_from_plans([plan])
    scan = {
        "host": "127.0.0.1",
        "resolved_ip": "",
        "scan_mode": "test",
        "duration_seconds": 0,
        "open_ports": [],
        "findings": [],
        **package,
    }
    start = datetime.now(timezone.utc)
    json_path = save_json_report(scan, "VulScan", "21.4-test", start, start, reports_dir=tmp_path)
    html_path = save_html_report(scan, "VulScan", "21.4-test", start, start, reports_dir=tmp_path)
    assert "parameter_replay_plans" in json_path.read_text(encoding="utf-8")
    assert "Safe Authenticated Parameter Replay Planner" in html_path.read_text(encoding="utf-8")
