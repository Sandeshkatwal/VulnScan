from fastapi.testclient import TestClient

from scanner.api_app import create_app


def test_access_control_planner_api_does_not_perform_live_requests(monkeypatch):
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)

    def fail_fetch(*args, **kwargs):
        raise AssertionError("live request should not be performed")

    monkeypatch.setattr("requests.Session.request", fail_fetch, raising=False)
    client = TestClient(create_app())
    response = client.post(
        "/access-tests/create",
        json={
            "role": {"role_id": "standard_user", "role_name": "standard_user", "role_label": "Standard User", "user_type": "standard_user"},
            "endpoint": {"url": "http://127.0.0.1:8000/admin/users", "method": "GET"},
            "expected_permission": "denied",
            "test_type": "vertical_access_control_review",
        },
    )
    assert response.status_code == 200
    assert response.json()["access_control_test_plan"]["expected_permission"] == "denied"


def test_access_control_planner_api_rejects_credential_fields(monkeypatch):
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    client = TestClient(create_app())
    response = client.post(
        "/access-tests/create",
        json={
            "role": {"role_id": "bad", "role_name": "bad", "role_label": "Bad", "user_type": "custom", "password": "secret"},
            "endpoint": {"url": "http://127.0.0.1:8000/admin/users", "method": "GET"},
            "expected_permission": "denied",
            "test_type": "vertical_access_control_review",
        },
    )
    assert response.status_code == 400


def test_access_control_planner_report_template_api(monkeypatch):
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    client = TestClient(create_app())
    plan = {
        "test_plan_id": "p1",
        "title": "Standard User Admin Function Review",
        "affected_url": "http://127.0.0.1:8000/admin/users",
        "role_label": "Standard User",
        "expected_secure_behaviour": "Only roles with explicit authorization can access this function.",
        "manual_steps": ["Use Authorised Test Accounts Only."],
    }
    response = client.post("/access-tests/report-template", json={"plan": plan})
    assert response.status_code == 200
    assert "A01 Manual Validation Plan" in response.json()["a01_report_template"]["Title"]
