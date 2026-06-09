from fastapi.testclient import TestClient

from scanner.api_app import create_app


def test_role_mapping_api_does_not_perform_live_requests(monkeypatch):
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    def fail_fetch(*args, **kwargs):
        raise AssertionError("live request should not be performed")

    monkeypatch.setattr("requests.Session.request", fail_fetch, raising=False)
    app = create_app()
    client = TestClient(app)
    response = client.post(
        "/roles/manual-plan",
        json={
            "role": {"role_id": "standard_user", "role_name": "standard_user", "role_label": "Standard User", "user_type": "standard_user"},
            "endpoint": {"url": "http://127.0.0.1:8000/admin/users", "method": "GET"},
            "expected_permission": "denied",
        },
    )
    assert response.status_code == 200
    assert response.json()["manual_validation_plan"]["expected_permission"] == "denied"


def test_role_mapping_api_rejects_credential_fields(monkeypatch):
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    app = create_app()
    client = TestClient(app)
    response = client.post(
        "/roles/validate",
        json={
            "roles": [{"role_id": "bad", "role_name": "bad", "role_label": "Bad", "user_type": "custom", "password": "secret"}],
            "permission_matrix": {"matrix_id": "x", "matrix_name": "x", "target": "local"},
        },
    )
    assert response.status_code == 400
