from fastapi.testclient import TestClient

from scanner.api_app import create_app


def test_api_replay_plan_create_and_observe_no_live_requests() -> None:
    client = TestClient(create_app())
    response = client.post(
        "/replay-plans/create",
        json={
            "endpoint": "http://127.0.0.1:8000/users/123?user_id=123",
            "parameter": "user_id",
            "intent": "object_ownership_review",
            "role": "standard_user",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["parameter_replay_plan"]["parameter_name"] == "user_id"
    assert payload["redacted_request_template"]["method"] == "GET"
    assert "No Automatic Replay." in payload["parameter_replay_plan"]["safety_notes"]

    observe = client.post(
        "/replay-plans/observe",
        json={"replay_plan_id": payload["parameter_replay_plan"]["replay_plan_id"], "observed_access_result": "denied_as_expected", "observed_status_code": 403, "observed_message_summary": "Access denied for standard_user as expected"},
    )
    assert observe.status_code == 200
    assert observe.json()["parameter_replay_observation"]["observed_access_result"] == "denied_as_expected"


def test_api_rejects_credential_fields() -> None:
    client = TestClient(create_app())
    response = client.post(
        "/replay-plans/create",
        json={
            "endpoint": "http://127.0.0.1:8000/users/123?user_id=123",
            "parameter": "user_id",
            "role": {"role_label": "standard_user", "password": "not-allowed"},
        },
    )
    assert response.status_code == 400
