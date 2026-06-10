from fastapi.testclient import TestClient

from scanner.api_app import create_app


def test_api_business_logic_detect_create_observe_no_live_requests() -> None:
    client = TestClient(create_app())
    detect = client.post("/business-logic/detect", json={"endpoint_results": [{"url": "http://127.0.0.1:8000/checkout", "method": "POST"}]})
    assert detect.status_code == 200
    assert detect.json()["business_logic_workflow_candidates"][0]["workflow_type"] == "checkout_payment"

    created = client.post("/business-logic/create", json={"workflow": "checkout_payment", "endpoint": "http://127.0.0.1:8000/checkout", "role": "standard_user"})
    assert created.status_code == 200
    plan_id = created.json()["business_logic_review_plan"]["review_plan_id"]

    observed = client.post("/business-logic/observe", json={"review_plan_id": plan_id, "observed_result": "behaved_as_expected", "observed_message_summary": "Workflow behaved as expected using approved test data"})
    assert observed.status_code == 200
    assert observed.json()["business_logic_observation"]["observed_result"] == "behaved_as_expected"


def test_api_business_logic_rejects_credential_fields() -> None:
    client = TestClient(create_app())
    response = client.post("/business-logic/create", json={"workflow": "checkout_payment", "endpoint": "http://127.0.0.1:8000/checkout", "role": {"role_label": "standard_user", "password": "not-allowed"}})
    assert response.status_code == 400
