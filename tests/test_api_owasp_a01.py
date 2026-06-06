from fastapi.testclient import TestClient

from scanner.api_app import create_app


def test_api_a01_rules_assess_and_manual_plan() -> None:
    client = TestClient(create_app())
    rules = client.get("/owasp/a01/rules")
    assert rules.status_code == 200
    assert rules.json()["owasp_id"] == "A01:2025"

    response = client.post(
        "/owasp/a01/assess",
        json={
            "target": "http://example.test",
            "endpoint_results": [{"url": "http://example.test/api/orders/123/export?order_id=123"}],
            "parameter_results": [{"url": "http://example.test/api/orders/123/export?order_id=123", "parameter_name": "order_id"}],
            "evidence_records": [],
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["a01_access_control_summary"]["enabled"] is True
    assert payload["a01_access_control_evidence"]

    plan = client.post("/owasp/a01/manual-plan", json={"evidence_item": payload["a01_access_control_evidence"][0]})
    assert plan.status_code == 200
    assert plan.json()["manual_validation_plan"]["manual_validation_required"] is True
    assert "evidence_template" in plan.json()
