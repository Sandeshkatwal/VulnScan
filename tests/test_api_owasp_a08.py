from fastapi.testclient import TestClient

from scanner.api_app import create_app


def test_a08_rules_assess_and_manual_plan_api() -> None:
    client = TestClient(create_app())
    rules = client.get("/owasp/a08/rules")
    assert rules.status_code == 200
    assert rules.json()["owasp_id"] == "A08:2025"

    response = client.post(
        "/owasp/a08/assess",
        json={
            "target": "http://127.0.0.1:8000",
            "endpoint_results": [{"url": "http://127.0.0.1:8000/api/import?file"}, {"url": "http://127.0.0.1:8000/webhook?signature"}],
            "parameter_results": [{"url": "http://127.0.0.1:8000/webhook?signature=secret-token", "parameter_name": "signature"}],
            "forms": [{"action": "/upload", "enctype": "multipart/form-data", "fields": [{"name": "file", "type": "file"}]}],
            "scripts": [{"src": "https://cdn.example.test/app.js"}],
            "stylesheets": [],
            "html_snippet": "",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["a08_integrity_summary"]["total_evidence_items"] >= 4
    assert body["a08_integrity_summary"]["manual_validation_required_count"] >= 4
    assert not any("secret-token" in str(item) for item in body["a08_integrity_evidence"])

    manual = client.post(
        "/owasp/a08/manual-plan",
        json={"evidence_item": {"workflow_type": "webhook_callback", "manual_test_plan_id": "webhook_signature_review"}},
    )
    assert manual.status_code == 200
    assert "Verify signatures/HMAC are required." in manual.json()["manual_validation_plan"]["safe_manual_steps"]
