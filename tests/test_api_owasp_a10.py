from __future__ import annotations

from fastapi.testclient import TestClient

from scanner.api_app import create_app


def test_api_a10_rules_and_assess() -> None:
    client = TestClient(create_app())
    rules = client.get("/owasp/a10/rules")
    assert rules.status_code == 200
    assert rules.json()["owasp_id"] == "A10:2025"

    response = client.post(
        "/owasp/a10/assess",
        json={
            "target": "http://127.0.0.1:8000",
            "responses": [
                {
                    "url": "http://127.0.0.1:8000/error",
                    "status_code": 500,
                    "body_snippet": "Traceback token=NeverReturnToken SQL syntax error",
                    "headers": {},
                }
            ],
            "endpoint_results": [],
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["a10_error_handling_summary"]["enabled"] is True
    assert payload["a10_error_handling_evidence"]
    assert "NeverReturnToken" not in str(payload)
