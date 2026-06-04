from __future__ import annotations

from fastapi.testclient import TestClient

from scanner.api_app import create_app


def test_api_a07_rules_and_assess() -> None:
    client = TestClient(create_app())
    rules = client.get("/owasp/a07/rules")
    assert rules.status_code == 200
    assert rules.json()["owasp_id"] == "A07:2025"

    response = client.post(
        "/owasp/a07/assess",
        json={
            "target": "https://example.test/login",
            "urls": ["https://example.test/reset-password?token=NeverReturnToken"],
            "headers": {},
            "set_cookie_headers": ["SESSIONID=NeverReturnCookie; Path=/"],
            "forms": [{"page_url": "https://example.test/login", "has_password_field": True, "input_fields": [{"name": "password", "type": "password"}]}],
            "endpoint_results": [],
            "parameter_results": [],
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["a07_authentication_summary"]["enabled"] is True
    assert payload["a07_authentication_evidence"]
    assert "NeverReturnCookie" not in str(payload)
    assert "NeverReturnToken" not in str(payload)
