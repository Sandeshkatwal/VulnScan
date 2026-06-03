from __future__ import annotations

from fastapi.testclient import TestClient

from scanner.api_app import create_app


def test_api_a04_rules_and_assess() -> None:
    client = TestClient(create_app())
    rules = client.get("/owasp/a04/rules")
    assert rules.status_code == 200
    assert rules.json()["owasp_id"] == "A04:2025"

    response = client.post(
        "/owasp/a04/assess",
        json={
            "target": "https://example.test/",
            "headers": {},
            "set_cookie_headers": ["SESSIONID=NeverReturnValue; Path=/"],
            "urls": ["http://example.test/login?token=NeverReturnToken"],
            "forms": [],
            "html_snippet": "",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["a04_crypto_summary"]["enabled"] is True
    assert payload["a04_crypto_evidence"]
    assert "NeverReturnValue" not in str(payload)
    assert "NeverReturnToken" not in str(payload)
