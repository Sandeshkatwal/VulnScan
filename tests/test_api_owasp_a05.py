from fastapi.testclient import TestClient

from scanner.api_app import create_app


def test_api_a05_rules_and_assess() -> None:
    client = TestClient(create_app())
    rules = client.get("/owasp/a05/rules")
    assert rules.status_code == 200
    assert rules.json()["owasp_id"] == "A05:2025"

    response = client.post(
        "/owasp/a05/assess",
        json={
            "target": "http://example.test",
            "endpoint_results": [{"url": "http://example.test/api/items?filter=open"}],
            "parameter_results": [{"url": "http://example.test/search?q=test", "parameter_name": "q"}],
            "forms": [{"action": "http://example.test/search", "fields": [{"name": "q", "type": "search"}]}],
            "safe_reflection": False,
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["a05_injection_summary"]["enabled"] is True
    assert payload["a05_injection_evidence"]
