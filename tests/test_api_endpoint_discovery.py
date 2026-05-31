from fastapi.testclient import TestClient

from scanner.api_app import create_app


def test_api_endpoint_discovery_analyse() -> None:
    client = TestClient(create_app())
    response = client.post(
        "/bug-bounty/endpoints/analyse",
        json={
            "urls": [
                "http://127.0.0.1:8000/account?id=123",
                "http://127.0.0.1:8000/redirect?next=/dashboard",
            ],
            "base_url": "http://127.0.0.1:8000",
            "scope_file": "data/bug_bounty/sample_program_scope.json",
            "enforce_scope": True,
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["endpoint_discovery"]["enabled"] is True
    assert payload["parameter_results"]
    assert payload["endpoint_skipped"] == []


def test_api_endpoint_discovery_rejects_empty_urls() -> None:
    client = TestClient(create_app())
    response = client.post("/bug-bounty/endpoints/analyse", json={"urls": []})
    assert response.status_code == 400


def test_api_lists_endpoint_reports() -> None:
    client = TestClient(create_app())
    response = client.get("/bug-bounty/endpoints/reports")
    assert response.status_code == 200
    assert "reports" in response.json()
