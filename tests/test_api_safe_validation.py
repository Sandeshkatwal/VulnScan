from fastapi.testclient import TestClient

from scanner.api_app import create_app


def test_api_safe_validation_returns_result() -> None:
    client = TestClient(create_app())
    response = client.post(
        "/bug-bounty/validate",
        json={
            "targets": [
                {
                    "url": "http://127.0.0.1:8000/search?q=test",
                    "candidate_type": "reflected_input",
                    "parameter": "q",
                }
            ],
            "checks": ["reflected_input_observation"],
            "request_delay": 0,
            "timeout": 1,
            "max_validation_requests": 1,
            "safe_active_confirm": True,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["safe_active_validation"]["enabled"] is True
    assert "safe_active_validation_results" in body


def test_api_safe_validation_rejects_empty_targets() -> None:
    client = TestClient(create_app())
    response = client.post("/bug-bounty/validate", json={"targets": []})
    assert response.status_code == 400
