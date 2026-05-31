from __future__ import annotations

from fastapi.testclient import TestClient

from scanner.api_app import create_app


UNIT_API_KEY = "unit-test-api-key"


def test_api_scope_check_returns_correct_decision(monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    client = TestClient(create_app())

    response = client.post(
        "/bug-bounty/scope-check",
        json={
            "target": "https://demo-web.local/",
            "scope_file": "data/bug_bounty/sample_program_scope.json",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["in_scope"] is True
    assert payload["program_name"] == "Demo Program Scope"


def test_api_does_not_allow_arbitrary_scope_file_paths(monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    client = TestClient(create_app())

    response = client.post(
        "/bug-bounty/scope-check",
        json={
            "target": "https://demo-web.local/",
            "scope_file": "../README.md",
        },
    )

    assert response.status_code == 400
    assert "data/bug_bounty" in response.json()["detail"]


def test_api_key_protection_applies_to_bug_bounty_endpoints(monkeypatch) -> None:
    monkeypatch.setenv("VULSCAN_API_KEY", UNIT_API_KEY)
    client = TestClient(create_app())

    missing_key = client.get("/bug-bounty/scopes")
    with_key = client.get("/bug-bounty/scopes", headers={"X-VulScan-API-Key": UNIT_API_KEY})

    assert missing_key.status_code == 401
    assert with_key.status_code == 200


def test_api_scope_detail_by_program_id(monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    client = TestClient(create_app())

    response = client.get("/bug-bounty/scopes/demo-bug-bounty-program")

    assert response.status_code == 200
    payload = response.json()
    assert payload["metadata"]["program_id"] == "demo-bug-bounty-program"
    assert "forbidden_actions" in payload["scope"]
