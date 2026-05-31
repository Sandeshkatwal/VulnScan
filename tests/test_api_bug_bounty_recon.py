from __future__ import annotations

from fastapi.testclient import TestClient

from scanner.api_app import create_app


UNIT_API_KEY = "unit-test-api-key"


def test_api_recon_returns_direct_result(monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)

    def fake_recon(**kwargs):
        return {
            "bug_bounty_recon": {"enabled": True, "input_targets_count": len(kwargs["raw_targets"]), "live_count": 1},
            "bug_bounty_recon_results": [{"probe_url": "http://127.0.0.1", "live": True}],
            "bug_bounty_recon_skipped": [],
            "findings": [],
        }

    monkeypatch.setattr("scanner.api_app.run_bug_bounty_recon", fake_recon)
    client = TestClient(create_app())

    response = client.post(
        "/bug-bounty/recon",
        json={
            "targets": ["127.0.0.1"],
            "scope_file": "data/bug_bounty/sample_program_scope.json",
            "enforce_scope": True,
            "request_delay": 0,
            "max_requests_per_minute": 30,
            "timeout": 5,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["bug_bounty_recon"]["input_targets_count"] == 1
    assert payload["bug_bounty_recon_results"][0]["live"] is True


def test_api_recon_rejects_empty_targets(monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    client = TestClient(create_app())

    response = client.post("/bug-bounty/recon", json={"targets": []})

    assert response.status_code == 400
    assert "target" in response.json()["detail"].lower()


def test_api_recon_rejects_scope_files_outside_bug_bounty_directory(monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    client = TestClient(create_app())

    response = client.post(
        "/bug-bounty/recon",
        json={
            "targets": ["127.0.0.1"],
            "scope_file": "../README.md",
            "enforce_scope": True,
        },
    )

    assert response.status_code == 400
    assert "data/bug_bounty" in response.json()["detail"]


def test_api_key_protection_applies_to_recon_endpoints(monkeypatch) -> None:
    monkeypatch.setenv("VULSCAN_API_KEY", UNIT_API_KEY)
    client = TestClient(create_app())

    missing_key = client.post("/bug-bounty/recon", json={"targets": ["127.0.0.1"]})
    with_key = client.get("/bug-bounty/recon/results", headers={"X-VulScan-API-Key": UNIT_API_KEY})

    assert missing_key.status_code == 401
    assert with_key.status_code == 200
