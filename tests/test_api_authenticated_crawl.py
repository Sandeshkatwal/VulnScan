from fastapi.testclient import TestClient

from scanner.api_app import create_app
from scanner.session_profiles import load_session_profile


def test_authenticated_crawl_api_requires_api_key(monkeypatch) -> None:
    monkeypatch.setenv("VULSCAN_API_KEY", "test-key")
    client = TestClient(create_app())

    response = client.post("/authenticated/crawl", json={"url": "http://127.0.0.1:8000/dashboard", "profile": {}})

    assert response.status_code == 401


def test_authenticated_crawl_api_dry_run_redacts_profile(monkeypatch) -> None:
    monkeypatch.setenv("VULSCAN_API_KEY", "test-key")
    client = TestClient(create_app())
    profile = load_session_profile("data/auth_profiles/sample_session_profile.redacted.json")

    response = client.post(
        "/authenticated/crawl",
        headers={"Authorization": "Bearer test-key"},
        json={"url": "http://127.0.0.1:8000/dashboard", "profile": profile, "dry_run": True, "max_pages": 1},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["authenticated_crawl_summary"]["pages_crawled"] == 1
    assert "Bearer [REDACTED]" not in response.text
    assert "sessionid" in response.text
