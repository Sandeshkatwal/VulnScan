from fastapi.testclient import TestClient

from scanner.api_app import create_app
from scanner.session_profiles import load_session_profile


UNIT_API_KEY = "unit-test-api-key"


def test_auth_api_returns_redacted_profile_and_boundary(monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    client = TestClient(create_app())
    profile = load_session_profile("data/auth_profiles/sample_session_profile.redacted.json")

    validate = client.post("/auth/profile/validate", json={"profile": profile})
    boundary = client.post("/auth/boundary/check", json={"profile": profile, "url": "http://127.0.0.1:8000/dashboard"})
    classified = client.post("/auth/endpoints/classify", json={"profile": profile, "endpoint_results": [{"url": "http://127.0.0.1:8000/private", "status_code": 403}]})

    assert validate.status_code == 200
    assert boundary.json()["allowed_by_profile"] is True
    assert classified.json()["classified_endpoints"][0]["auth_required_classification"] == "auth_required_likely"
    assert "Bearer abc" not in validate.text
    assert "session-value" not in validate.text


def test_auth_api_key_protection_applies(monkeypatch) -> None:
    monkeypatch.setenv("VULSCAN_API_KEY", UNIT_API_KEY)
    client = TestClient(create_app())

    missing = client.get("/auth/profiles")
    accepted = client.get("/auth/profiles", headers={"X-VulScan-API-Key": UNIT_API_KEY})

    assert missing.status_code == 401
    assert accepted.status_code == 200
