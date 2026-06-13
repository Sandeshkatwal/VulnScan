from fastapi.testclient import TestClient

from scanner.api_app import create_app


def _fake_scan_executor(**kwargs):
    return {"scan_id": "scan-regression", "status": "completed", "target": kwargs["target"], "summary": {}}


def test_invalid_payload_returns_structured_error() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))
    response = client.post("/scans", json={"target": "http://127.0.0.1:8000", "unexpected": True})
    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "Invalid request body."
    assert body["safe_error"] is True


def test_missing_resource_returns_404() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))
    response = client.get("/jobs/not-a-real-job")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_unsafe_report_id_is_blocked() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))
    response = client.get("/reports/../download")
    assert response.status_code in {404, 405}


def test_redact_check_does_not_return_raw_secret() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))
    response = client.post("/evidence/redact-check", json={"text": "Authorization: Bearer raw-secret-token-12345"})
    assert response.status_code == 200
    payload = response.json()
    assert "raw-secret-token-12345" not in str(payload)
    assert "[REDACTED-BEARER]" in str(payload)


def test_health_and_version_endpoints_stable() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))
    health = client.get("/health").json()
    version = client.get("/version").json()
    assert health["scanner"] == "VulScan"
    assert health["authorised_use_only"] is True
    assert version["version"] == "22.1.0-beta"
    assert version["release_channel"] == "public-beta"
