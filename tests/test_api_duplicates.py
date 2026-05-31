from fastapi.testclient import TestClient

from scanner.api_app import create_app
from scanner.api_security import API_KEY_ENV_VAR

UNIT_API_KEY = "unit-duplicates-key"


def _client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setenv(API_KEY_ENV_VAR, UNIT_API_KEY)
    return TestClient(create_app(remediation_db_path=tmp_path / "api_duplicates.db"))


def test_api_duplicate_fingerprint_and_check(monkeypatch, tmp_path) -> None:
    client = _client(tmp_path, monkeypatch)
    headers = {"X-VulScan-API-Key": UNIT_API_KEY}
    payload = {
        "url": "http://127.0.0.1:8000/account?id=123",
        "issue_type": "idor_candidate",
        "parameter_names": ["id"],
        "source": "endpoint_discovery",
    }

    fingerprint = client.post("/duplicates/fingerprint", json=payload, headers=headers)
    assert fingerprint.status_code == 200
    assert fingerprint.json()["fingerprint"]["parameter_names"] == ["id"]
    assert "123" not in str(fingerprint.json())

    first = client.post("/duplicates/check", json=payload, headers=headers)
    second = client.post(
        "/duplicates/check",
        json={**payload, "url": "http://127.0.0.1:8000/account?id=456"},
        headers=headers,
    )
    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["duplicate_result"]["duplicate_status"] == "exact_duplicate"


def test_api_duplicate_groups_and_fingerprint_lookup(monkeypatch, tmp_path) -> None:
    client = _client(tmp_path, monkeypatch)
    headers = {"X-VulScan-API-Key": UNIT_API_KEY}
    response = client.post(
        "/duplicates/check",
        json={"url": "http://127.0.0.1:8000/account?id=123", "issue_type": "idor_candidate", "parameter": "id"},
        headers=headers,
    )
    body = response.json()

    groups = client.get("/duplicates/groups", headers=headers)
    assert groups.status_code == 200
    assert groups.json()["summary"]["total_fingerprints"] == 1

    fingerprint_id = body["fingerprint"]["fingerprint_id"]
    fingerprint = client.get(f"/duplicates/fingerprints/{fingerprint_id}", headers=headers)
    assert fingerprint.status_code == 200
    assert fingerprint.json()["fingerprint_id"] == fingerprint_id


def test_api_key_protection_applies_to_duplicates(monkeypatch, tmp_path) -> None:
    client = _client(tmp_path, monkeypatch)

    missing_key = client.get("/duplicates/groups")
    with_key = client.get("/duplicates/groups", headers={"X-VulScan-API-Key": UNIT_API_KEY})

    assert missing_key.status_code == 401
    assert with_key.status_code == 200


def test_api_rejects_parameter_values_and_credentials(monkeypatch, tmp_path) -> None:
    client = _client(tmp_path, monkeypatch)
    headers = {"X-VulScan-API-Key": UNIT_API_KEY}
    response = client.post(
        "/duplicates/check",
        json={
            "url": "http://127.0.0.1:8000/account?id=123",
            "issue_type": "idor_candidate",
            "parameter_values": {"id": "123"},
        },
        headers=headers,
    )

    assert response.status_code == 422
