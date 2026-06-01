from fastapi.testclient import TestClient

from scanner.api_app import create_app
from scanner.api_security import API_KEY_ENV_VAR
from tests.test_bug_intelligence_metrics import _seed_metrics_db


UNIT_API_KEY = "unit-test-key"


def test_api_metrics_summary(monkeypatch, tmp_path):
    db_path = tmp_path / "metrics_api.db"
    _seed_metrics_db(db_path)
    monkeypatch.setenv(API_KEY_ENV_VAR, UNIT_API_KEY)
    client = TestClient(create_app(remediation_db_path=db_path))

    response = client.get("/bug-intelligence/metrics/summary", headers={"X-VulScan-API-Key": UNIT_API_KEY})

    assert response.status_code == 200
    metrics = response.json()["bug_intelligence_metrics"]
    assert metrics["total_submissions"] == 5
    assert metrics["total_accepted"] == 2
    assert metrics["duplicate_rate"] == 20.0


def test_api_metrics_key_protection_applies(monkeypatch, tmp_path):
    db_path = tmp_path / "metrics_api.db"
    _seed_metrics_db(db_path)
    monkeypatch.setenv(API_KEY_ENV_VAR, UNIT_API_KEY)
    client = TestClient(create_app(remediation_db_path=db_path))

    missing = client.get("/bug-intelligence/metrics/summary")
    accepted = client.get("/bug-intelligence/metrics/summary", headers={"X-VulScan-API-Key": UNIT_API_KEY})

    assert missing.status_code == 401
    assert accepted.status_code == 200


def test_api_metrics_export_json(monkeypatch, tmp_path):
    db_path = tmp_path / "metrics_api.db"
    _seed_metrics_db(db_path)
    monkeypatch.setenv(API_KEY_ENV_VAR, UNIT_API_KEY)
    client = TestClient(create_app(remediation_db_path=db_path))

    response = client.get("/bug-intelligence/metrics/export?format=json", headers={"X-VulScan-API-Key": UNIT_API_KEY})

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["total_bounty_by_currency"] == {"USD": 250.0}
    assert body["program_performance"]
