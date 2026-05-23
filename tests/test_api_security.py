from fastapi.testclient import TestClient
from typer.testing import CliRunner

from scanner.api_app import create_app
from scanner.main import app


UNIT_API_KEY = "unit-test-api-key"


def test_health_works_without_api_key_when_key_configured(monkeypatch) -> None:
    monkeypatch.setenv("VULSCAN_API_KEY", UNIT_API_KEY)
    client = TestClient(create_app())

    response = client.get("/health")

    assert response.status_code == 200


def test_version_works_without_api_key_when_key_configured(monkeypatch) -> None:
    monkeypatch.setenv("VULSCAN_API_KEY", UNIT_API_KEY)
    client = TestClient(create_app())

    response = client.get("/version")

    assert response.status_code == 200


def test_protected_endpoint_works_in_local_dev_mode(monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    client = TestClient(create_app())

    response = client.get("/jobs")

    assert response.status_code == 200


def test_protected_endpoint_rejects_missing_key(monkeypatch) -> None:
    monkeypatch.setenv("VULSCAN_API_KEY", UNIT_API_KEY)
    client = TestClient(create_app())

    response = client.get("/jobs")

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or missing API key."}


def test_protected_endpoint_rejects_wrong_key(monkeypatch) -> None:
    monkeypatch.setenv("VULSCAN_API_KEY", UNIT_API_KEY)
    client = TestClient(create_app())

    response = client.get("/jobs", headers={"X-VulScan-API-Key": "wrong-unit-key"})

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or missing API key."}


def test_protected_endpoint_accepts_x_vulscan_api_key_header(monkeypatch) -> None:
    monkeypatch.setenv("VULSCAN_API_KEY", UNIT_API_KEY)
    client = TestClient(create_app())

    response = client.get("/jobs", headers={"X-VulScan-API-Key": UNIT_API_KEY})

    assert response.status_code == 200


def test_protected_endpoint_accepts_authorization_bearer_header(monkeypatch) -> None:
    monkeypatch.setenv("VULSCAN_API_KEY", UNIT_API_KEY)
    client = TestClient(create_app())

    response = client.get("/jobs", headers={"Authorization": f"Bearer {UNIT_API_KEY}"})

    assert response.status_code == 200


def test_api_key_is_not_present_in_job_response(monkeypatch) -> None:
    monkeypatch.setenv("VULSCAN_API_KEY", UNIT_API_KEY)
    client = TestClient(create_app())

    response = client.get("/jobs", headers={"X-VulScan-API-Key": UNIT_API_KEY})

    assert response.status_code == 200
    assert UNIT_API_KEY not in response.text


def test_api_key_is_not_present_in_error_response(monkeypatch) -> None:
    monkeypatch.setenv("VULSCAN_API_KEY", UNIT_API_KEY)
    client = TestClient(create_app())

    response = client.get("/jobs", headers={"X-VulScan-API-Key": "wrong-unit-key"})

    assert response.status_code == 401
    assert UNIT_API_KEY not in response.text
    assert "wrong-unit-key" not in response.text


def test_require_api_key_refuses_startup_when_key_missing(monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    runner = CliRunner()

    result = runner.invoke(app, ["api", "--require-api-key"])

    assert result.exit_code == 1
    assert "VULSCAN_API_KEY is not set" in result.output
    assert "change-this-local-dev-key" in result.output
