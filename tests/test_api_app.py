from fastapi.testclient import TestClient
import pytest

from scanner.api_app import create_app


@pytest.fixture(autouse=True)
def clear_api_key(monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)


def _fake_scan_executor(**kwargs):
    return {
        "scan_id": "scan-123",
        "status": "completed",
        "target": kwargs["target"],
        "summary": {"total_open_ports": 0, "total_findings": 0},
        "result_path": "reports/unit.json" if kwargs.get("json_report") else None,
        "html_report_path": None,
        "retrievable": bool(kwargs.get("save_db")),
    }


def test_health_returns_ok() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "scanner": "VulScan"}


def test_version_returns_scanner_and_version() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    response = client.get("/version")

    assert response.status_code == 200
    body = response.json()
    assert body["scanner"] == "VulScan"
    assert body["api_version"] == "15.2"
    assert body["version"]


def test_post_scans_accepts_safe_scan_request() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    response = client.post(
        "/scans",
        json={
            "target": "127.0.0.1",
            "scan_mode": "safe",
            "json_report": True,
            "html_report": False,
            "save_db": True,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] == "scan-123"
    assert body["status"] == "completed"
    assert body["result_path"] == "reports/unit.json"


def test_post_scans_rejects_credential_fields() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    response = client.post(
        "/scans",
        json={"target": "127.0.0.1", "scan_mode": "safe", "ssh_password": "not-a-real-secret"},
    )

    assert response.status_code == 422
    assert "traceback" not in response.text.lower()
    assert "not-a-real-secret" not in response.text


def test_post_scans_rejects_unsupported_scan_mode() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    response = client.post("/scans", json={"target": "127.0.0.1", "scan_mode": "credentialed"})

    assert response.status_code == 400
    assert "safe scan_mode" in response.text


def test_get_scans_returns_list_structure(monkeypatch) -> None:
    monkeypatch.setattr(
        "scanner.api_app.get_recent_scans",
        lambda limit=10, target=None: [{"scan_id": "scan-1", "target": target or "127.0.0.1"}],
    )
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    response = client.get("/scans")

    assert response.status_code == 200
    assert response.json()["scans"][0]["scan_id"] == "scan-1"


def test_get_jobs_returns_list_structure() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    response = client.get("/jobs")

    assert response.status_code == 200
    assert response.json() == {"jobs": []}


def test_get_scan_handles_missing_scan(monkeypatch) -> None:
    monkeypatch.setattr("scanner.api_app.get_scan_result_by_id", lambda scan_id: None)
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    response = client.get("/scans/missing")

    assert response.status_code == 404
    assert "traceback" not in response.text.lower()


def test_get_scan_findings_handles_missing_scan(monkeypatch) -> None:
    monkeypatch.setattr("scanner.api_app.get_findings_for_scan_id", lambda scan_id: None)
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    response = client.get("/scans/missing/findings")

    assert response.status_code == 404
    assert "traceback" not in response.text.lower()


def test_error_responses_do_not_include_tracebacks() -> None:
    def failing_executor(**kwargs):
        raise RuntimeError("internal unit failure")

    client = TestClient(create_app(scan_executor=failing_executor))

    response = client.post("/scans", json={"target": "127.0.0.1", "scan_mode": "safe"})

    assert response.status_code == 500
    assert "traceback" not in response.text.lower()
    assert "internal unit failure" not in response.text
