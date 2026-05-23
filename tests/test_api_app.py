from fastapi.testclient import TestClient
import pytest

from scanner.api_app import create_app
from scanner.api_job_store import ApiJobStore


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


@pytest.fixture
def job_store(tmp_path):
    return ApiJobStore(tmp_path / "vulscan-test.db")


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
    assert body["api_version"] == "15.3"
    assert body["version"]


def test_post_scans_creates_persistent_safe_scan_job(job_store) -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor, job_store=job_store))

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
    assert body["job_id"]
    assert body["status"] == "queued"
    job = job_store.get_job(body["job_id"])
    assert job is not None
    assert job["scan_id"] == "scan-123"
    assert job["status"] == "completed"
    assert job["result_path"] == "reports/unit.json"


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
    store = ApiJobStore()
    client = TestClient(create_app(scan_executor=_fake_scan_executor, job_store=store))

    response = client.get("/jobs")

    assert response.status_code == 200
    assert "jobs" in response.json()


def test_get_jobs_uses_persistent_store(job_store) -> None:
    job_store.create_job({"job_id": "job-1", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})
    client = TestClient(create_app(scan_executor=_fake_scan_executor, job_store=job_store))

    response = client.get("/jobs")

    assert response.status_code == 200
    assert response.json()["jobs"][0]["job_id"] == "job-1"


def test_get_job_returns_persistent_job(job_store) -> None:
    job_store.create_job({"job_id": "job-1", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})
    client = TestClient(create_app(scan_executor=_fake_scan_executor, job_store=job_store))

    response = client.get("/jobs/job-1")

    assert response.status_code == 200
    assert response.json()["job_id"] == "job-1"


def test_get_job_result_handles_missing_payload(job_store) -> None:
    job_store.create_job({"job_id": "job-1", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})
    job_store.save_job_result("job-1", "missing-scan", {"total_findings": 0}, None, None)
    client = TestClient(create_app(scan_executor=_fake_scan_executor, job_store=job_store))

    response = client.get("/jobs/job-1/result")

    assert response.status_code == 200
    assert response.json()["message"] == "Job completed but result payload is no longer available."


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


def test_scan_job_failure_does_not_include_tracebacks(job_store) -> None:
    def failing_executor(**kwargs):
        raise RuntimeError("internal unit failure")

    client = TestClient(create_app(scan_executor=failing_executor, job_store=job_store))

    response = client.post("/scans", json={"target": "127.0.0.1", "scan_mode": "safe"})

    assert response.status_code == 200
    job = job_store.get_job(response.json()["job_id"])
    assert job["status"] == "failed"
    assert job["safe_error_code"] == "API_JOB_FAILED"
    assert "traceback" not in str(job).lower()
    assert "internal unit failure" not in str(job)
