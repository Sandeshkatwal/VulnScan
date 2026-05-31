from fastapi.testclient import TestClient
import json
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
    assert body["api_version"] == "18.8"
    assert body["version"]


def test_local_dashboard_cors_origin_is_allowed() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    response = client.options(
        "/jobs",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-VulScan-API-Key",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


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
        "scanner.api_app.get_recent_scans_page",
        lambda **kwargs: ([{"scan_id": "scan-1", "target": kwargs.get("target") or "127.0.0.1"}], 1),
    )
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    response = client.get("/scans")

    assert response.status_code == 200
    assert response.json()["scans"][0]["scan_id"] == "scan-1"
    assert response.json()["pagination"]["total"] == 1


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


def test_get_jobs_supports_limit_offset(job_store) -> None:
    job_store.create_job({"job_id": "job-1", "target": "127.0.0.1", "created_at": "2026-05-23T00:00:00+00:00", "request": {"target": "127.0.0.1"}})
    job_store.create_job({"job_id": "job-2", "target": "127.0.0.1", "created_at": "2026-05-23T00:00:01+00:00", "request": {"target": "127.0.0.1"}})
    client = TestClient(create_app(scan_executor=_fake_scan_executor, job_store=job_store))

    response = client.get("/jobs?limit=1&offset=1")

    assert response.status_code == 200
    assert response.json()["pagination"]["offset"] == 1
    assert response.json()["pagination"]["has_previous"] is True
    assert len(response.json()["jobs"]) == 1


def test_get_jobs_supports_status_filter(job_store) -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor, job_store=job_store))
    job_store.create_job({"job_id": "job-1", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})
    job_store.create_job({"job_id": "job-2", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})
    job_store.mark_job_failed("job-2", "API_JOB_FAILED", "Safe failure.")

    response = client.get("/jobs?status=failed")

    assert response.status_code == 200
    assert [job["job_id"] for job in response.json()["jobs"]] == ["job-2"]
    assert response.json()["filters"]["status"] == "failed"


def test_get_jobs_supports_target_filter(job_store) -> None:
    job_store.create_job({"job_id": "job-1", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})
    job_store.create_job({"job_id": "job-2", "target": "127.0.0.2", "request": {"target": "127.0.0.2"}})
    client = TestClient(create_app(scan_executor=_fake_scan_executor, job_store=job_store))

    response = client.get("/jobs?target=127.0.0.2")

    assert response.status_code == 200
    assert [job["job_id"] for job in response.json()["jobs"]] == ["job-2"]


def test_get_jobs_rejects_invalid_sort_by(job_store) -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor, job_store=job_store))

    response = client.get("/jobs?sort_by=scan_id")

    assert response.status_code == 400
    assert "Unsupported sort_by" in response.text


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


def test_get_job_findings_supports_severity_filter(job_store, tmp_path) -> None:
    result_path = tmp_path / "result.json"
    result_path.write_text(
        json.dumps(
            {
                "findings": [
                    {"title": "High Finding", "severity": "High", "source": "unit", "category": "Unit"},
                    {"title": "Low Finding", "severity": "Low", "source": "unit", "category": "Unit"},
                ]
            }
        ),
        encoding="utf-8",
    )
    job_store.create_job({"job_id": "job-1", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})
    job_store.save_job_result("job-1", "scan-1", {"total_findings": 2}, str(result_path), None)
    client = TestClient(create_app(scan_executor=_fake_scan_executor, job_store=job_store))

    response = client.get("/jobs/job-1/findings?severity=High")

    assert response.status_code == 200
    assert [finding["title"] for finding in response.json()["findings"]] == ["High Finding"]


def test_get_job_findings_supports_compact_true(job_store, tmp_path) -> None:
    result_path = tmp_path / "result.json"
    result_path.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "title": "High Finding",
                        "severity": "High",
                        "source": "unit",
                        "category": "Unit",
                        "risk_score": 80,
                        "priority_score": 90,
                        "priority_label": "Fix First",
                        "recommendation": "Fix it.",
                        "evidence": "Verbose evidence.",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    job_store.create_job({"job_id": "job-1", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})
    job_store.save_job_result("job-1", "scan-1", {"total_findings": 1}, str(result_path), None)
    client = TestClient(create_app(scan_executor=_fake_scan_executor, job_store=job_store))

    response = client.get("/jobs/job-1/findings?compact=true")

    assert response.status_code == 200
    finding = response.json()["findings"][0]
    assert "recommendation" in finding
    assert "evidence" not in finding


def test_get_scans_supports_pagination(monkeypatch) -> None:
    monkeypatch.setattr(
        "scanner.api_app.get_recent_scans_page",
        lambda **kwargs: ([{"scan_id": "scan-2", "target": "127.0.0.1"}], 3),
    )
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    response = client.get("/scans?limit=1&offset=1")

    assert response.status_code == 200
    assert response.json()["pagination"]["total"] == 3
    assert response.json()["pagination"]["has_next"] is True


def test_export_findings_includes_filters(monkeypatch) -> None:
    monkeypatch.setattr(
        "scanner.api_app.export_findings",
        lambda *args, **kwargs: {
            "status": "exported",
            "format": "csv",
            "path": "exports/unit.csv",
            "record_count": 1,
            "filters": {"severity": kwargs.get("severity")},
            "pagination": {"limit": kwargs.get("limit"), "offset": kwargs.get("offset"), "returned": 1, "total": 1, "has_next": False, "has_previous": False, "next_offset": None, "previous_offset": None},
        },
    )
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    response = client.get("/exports/findings?format=csv&severity=Medium&limit=10")

    assert response.status_code == 200
    assert response.json()["filters"]["severity"] == "Medium"
    assert response.json()["export_path"] == "exports/unit.csv"


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
