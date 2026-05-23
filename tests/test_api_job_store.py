import json

import pytest

from scanner.api_job_store import ApiJobStore, INTERRUPTED_ERROR_CODE, sanitize_request_payload
from scanner.database import get_connection


@pytest.fixture
def store(tmp_path) -> ApiJobStore:
    return ApiJobStore(tmp_path / "vulscan-test.db")


def test_creates_api_jobs_table(store: ApiJobStore) -> None:
    with get_connection(store.db_path) as connection:
        row = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'api_jobs'"
        ).fetchone()

    assert row is not None


def test_insert_and_retrieve_job(store: ApiJobStore) -> None:
    store.create_job({"job_id": "job-1", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})

    job = store.get_job("job-1")

    assert job is not None
    assert job["job_id"] == "job-1"
    assert job["target"] == "127.0.0.1"
    assert job["status"] == "queued"


def test_update_job_status(store: ApiJobStore) -> None:
    store.create_job({"job_id": "job-1", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})

    job = store.update_job("job-1", status="running", started_at="2026-05-23T00:00:00+00:00")

    assert job is not None
    assert job["status"] == "running"
    assert job["started_at"]


def test_mark_job_completed(store: ApiJobStore) -> None:
    store.create_job({"job_id": "job-1", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})

    job = store.save_job_result("job-1", "scan-1", {"total_findings": 0}, "reports/unit.json", None)

    assert job is not None
    assert job["status"] == "completed"
    assert job["scan_id"] == "scan-1"
    assert job["result_summary"] == {"total_findings": 0}


def test_mark_job_failed(store: ApiJobStore) -> None:
    store.create_job({"job_id": "job-1", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})

    job = store.mark_job_failed("job-1", "API_JOB_FAILED", "Safe failure message.")

    assert job is not None
    assert job["status"] == "failed"
    assert job["safe_error_code"] == "API_JOB_FAILED"
    assert job["error_message"] == "Safe failure message."


def test_list_jobs_newest_first(store: ApiJobStore) -> None:
    store.create_job(
        {
            "job_id": "old-job",
            "target": "127.0.0.1",
            "created_at": "2026-05-23T00:00:00+00:00",
            "request": {"target": "127.0.0.1"},
        }
    )
    store.create_job(
        {
            "job_id": "new-job",
            "target": "127.0.0.2",
            "created_at": "2026-05-23T00:00:01+00:00",
            "request": {"target": "127.0.0.2"},
        }
    )

    jobs = store.list_jobs()

    assert [job["job_id"] for job in jobs] == ["new-job", "old-job"]


def test_filter_jobs_by_status(store: ApiJobStore) -> None:
    store.create_job({"job_id": "queued-job", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})
    store.create_job({"job_id": "failed-job", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})
    store.mark_job_failed("failed-job", "API_JOB_FAILED", "Safe failure message.")

    jobs = store.list_jobs(status="failed")

    assert [job["job_id"] for job in jobs] == ["failed-job"]


def test_filter_jobs_by_target(store: ApiJobStore) -> None:
    store.create_job({"job_id": "job-1", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})
    store.create_job({"job_id": "job-2", "target": "127.0.0.2", "request": {"target": "127.0.0.2"}})

    jobs = store.list_jobs(target="127.0.0.2")

    assert [job["job_id"] for job in jobs] == ["job-2"]


def test_running_jobs_are_marked_interrupted_on_startup(store: ApiJobStore) -> None:
    store.create_job({"job_id": "queued-job", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})
    store.create_job({"job_id": "running-job", "target": "127.0.0.1", "status": "running", "request": {"target": "127.0.0.1"}})

    changed = store.mark_interrupted_jobs()

    assert changed == 2
    assert store.get_job("queued-job")["safe_error_code"] == INTERRUPTED_ERROR_CODE
    assert store.get_job("running-job")["status"] == "failed"


def test_request_json_does_not_contain_api_key(store: ApiJobStore) -> None:
    store.create_job({"job_id": "job-1", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})

    with get_connection(store.db_path) as connection:
        row = connection.execute("SELECT request_json FROM api_jobs WHERE job_id = ?", ("job-1",)).fetchone()

    assert "api-key" not in str(row["request_json"]).lower()
    assert "vulscan" not in str(row["request_json"]).lower()


@pytest.mark.parametrize("unsafe_key", ["password", "token", "secret", "private_key", "ssh_password", "windows_password", "api_key", "bearer", "authorization"])
def test_request_json_rejects_unsafe_credential_fields(unsafe_key: str) -> None:
    with pytest.raises(ValueError):
        sanitize_request_payload({"target": "127.0.0.1", unsafe_key: "unit-test-value"})


def test_raw_request_json_is_sanitized_before_storage(store: ApiJobStore) -> None:
    store.create_job({"job_id": "job-1", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})

    with get_connection(store.db_path) as connection:
        row = connection.execute("SELECT request_json FROM api_jobs WHERE job_id = ?", ("job-1",)).fetchone()

    assert json.loads(row["request_json"]) == {"target": "127.0.0.1"}
