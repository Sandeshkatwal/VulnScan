from scanner.api_job_store import ApiJobStore
from scanner.api_jobs import run_scan_job


def test_run_scan_job_persists_completed_result(tmp_path) -> None:
    store = ApiJobStore(tmp_path / "vulscan-test.db")
    store.create_job({"job_id": "job-1", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})

    def executor(**kwargs):
        return {
            "scan_id": "scan-1",
            "summary": {"total_findings": 0},
            "result_path": "reports/unit.json",
            "html_report_path": None,
        }

    run_scan_job(job_id="job-1", request={"target": "127.0.0.1"}, store=store, executor=executor)

    job = store.get_job("job-1")
    assert job["status"] == "completed"
    assert job["scan_id"] == "scan-1"
    assert job["result_summary"] == {"total_findings": 0}


def test_run_scan_job_persists_safe_failure(tmp_path) -> None:
    store = ApiJobStore(tmp_path / "vulscan-test.db")
    store.create_job({"job_id": "job-1", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})

    def executor(**kwargs):
        raise RuntimeError("internal unit failure")

    run_scan_job(job_id="job-1", request={"target": "127.0.0.1"}, store=store, executor=executor)

    job = store.get_job("job-1")
    assert job["status"] == "failed"
    assert job["safe_error_code"] == "API_JOB_FAILED"
    assert "internal unit failure" not in job["error_message"]
