import json

from fastapi.testclient import TestClient

from scanner.api_app import create_app
from scanner.api_reports import encode_report_id
from scanner.api_job_store import ApiJobStore


UNIT_API_KEY = "unit-test-api-key"


def _write_reports(reports_dir):
    reports_dir.mkdir()
    json_path = reports_dir / "127.0.0.1_2026-05-29_000000.json"
    html_path = reports_dir / "127.0.0.1_2026-05-29_000000.html"
    ignored_path = reports_dir / "notes.txt"
    json_path.write_text(json.dumps({"target": "127.0.0.1", "findings": []}), encoding="utf-8")
    html_path.write_text("<html><body><h1>Report</h1></body></html>", encoding="utf-8")
    ignored_path.write_text("not a report", encoding="utf-8")
    return json_path, html_path, ignored_path


def test_list_reports_returns_json_and_html(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    reports_dir = tmp_path / "reports"
    _write_reports(reports_dir)
    client = TestClient(create_app(reports_dir=reports_dir))

    response = client.get("/reports")

    assert response.status_code == 200
    reports = response.json()["reports"]
    assert {report["type"] for report in reports} == {"json", "html"}
    assert all(report["filename"] != "notes.txt" for report in reports)
    assert all(report["download_url"].startswith("/reports/") for report in reports)


def test_list_reports_filters_type_and_target(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    reports_dir = tmp_path / "reports"
    _write_reports(reports_dir)
    client = TestClient(create_app(reports_dir=reports_dir))

    response = client.get("/reports?type=json&target=127.0.0.1")

    assert response.status_code == 200
    reports = response.json()["reports"]
    assert len(reports) == 1
    assert reports[0]["type"] == "json"


def test_download_report_works_for_allowed_file(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    reports_dir = tmp_path / "reports"
    json_path, _, _ = _write_reports(reports_dir)
    report_id = encode_report_id(json_path, reports_dir)
    client = TestClient(create_app(reports_dir=reports_dir))

    response = client.get(f"/reports/{report_id}/download")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["target"] == "127.0.0.1"


def test_view_html_report_returns_html(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    reports_dir = tmp_path / "reports"
    _, html_path, _ = _write_reports(reports_dir)
    report_id = encode_report_id(html_path, reports_dir)
    client = TestClient(create_app(reports_dir=reports_dir))

    response = client.get(f"/reports/{report_id}/view")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "<h1>Report</h1>" in response.text


def test_unknown_report_id_returns_404(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    client = TestClient(create_app(reports_dir=reports_dir))

    response = client.get("/reports/unknown/metadata")

    assert response.status_code == 404


def test_path_traversal_is_blocked(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    client = TestClient(create_app(reports_dir=reports_dir))

    response = client.get("/reports/..%2Fsecret/download")

    assert response.status_code == 404


def test_file_outside_reports_directory_is_not_served(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")

    assert encode_report_id(outside, reports_dir) is None
    client = TestClient(create_app(reports_dir=reports_dir))
    response = client.get("/reports/b3V0c2lkZS5qc29u/download")

    assert response.status_code == 404


def test_report_endpoints_require_api_key_when_configured(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("VULSCAN_API_KEY", UNIT_API_KEY)
    reports_dir = tmp_path / "reports"
    _write_reports(reports_dir)
    client = TestClient(create_app(reports_dir=reports_dir))

    missing = client.get("/reports")
    accepted = client.get("/reports", headers={"X-VulScan-API-Key": UNIT_API_KEY})

    assert missing.status_code == 401
    assert accepted.status_code == 200
    assert UNIT_API_KEY not in missing.text
    assert UNIT_API_KEY not in accepted.text


def test_job_report_paths_include_safe_urls(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    reports_dir = tmp_path / "reports"
    json_path, html_path, _ = _write_reports(reports_dir)
    store = ApiJobStore(tmp_path / "jobs.db")
    store.create_job({"job_id": "job-1", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})
    store.save_job_result("job-1", "scan-1", {"total_findings": 0}, str(json_path), str(html_path))
    client = TestClient(create_app(job_store=store, reports_dir=reports_dir))

    response = client.get("/jobs/job-1")

    assert response.status_code == 200
    body = response.json()
    assert body["result_download_url"].endswith("/download")
    assert body["html_view_url"].endswith("/view")
    assert body["html_download_url"].endswith("/download")
