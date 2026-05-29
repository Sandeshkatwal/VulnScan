from fastapi.testclient import TestClient

from scanner.api_app import create_app
from scanner.api_job_store import ApiJobStore
from scanner.api_remediation import build_remediation_finding_key
from scanner.database import get_connection, init_db


UNIT_API_KEY = "unit-test-api-key"


def _seed_remediation(db_path, finding_key="ABCDEF123456"):
    init_db(db_path)
    with get_connection(db_path) as connection:
        connection.execute(
            """
            INSERT INTO remediation_status (
                finding_fingerprint, finding_id, target, title, source, category,
                severity, priority_label, status, owner, due_date, note,
                first_seen, last_seen, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_key,
                "F-1",
                "127.0.0.1",
                "Test finding",
                "port_scan",
                "exposure",
                "High",
                "Fix First",
                "Open",
                None,
                "2099-01-01",
                None,
                "2026-05-29T00:00:00+00:00",
                "2026-05-29T00:00:00+00:00",
                "2026-05-29T00:00:00+00:00",
                "2026-05-29T00:00:00+00:00",
            ),
        )


def test_list_remediation_records(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    db_path = tmp_path / "vulscan.db"
    _seed_remediation(db_path)
    client = TestClient(create_app(remediation_db_path=db_path))

    response = client.get("/remediation?status=open")

    assert response.status_code == 200
    body = response.json()
    assert body["records"][0]["finding_key"] == "ABCDEF123456"
    assert body["records"][0]["status"] == "open"


def test_get_remediation_summary(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    db_path = tmp_path / "vulscan.db"
    _seed_remediation(db_path)
    client = TestClient(create_app(remediation_db_path=db_path))

    response = client.get("/remediation/summary")

    assert response.status_code == 200
    assert response.json()["open_count"] == 1
    assert response.json()["total_count"] == 1


def test_update_remediation_status(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    db_path = tmp_path / "vulscan.db"
    _seed_remediation(db_path)
    client = TestClient(create_app(remediation_db_path=db_path))

    response = client.put(
        "/remediation/ABCDEF12",
        json={"status": "in_progress", "note": "Reviewing remediation options.", "owner": "security", "due_date": "2099-02-01"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "in_progress"
    assert body["note"] == "Reviewing remediation options."
    assert body["record"]["owner"] == "security"
    assert body["record"]["history"][0]["new_status"] == "in_progress"


def test_update_rejects_invalid_status(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    db_path = tmp_path / "vulscan.db"
    _seed_remediation(db_path)
    client = TestClient(create_app(remediation_db_path=db_path))

    response = client.put("/remediation/ABCDEF12", json={"status": "patched"})

    assert response.status_code == 400


def test_update_rejects_unsafe_note_content(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    db_path = tmp_path / "vulscan.db"
    _seed_remediation(db_path)
    client = TestClient(create_app(remediation_db_path=db_path))

    response = client.put("/remediation/ABCDEF12", json={"status": "in_progress", "note": "password=demo"})

    assert response.status_code == 400
    assert "password=demo" not in response.text


def test_finding_key_is_stable() -> None:
    finding = {"title": "Open SSH", "affected_host": "127.0.0.1", "affected_port": 22, "service": "ssh", "category": "exposure", "source": "port_scan"}

    assert build_remediation_finding_key(finding, "127.0.0.1") == build_remediation_finding_key(dict(finding), "127.0.0.1")


def test_remediation_update_does_not_execute_commands(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    db_path = tmp_path / "vulscan.db"
    _seed_remediation(db_path)
    client = TestClient(create_app(remediation_db_path=db_path))

    response = client.put("/remediation/ABCDEF12", json={"status": "fixed", "note": "Tracked manually."})

    assert response.status_code == 200
    assert response.json()["status"] == "fixed"


def test_remediation_endpoints_require_api_key_when_configured(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("VULSCAN_API_KEY", UNIT_API_KEY)
    db_path = tmp_path / "vulscan.db"
    _seed_remediation(db_path)
    client = TestClient(create_app(remediation_db_path=db_path))

    missing = client.get("/remediation/summary")
    accepted = client.get("/remediation/summary", headers={"X-VulScan-API-Key": UNIT_API_KEY})

    assert missing.status_code == 401
    assert accepted.status_code == 200
    assert UNIT_API_KEY not in missing.text
    assert UNIT_API_KEY not in accepted.text


def test_finding_responses_include_finding_key(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    db_path = tmp_path / "vulscan.db"
    finding = {"id": "F-1", "title": "Test finding", "severity": "High", "category": "exposure", "affected_host": "127.0.0.1", "source": "port_scan"}
    finding_key = build_remediation_finding_key(finding, "127.0.0.1")
    _seed_remediation(db_path, finding_key=finding_key)
    report_path = tmp_path / "report.json"
    report_path.write_text('{"findings":[{"id":"F-1","title":"Test finding","severity":"High","category":"exposure","affected_host":"127.0.0.1","source":"port_scan"}]}', encoding="utf-8")
    store = ApiJobStore(tmp_path / "jobs.db")
    store.create_job({"job_id": "job-1", "target": "127.0.0.1", "request": {"target": "127.0.0.1"}})
    store.save_job_result("job-1", "scan-1", {"total_findings": 1}, str(report_path), None)
    client = TestClient(create_app(job_store=store, remediation_db_path=db_path))

    response = client.get("/jobs/job-1/findings")

    assert response.status_code == 200
    finding = response.json()["findings"][0]
    assert finding["finding_key"]
    assert finding["remediation_status"] == "open"
