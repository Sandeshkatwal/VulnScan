from fastapi.testclient import TestClient

from scanner.api_app import create_app
from scanner.api_security import API_KEY_ENV_VAR


UNIT_API_KEY = "unit-test-key"


def build_client(tmp_path, monkeypatch):
    monkeypatch.setenv(API_KEY_ENV_VAR, UNIT_API_KEY)
    app = create_app(remediation_db_path=tmp_path / "submissions.db")
    return TestClient(app)


def test_api_submission_lifecycle(monkeypatch, tmp_path):
    client = build_client(tmp_path, monkeypatch)
    headers = {"X-VulScan-API-Key": UNIT_API_KEY}

    created = client.post(
        "/submissions",
        headers=headers,
        json={"report_id": "REPORT_ID", "program_name": "Demo Program", "platform": "manual", "status": "draft"},
    )
    assert created.status_code == 200
    submission_id = created.json()["submission_id"]

    listed = client.get("/submissions", headers=headers)
    assert listed.status_code == 200
    assert listed.json()["submissions"][0]["submission_id"] == submission_id

    updated = client.post(
        f"/submissions/{submission_id}/status",
        headers=headers,
        json={"status": "submitted", "note": "Submitted through platform."},
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "submitted"

    timeline = client.get(f"/submissions/{submission_id}/timeline", headers=headers)
    assert timeline.status_code == 200
    assert len(timeline.json()["events"]) >= 2


def test_api_rejects_invalid_status_and_credentials(monkeypatch, tmp_path):
    client = build_client(tmp_path, monkeypatch)
    headers = {"X-VulScan-API-Key": UNIT_API_KEY}

    invalid = client.post("/submissions", headers=headers, json={"program_name": "Demo", "platform": "manual", "status": "invalid"})
    assert invalid.status_code == 400

    credential_field = client.post(
        "/submissions",
        headers=headers,
        json={"program_name": "Demo", "platform": "manual", "platform_token": "not-allowed"},
    )
    assert credential_field.status_code == 422


def test_api_retest_and_summary(monkeypatch, tmp_path):
    client = build_client(tmp_path, monkeypatch)
    headers = {"X-VulScan-API-Key": UNIT_API_KEY}

    submission = client.post("/submissions", headers=headers, json={"program_name": "Demo", "platform": "manual"}).json()
    retest = client.post(
        "/retests",
        headers=headers,
        json={"submission_id": submission["submission_id"], "status": "retest_required", "notes": "Retest requested."},
    )
    assert retest.status_code == 200
    retest_id = retest.json()["retest_id"]

    updated = client.put(
        f"/retests/{retest_id}",
        headers=headers,
        json={"status": "retest_passed", "retest_result": "issue_no_longer_reproducible", "notes": "Manual retest passed."},
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "retest_passed"

    summary = client.get("/submissions/summary", headers=headers)
    assert summary.status_code == 200
    assert summary.json()["total_count"] == 1
    assert summary.json()["retest_passed_count"] == 1


def test_api_key_protection_applies(monkeypatch, tmp_path):
    client = build_client(tmp_path, monkeypatch)

    missing_key = client.get("/submissions")
    with_key = client.get("/submissions", headers={"X-VulScan-API-Key": UNIT_API_KEY})

    assert missing_key.status_code == 401
    assert with_key.status_code == 200
