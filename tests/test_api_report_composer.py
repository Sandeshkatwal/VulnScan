from fastapi.testclient import TestClient

from scanner.api_app import create_app
from scanner.api_report_composer import resolve_composed_report_download


def test_download_endpoint_blocks_path_traversal():
    assert resolve_composed_report_download("../outside") is None


def test_report_composer_api_does_not_return_raw_secrets(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app())

    response = client.post(
        "/reports/finding",
        json={
            "title": "Manual candidate",
            "technical_summary": "Authorization: Bearer demo-secret-token",
            "severity": "Low",
            "validation_status": "candidate",
        },
    )

    assert response.status_code == 200
    body = response.text
    assert "demo-secret-token" not in body
    assert "[REDACTED-BEARER]" in body


def test_report_composer_download_rejects_traversal(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app())

    response = client.get("/reports/..%2Foutside/download")

    assert response.status_code == 404
