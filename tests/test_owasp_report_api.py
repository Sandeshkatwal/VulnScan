from __future__ import annotations

from fastapi.testclient import TestClient

from scanner.api_app import create_app


UNIT_API_KEY = "unit-test-api-key"


def _payload() -> dict[str, object]:
    return {
        "target": "http://127.0.0.1:8000",
        "owasp_evidence_items": [
            {
                "evidence_id": "ev-a02",
                "source": "owasp_a02",
                "title": "Missing Content-Security-Policy",
                "owasp_id": "A02:2025",
                "owasp_name": "Security Misconfiguration",
                "confidence": "High",
                "evidence_strength": "strong_indicator",
                "manual_validation_required": False,
            }
        ],
    }


def test_build_owasp_report_endpoint_writes_markdown(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app())

    response = client.post("/owasp/report/build", json=_payload())

    assert response.status_code == 200
    body = response.json()
    assert body["owasp_assessment_report"]["category_results"]
    assert body["markdown_report_path"].startswith("reports")
    assert body["download_url"].startswith("/owasp/report/owasp_assessment_")


def test_latest_and_download_owasp_report(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app())
    built = client.post("/owasp/report/build", json=_payload()).json()
    report_id = built["owasp_assessment_report"]["report_id"]

    latest = client.get("/owasp/report/latest")
    metadata = client.get(f"/owasp/report/{report_id}")
    download = client.get(f"/owasp/report/{report_id}/download")

    assert latest.status_code == 200
    assert metadata.status_code == 200
    assert download.status_code == 200
    assert "# VulScan OWASP Assessment Report" in download.text


def test_owasp_report_download_blocks_path_traversal(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VULSCAN_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app())

    response = client.get("/owasp/report/..%2Fsecret/download")

    assert response.status_code == 404


def test_owasp_report_endpoints_require_api_key_when_configured(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("VULSCAN_API_KEY", UNIT_API_KEY)
    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app())

    missing = client.post("/owasp/report/build", json=_payload())
    accepted = client.post("/owasp/report/build", json=_payload(), headers={"X-VulScan-API-Key": UNIT_API_KEY})

    assert missing.status_code == 401
    assert accepted.status_code == 200
    assert UNIT_API_KEY not in missing.text
    assert UNIT_API_KEY not in accepted.text
