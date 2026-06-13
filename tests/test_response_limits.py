from fastapi.testclient import TestClient

from scanner.api_app import create_app


def test_evidence_endpoint_supports_pagination(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app())
    for index in range(3):
        client.post("/evidence", json={"title": f"Evidence {index}", "evidence_type": "manual_observation", "safe_summary": "simulated safe summary"})

    response = client.get("/evidence?page=1&page_size=2")

    assert response.status_code == 200
    body = response.json()
    assert len(body["evidence_items"]) == 2
    assert body["paginated_response"]["total"] == 3
    assert body["paginated_response"]["has_next"] is True


def test_findings_endpoint_supports_pagination(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app())
    for index in range(3):
        client.post(
            "/reports/finding",
            json={
                "title": f"Finding {index}",
                "technical_summary": "simulated safe finding",
                "severity": "Low",
                "validation_status": "candidate",
            },
        )

    response = client.get("/reports/findings?page=1&page_size=2")

    assert response.status_code == 200
    body = response.json()
    assert len(body["findings"]) == 2
    assert body["paginated_response"]["total"] == 3


def test_summary_endpoints_avoid_returning_full_huge_arrays(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app())
    client.post(
        "/reports/finding",
        json={
            "title": "Summary candidate",
            "technical_summary": "x" * 1000,
            "severity": "Low",
            "validation_status": "candidate",
        },
    )

    response = client.get("/reports/findings")

    assert response.status_code == 200
    finding = response.json()["findings"][0]
    assert len(finding["technical_summary"]) < 300
    assert "detail_url" in finding
