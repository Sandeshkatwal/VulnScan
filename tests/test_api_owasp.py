from fastapi.testclient import TestClient

from scanner.api_app import create_app


def test_api_owasp_categories() -> None:
    client = TestClient(create_app())
    response = client.get("/owasp/categories")
    assert response.status_code == 200
    body = response.json()
    assert body["version"] == "2025"
    assert len(body["categories"]) == 10


def test_api_owasp_map() -> None:
    client = TestClient(create_app())
    response = client.post(
        "/owasp/map",
        json={
            "findings": [
                {
                    "title": "Missing Security Header",
                    "severity": "Informational",
                    "category": "Headers",
                    "evidence": "Missing security header.",
                    "source": "web_header_audit",
                }
            ],
            "endpoint_results": [{"path": "/admin", "endpoint_category": "admin"}],
            "parameter_results": [{"parameter_name": "q", "parameter_type": "injection_reflection", "path": "/search"}],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["owasp_top10_summary"]["enabled"] is True
    assert body["owasp_top10_mapped_items"]
