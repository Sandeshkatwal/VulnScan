from fastapi.testclient import TestClient

from scanner.api_app import create_app


client = TestClient(create_app())


def test_api_owasp_assessment_rules_endpoint() -> None:
    response = client.get("/owasp/assessment/rules")
    assert response.status_code == 200
    assert response.json()["version"] == "2025"
    assert len(response.json()["categories"]) == 10


def test_api_owasp_assessment_build_endpoint() -> None:
    response = client.post(
        "/owasp/assessment/build",
        json={
            "findings": [{"title": "Local CVE Match", "source": "vuln_intel", "category": "Vulnerability Intelligence", "evidence": "CVE indicator for component."}],
            "endpoint_results": [{"normalised_url": "http://127.0.0.1/admin", "endpoint_category": "admin"}],
            "parameter_results": [{"url": "http://127.0.0.1/account?id=1", "parameter_name": "id", "parameter_type": "idor"}],
            "safe_validation_results": [{"url": "http://127.0.0.1/search?q=test", "parameter": "q", "check_name": "reflected_input_observation", "indicator_found": True}],
            "evidence_records": [],
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["owasp_assessment_summary"]["enabled"] is True
    assert payload["owasp_category_results"]
    assert payload["owasp_evidence_items"]
    assert payload["owasp_coverage_gaps"]
