from fastapi.testclient import TestClient

from scanner.api_app import create_app


def test_a03_rules_assess_and_sbom_api() -> None:
    client = TestClient(create_app())
    rules = client.get("/owasp/a03/rules")
    assert rules.status_code == 200
    assert rules.json()["owasp_id"] == "A03:2025"

    response = client.post(
        "/owasp/a03/assess",
        json={
            "target": "http://127.0.0.1:8000",
            "headers": {"Server": "nginx/1.24.0"},
            "scripts": ["/static/jquery-3.6.0.min.js"],
            "endpoint_results": [{"url": "http://127.0.0.1:8000/package.json"}],
            "html_snippet": "",
            "sbom_components": [],
            "vuln_intel": {},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["a03_supply_chain_summary"]["total_evidence_items"] >= 3
    assert not any("token" in str(item).lower() for item in body["a03_supply_chain_evidence"])

    sbom = client.post(
        "/sbom/analyse",
        json={
            "sbom": {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"type": "library", "name": "jquery", "version": "3.6.0"}]},
            "use_vuln_intel": False,
            "vuln_intel": {},
        },
    )
    assert sbom.status_code == 200
    assert sbom.json()["components"][0]["name"] == "jquery"
