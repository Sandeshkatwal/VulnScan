from fastapi.testclient import TestClient

from scanner.api_app import create_app


def _fake_scan_executor(**kwargs):
    return {
        "scan_id": "scan-123",
        "status": "completed",
        "target": kwargs["target"],
        "summary": {"total_open_ports": 0, "total_findings": 0},
        "result_path": None,
        "html_report_path": None,
        "retrievable": True,
    }


def test_openapi_json_returns_schema() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert response.json()["openapi"]


def test_openapi_title_includes_vulscan_api() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    schema = client.get("/openapi.json").json()

    assert schema["info"]["title"] == "VulScan API"


def test_openapi_includes_key_paths() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    paths = client.get("/openapi.json").json()["paths"]

    assert "/health" in paths
    assert "/scans" in paths
    assert "/jobs/{job_id}" in paths


def test_scan_request_schema_does_not_include_password_fields() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    schema = client.get("/openapi.json").json()
    properties = schema["components"]["schemas"]["ScanRequest"]["properties"]

    for field in ("password", "ssh_password", "windows_password", "private_key", "token", "secret"):
        assert field not in properties


def test_api_key_security_scheme_exists() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    security_schemes = client.get("/openapi.json").json()["components"]["securitySchemes"]

    assert security_schemes["VulScanApiKey"]["type"] == "apiKey"
    assert security_schemes["VulScanApiKey"]["name"] == "X-VulScan-API-Key"


def test_protected_endpoint_docs_include_api_key_security() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    operation = client.get("/openapi.json").json()["paths"]["/jobs"]["get"]

    assert {"VulScanApiKey": []} in operation["security"]


def test_public_endpoint_docs_do_not_require_api_key() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    operation = client.get("/openapi.json").json()["paths"]["/health"]["get"]

    assert operation["security"] == []


def test_post_scans_request_example_exists() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    operation = client.get("/openapi.json").json()["paths"]["/scans"]["post"]
    example = operation["requestBody"]["content"]["application/json"]["example"]

    assert example["target"] == "127.0.0.1"
    assert example["scan_mode"] == "safe"
    assert "password" not in example


def test_error_response_model_exists() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    schemas = client.get("/openapi.json").json()["components"]["schemas"]

    assert "ErrorResponse" in schemas


def test_route_tags_exist() -> None:
    client = TestClient(create_app(scan_executor=_fake_scan_executor))

    schema = client.get("/openapi.json").json()
    tags = {tag["name"] for tag in schema["tags"]}

    assert {"Health", "Scans", "Jobs", "Findings", "Exports", "System"}.issubset(tags)
