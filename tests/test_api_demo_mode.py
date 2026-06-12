from fastapi.testclient import TestClient

from scanner.api_app import create_app


def test_demo_endpoints_return_fake_data_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app())

    status = client.get("/demo/status")
    dashboard = client.get("/demo/dashboard")
    report = client.post("/demo/report/build", json={"markdown": False, "html": False, "json": True})

    assert status.status_code == 200
    assert dashboard.status_code == 200
    assert report.status_code == 200
    text = dashboard.text + report.text
    assert "simulated" in text
    assert "secret-demo-token" not in text
    assert "password=" not in text.lower()

