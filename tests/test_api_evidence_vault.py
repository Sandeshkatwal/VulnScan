from fastapi.testclient import TestClient

from scanner.api_app import create_app


def test_api_evidence_vault_redacts_and_exports_safely(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app())
    created = client.post("/evidence", json={"title": "Manual", "evidence_type": "manual_observation", "safe_summary": "Authorization: Bearer secret-demo-token"})
    assert created.status_code == 200
    item = created.json()["evidence_vault_item"]
    assert "secret-demo-token" not in str(item)
    assert "[REDACTED-BEARER]" in str(item)
    evidence_id = item["evidence_id"]
    quality = client.post(f"/evidence/{evidence_id}/quality")
    assert quality.status_code == 200
    link = client.post(f"/evidence/{evidence_id}/link", json={"link_type": "finding", "linked_id": "finding-001"})
    assert link.status_code == 200
    export = client.post("/evidence/export", json={"evidence_ids": [evidence_id], "json": True})
    assert export.status_code == 200
    assert export.json()["export_allowed"] is True


def test_api_export_blocks_unsafe_evidence(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app())
    import json
    from pathlib import Path

    data_dir = Path("data") / "evidence_vault"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "unsafe.json").write_text(json.dumps({"evidence_id": "unsafe", "title": "Unsafe", "safe_summary": "Authorization: Bearer secret-demo-token", "redaction_status": "failed_secret_check", "secret_detection_status": "failed"}), encoding="utf-8")
    export = client.post("/evidence/export", json={"evidence_ids": ["unsafe"], "json": True})
    assert export.status_code == 200
    assert export.json()["export_allowed"] is False
