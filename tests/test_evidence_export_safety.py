from scanner.evidence_export_safety import can_export_evidence, export_evidence_summary_json, export_evidence_summary_markdown
from scanner.evidence_vault import create_evidence_item


def test_export_blocked_when_secret_detection_fails() -> None:
    item = {"evidence_id": "unsafe", "safe_summary": "Authorization: Bearer secret-demo-token", "redaction_status": "failed_secret_check", "secret_detection_status": "failed"}
    assert can_export_evidence(item)["export_allowed"] is False


def test_export_succeeds_for_safe_redacted_evidence(tmp_path) -> None:
    item = create_evidence_item(evidence_id="safe", title="Safe Evidence", safe_summary="Redacted summary", related_target="127.0.0.1")
    assert can_export_evidence(item)["export_allowed"] is True
    assert export_evidence_summary_json([item], tmp_path).exists()
    assert export_evidence_summary_markdown([item], tmp_path).exists()
