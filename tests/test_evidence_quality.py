from scanner.evidence_quality import calculate_evidence_quality_score
from scanner.evidence_vault import create_evidence_item


def test_evidence_quality_score_calculated() -> None:
    item = create_evidence_item(title="Manual observation", safe_summary="Safe summary", related_url="http://127.0.0.1:8000/admin", related_owasp_categories=["A01:2025"], redacted_response_summary="403 summary")
    score = calculate_evidence_quality_score(item)
    assert score["score"] >= 70
    assert score["label"] in {"Good Evidence", "Excellent Evidence"}


def test_failed_secret_check_lowers_quality_score() -> None:
    item = {"title": "Unsafe", "safe_summary": "Authorization: Bearer secret-demo-token", "secret_detection_status": "failed", "redaction_status": "failed_secret_check"}
    score = calculate_evidence_quality_score(item)
    assert score["score"] < 30
    assert score["label"] == "Blocked"
