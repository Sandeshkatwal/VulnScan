from scanner.report_composer import compose_report


def test_compose_report_model():
    finding = {"finding_id": "finding-001", "title": "Candidate", "severity": "Low", "confidence": "Low", "validation_status": "candidate", "owasp_categories": ["A02:2025"], "evidence_references": []}

    report = compose_report(title="Report", target="http://127.0.0.1", findings=[finding])

    assert report["report_id"]
    assert report["executive_summary"]["total_findings"] == 1
    assert report["export_safety_status"] == "allowed"

