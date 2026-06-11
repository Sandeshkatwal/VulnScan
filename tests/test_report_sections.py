from scanner.report_sections import build_evidence_summary_section, build_executive_summary, build_findings_summary, build_owasp_mapping_section
from scanner.retest_summary import build_retest_summary
from scanner.risk_acceptance import build_risk_acceptance_note, build_risk_acceptance_summary


def findings():
    return [
        {
            "finding_id": "finding-001",
            "title": "Missing CSP Header",
            "severity": "Low",
            "status": "draft",
            "validation_status": "manual_validation_required",
            "retest_status": "not_retested",
            "owasp_categories": ["A02:2025"],
            "evidence_references": ["ev-1"],
            "evidence_quality_summary": {"score": 80},
        },
        {
            "finding_id": "finding-002",
            "title": "Access control issue",
            "severity": "High",
            "status": "risk_accepted",
            "validation_status": "manually_verified_issue",
            "retest_status": "retest_required",
            "owasp_categories": ["A01:2025"],
            "risk_acceptance": build_risk_acceptance_note(finding_id="finding-002", accepted_by="owner", acceptance_reason="Temporary exception"),
        },
    ]


def test_build_executive_summary_and_findings_summary():
    summary = build_executive_summary(findings())
    counts = build_findings_summary(findings())

    assert summary["total_findings"] == 2
    assert summary["manual_validation_required_count"] == 1
    assert counts["severity_counts"]["High"] == 1


def test_build_owasp_mapping_evidence_retest_and_risk_acceptance_sections():
    data = findings()

    assert build_owasp_mapping_section(data)["matrix"][0]["finding_count"] == 1
    assert build_evidence_summary_section(data)["evidence_reference_count"] == 1
    assert build_retest_summary(data)["requiring_retest"] == 1
    assert build_risk_acceptance_summary(data)["accepted_risk_count"] == 1

