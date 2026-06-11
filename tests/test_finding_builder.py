from scanner.finding_builder import apply_finding_wording_policy, build_finding_from_evidence_vault_item, build_finding_from_manual_input, calculate_finding_risk_score
from scanner.report_remediation_library import remediation_for_categories


def safe_evidence(**overrides):
    item = {
        "evidence_id": "ev-1",
        "title": "Manual observation",
        "safe_summary": "Access denied for standard_user as expected.",
        "related_owasp_categories": ["A01:2025"],
        "related_url": "http://127.0.0.1/admin",
        "evidence_strength": "manually_verified_secure",
        "confidence": "high",
        "redaction_status": "redacted",
        "secret_detection_status": "passed",
        "evidence_quality_score": 90,
    }
    item.update(overrides)
    return item


def test_build_finding_from_safe_evidence_vault_item():
    finding = build_finding_from_evidence_vault_item(safe_evidence())

    assert finding["finding_id"]
    assert finding["evidence_references"] == ["ev-1"]
    assert finding["validation_status"] == "manually_verified_secure"


def test_candidate_finding_uses_candidate_wording():
    finding = build_finding_from_manual_input({"title": "Candidate", "technical_summary": "Header absent.", "validation_status": "candidate"})

    assert "candidate requiring manual validation" in finding["technical_summary"]
    assert "does not confirm exploitability" in finding["technical_summary"]


def test_manual_verified_issue_uses_confirmed_wording():
    finding = apply_finding_wording_policy({"title": "Issue", "technical_summary": "Observed.", "validation_status": "manually_verified_issue"})

    assert "Manual validation confirmed" in finding["technical_summary"]


def test_false_positive_wording_works():
    finding = apply_finding_wording_policy({"title": "FP", "technical_summary": "Reviewed.", "validation_status": "false_positive"})

    assert "marked false positive" in finding["technical_summary"]


def test_retest_passed_wording_works():
    finding = apply_finding_wording_policy({"title": "Retest", "technical_summary": "Retested.", "validation_status": "retest_passed"})

    assert "Retest indicates the issue has been remediated" in finding["technical_summary"]


def test_risk_score_calculated_and_low_confidence_prevents_overstatement():
    finding = {"severity": "Critical", "confidence": "Low", "evidence_strength": "weak_indicator", "retest_status": "not_retested"}

    risk = calculate_finding_risk_score(finding)

    assert 0 <= risk["risk_score"] <= 55
    assert risk["severity_suggestion"] in {"Medium", "High"}


def test_remediation_guidance_generated_for_owasp_categories():
    assert "server-side authorization" in " ".join(remediation_for_categories(["A01:2025"])["A01"])
    assert "Harden security headers" in " ".join(remediation_for_categories(["A02:2025"])["A02"])
    assert "parameterised queries" in " ".join(remediation_for_categories(["A05:2025"])["A05"])
    assert "Harden session" in " ".join(remediation_for_categories(["A07:2025"])["A07"])

