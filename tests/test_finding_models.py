from scanner.finding_models import build_professional_finding


def test_professional_finding_defaults_candidate_not_confirmed():
    finding = build_professional_finding(title="Candidate", confidence="Confirmed")

    assert finding["status"] == "draft"
    assert finding["validation_status"] == "candidate"
    assert finding["confidence"] == "High"

