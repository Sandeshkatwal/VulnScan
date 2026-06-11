from scanner.risk_acceptance import build_risk_acceptance_note


def test_risk_acceptance_note_model():
    note = build_risk_acceptance_note(finding_id="finding-001", accepted_by="owner", acceptance_reason="Temporary exception")

    assert note["acceptance_id"]
    assert note["finding_id"] == "finding-001"
    assert note["acceptance_reason"] == "Temporary exception"

