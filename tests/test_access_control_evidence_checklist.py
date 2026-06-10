from scanner.access_control_evidence_checklist import build_evidence_checklist, evidence_checklist_summary


def test_evidence_checklist_generated():
    checklist = build_evidence_checklist("demo-plan-001")
    assert checklist["test_plan_id"] == "demo-plan-001"
    assert len(checklist["items"]) >= 10
    assert checklist["items"][0]["status"] == "pending"


def test_evidence_checklist_summary_counts_items():
    checklist = build_evidence_checklist("demo-plan-001")
    checklist["items"][0]["status"] = "completed"
    summary = evidence_checklist_summary([checklist])
    assert summary["checklist_count"] == 1
    assert summary["completed_count"] == 1
