from scanner.retest_summary import build_retest_summary, update_finding_retest_status


def test_retest_summary_and_update():
    finding = {"finding_id": "finding-001", "status": "ready_for_review", "validation_status": "manually_verified_issue"}
    updated = update_finding_retest_status(finding, {"retest_status": "retest_passed", "retest_notes": "Fixed."})
    summary = build_retest_summary([updated])

    assert updated["status"] == "remediated"
    assert summary["passed"] == 1

