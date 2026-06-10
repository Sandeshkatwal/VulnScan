from scanner.access_control_retest import build_a01_retest_record, retest_summary


def test_retest_record_can_be_created():
    record = build_a01_retest_record(test_plan_id="demo-plan-001", retest_status="passed", retest_notes="Access remains denied after remediation")
    assert record["test_plan_id"] == "demo-plan-001"
    assert record["retest_status"] == "passed"


def test_retest_passed_updates_summary():
    record = build_a01_retest_record(test_plan_id="demo-plan-001", retest_status="passed")
    summary = retest_summary([record])
    assert summary["retest_passed_count"] == 1
    assert summary["retest_failed_count"] == 0
