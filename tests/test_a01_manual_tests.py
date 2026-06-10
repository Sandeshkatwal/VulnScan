import pytest

from scanner.a01_manual_tests import A01ManualTestError, build_a01_observation


def test_a01_observation_records_redacted_summary():
    observation = build_a01_observation(
        test_plan_id="demo-plan-001",
        observed_access_result="denied_as_expected",
        observed_status_code=403,
        observed_message_summary="Access denied for Standard User as expected",
    )
    assert observation["redaction_status"] == "redacted"
    assert observation["observed_status_code"] == 403


def test_a01_observation_rejects_bad_evidence_path():
    with pytest.raises(A01ManualTestError):
        build_a01_observation(
            test_plan_id="demo-plan-001",
            observed_access_result="denied_as_expected",
            evidence_file_path="C:/Windows/not-allowed.txt",
        )
