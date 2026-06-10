from pathlib import Path

import pytest

from scanner.business_logic_retest import build_business_logic_observation, build_business_logic_retest


def test_business_logic_observations_recorded() -> None:
    expected = build_business_logic_observation(review_plan_id="p1", observed_result="behaved_as_expected", observed_message_summary="Workflow behaved as expected using approved test data")
    issue = build_business_logic_observation(review_plan_id="p1", observed_result="unexpected_success", observed_message_summary="Unexpected success with approved test labels")
    assert expected["redaction_status"] == "redacted"
    assert issue["observed_result"] == "unexpected_success"


def test_business_logic_evidence_path_constrained() -> None:
    with pytest.raises(ValueError):
        build_business_logic_observation(review_plan_id="p1", observed_result="inconclusive", evidence_file_path=str(Path("reports") / "other" / "evidence.txt"))


def test_business_logic_retest_record_created() -> None:
    retest = build_business_logic_retest(review_plan_id="p1", retest_status="passed", retest_notes="Workflow control still enforced after remediation")
    assert retest["retest_status"] == "passed"
