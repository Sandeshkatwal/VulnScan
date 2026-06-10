from pathlib import Path

import pytest

from scanner.parameter_review_workflow import build_parameter_replay_observation, build_parameter_replay_retest, build_replay_evidence_checklist, build_report_ready_replay_template


def test_evidence_checklist_generated() -> None:
    checklist = build_replay_evidence_checklist("demo-replay-001")
    assert checklist["replay_plan_id"] == "demo-replay-001"
    assert any(item["item"] == "No secrets included." for item in checklist["items"])


def test_observation_denied_and_unexpectedly_allowed_recorded() -> None:
    denied = build_parameter_replay_observation(replay_plan_id="p1", observed_access_result="denied_as_expected", observed_status_code=403, observed_message_summary="Access denied for standard_user as expected")
    allowed = build_parameter_replay_observation(replay_plan_id="p1", observed_access_result="unexpectedly_allowed", observed_status_code=200, observed_message_summary="Unexpectedly allowed for approved test object label")
    assert denied["redaction_status"] == "redacted"
    assert allowed["observed_access_result"] == "unexpectedly_allowed"


def test_evidence_path_must_stay_under_parameter_replay_evidence() -> None:
    with pytest.raises(ValueError):
        build_parameter_replay_observation(replay_plan_id="p1", observed_access_result="inconclusive", evidence_file_path=str(Path("reports") / "other" / "evidence.txt"))


def test_report_template_candidate_and_issue_wording() -> None:
    plan = {"title": "Object Ownership Review: user_id", "parameter_name": "user_id", "affected_url": "http://127.0.0.1/users/{id}", "manual_steps": ["Use authorised test accounts only."], "related_owasp_categories": ["A01"]}
    candidate = build_report_ready_replay_template(plan)
    issue = build_report_ready_replay_template(plan, {"observed_access_result": "unexpectedly_allowed", "observed_message_summary": "Unexpected access recorded with approved test labels."})
    assert candidate["Title"].startswith("Replay Plan:")
    assert issue["Title"].startswith("Manually Verified Parameter Replay Issue:")


def test_retest_record_created() -> None:
    retest = build_parameter_replay_retest(replay_plan_id="p1", retest_status="passed", retest_notes="Parameter access remains denied after remediation")
    assert retest["retest_status"] == "passed"
