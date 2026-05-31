from scanner.submission_tracker import (
    create_retest,
    create_submission,
    get_submission_summary,
    get_submission_timeline,
    list_submissions,
    update_payment,
    update_retest,
    update_submission_status,
    add_submission_note,
)


def test_create_list_update_and_timeline(tmp_path):
    db_path = tmp_path / "submissions.db"
    record = create_submission(report_id="REPORT_ID", program_name="Demo Program", platform="manual", status="draft", db_path=db_path)

    assert record["submission_id"]
    assert list_submissions(db_path=db_path)[0]["status"] == "draft"

    updated = update_submission_status(record["submission_id"], "submitted", note="Submitted through platform.", db_path=db_path)
    assert updated is not None
    assert updated["status"] == "submitted"

    events = get_submission_timeline(record["submission_id"], db_path=db_path)
    assert [event["event_type"] for event in events] == ["created", "status_changed"]


def test_notes_are_redacted(tmp_path):
    db_path = tmp_path / "submissions.db"
    record = create_submission(report_id="REPORT_ID", program_name="Demo", platform="manual", notes="token=abc123", db_path=db_path)

    assert "[REDACTED]" in record["notes"]
    assert record["safe_notes_redacted"] is True

    updated = add_submission_note(record["submission_id"], "Authorization: Bearer abcdefgh123456", db_path=db_path)
    assert updated is not None
    assert "[REDACTED]" in updated["notes"]


def test_create_and_update_retest(tmp_path):
    db_path = tmp_path / "submissions.db"
    submission = create_submission(report_id="REPORT_ID", program_name="Demo", platform="manual", db_path=db_path)
    retest = create_retest(submission_id=submission["submission_id"], status="retest_required", notes="Retest requested.", db_path=db_path)

    assert retest["status"] == "retest_required"

    updated = update_retest(
        retest["retest_id"],
        status="retest_passed",
        retest_result="issue_no_longer_reproducible",
        notes="Manual retest passed.",
        db_path=db_path,
    )
    assert updated is not None
    assert updated["status"] == "retest_passed"
    assert updated["retest_result"] == "issue_no_longer_reproducible"


def test_submission_summary_counts_and_bounty(tmp_path):
    db_path = tmp_path / "submissions.db"
    submission = create_submission(report_id="REPORT_ID", program_name="Demo", platform="manual", status="accepted", db_path=db_path)
    update_payment(submission["submission_id"], bounty_amount="100", bounty_currency="USD", status="paid", db_path=db_path)
    create_retest(submission_id=submission["submission_id"], status="retest_failed", db_path=db_path)

    summary = get_submission_summary(db_path=db_path)

    assert summary["total_count"] == 1
    assert summary["paid_count"] == 1
    assert summary["retest_failed_count"] == 1
    assert summary["total_bounty_amount_by_currency"]["USD"] == 100.0
