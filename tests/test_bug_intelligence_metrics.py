import json

from scanner.bug_intelligence_metrics import build_bug_intelligence_metrics, export_metrics
from scanner.database import get_connection, init_db


def _seed_metrics_db(db_path):
    init_db(db_path)
    rows = [
        ("sub_1", "rep_1", ["ev_1", "ev_2"], "IDOR in account endpoint", "Alpha", "accepted", "High", None, None, "2026-01-10T10:00:00+00:00", "2026-01-11T10:00:00+00:00", "2026-01-12T10:00:00+00:00", None, None),
        ("sub_2", "rep_2", ["ev_3"], "Security Misconfiguration header", "Alpha", "duplicate", "Medium", None, None, "2026-02-01T10:00:00+00:00", "2026-02-02T10:00:00+00:00", None, None, None),
        ("sub_3", "rep_3", [], "Open Redirect candidate", "Beta", "informative", "Low", None, None, "2026-03-01T10:00:00+00:00", "2026-03-02T10:00:00+00:00", None, None, None),
        ("sub_4", "rep_4", ["ev_4"], "IDOR profile access", "Beta", "paid", "High", "250", "USD", "2026-05-20T10:00:00+00:00", "2026-05-21T10:00:00+00:00", "2026-05-22T10:00:00+00:00", "2026-05-24T10:00:00+00:00", "2026-05-26T10:00:00+00:00"),
        ("sub_old", "rep_old", [], "Directory Listing", "Gamma", "not_applicable", "Low", None, None, "2025-01-01T10:00:00+00:00", None, None, None, None),
    ]
    with get_connection(db_path) as connection:
        for row in rows:
            connection.execute(
                """
                INSERT INTO security_submissions (
                    submission_id, report_id, evidence_ids_json, finding_title, program_name,
                    platform, status, severity_submitted, severity_accepted, duplicate_of,
                    bounty_amount, bounty_currency, submitted_at, triaged_at, accepted_at,
                    resolved_at, paid_at, notes, safe_notes_redacted, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'manual', ?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?, ?, 'Steps, impact, and remediation tracked locally.', 0, ?, ?)
                """,
                (
                    row[0],
                    row[1],
                    json.dumps(row[2]),
                    row[3],
                    row[4],
                    row[5],
                    row[6],
                    row[7],
                    row[8],
                    row[9],
                    row[10],
                    row[11],
                    row[12],
                    row[13],
                    row[9],
                    row[13] or row[12] or row[10] or row[9],
                ),
            )
        connection.execute(
            """
            INSERT INTO security_retests (
                retest_id, submission_id, report_id, target, affected_url, status,
                requested_at, retested_at, retest_result, evidence_id, notes, created_at, updated_at
            ) VALUES
                ('rt_1', 'sub_4', 'rep_4', 'demo.local', 'https://demo.local/a', 'retest_passed',
                 '2026-05-23T10:00:00+00:00', '2026-05-24T10:00:00+00:00', 'issue_no_longer_reproducible', 'ev_5', 'Passed', '2026-05-23T10:00:00+00:00', '2026-05-24T10:00:00+00:00'),
                ('rt_2', 'sub_2', 'rep_2', 'demo.local', 'https://demo.local/b', 'retest_failed',
                 '2026-02-03T10:00:00+00:00', '2026-02-04T10:00:00+00:00', 'issue_still_reproducible', 'ev_6', 'Failed', '2026-02-03T10:00:00+00:00', '2026-02-04T10:00:00+00:00')
            """
        )


def test_bug_intelligence_metrics_summary_counts_and_rates(tmp_path):
    db_path = tmp_path / "metrics.db"
    _seed_metrics_db(db_path)

    metrics = build_bug_intelligence_metrics(db_path=db_path)["bug_intelligence_metrics"]

    assert metrics["total_submissions"] == 5
    assert metrics["total_accepted"] == 2
    assert metrics["total_duplicates"] == 1
    assert metrics["acceptance_rate"] == 40.0
    assert metrics["duplicate_rate"] == 20.0
    assert metrics["total_bounty_by_currency"] == {"USD": 250.0}


def test_bug_intelligence_metrics_program_classes_monthly_outcomes_retests_quality(tmp_path):
    db_path = tmp_path / "metrics.db"
    _seed_metrics_db(db_path)

    metrics = build_bug_intelligence_metrics(db_path=db_path)["bug_intelligence_metrics"]

    alpha = next(row for row in metrics["top_programs"] if row["program_name"] == "Alpha")
    assert alpha["total_submissions"] == 2
    assert alpha["duplicates"] == 1
    assert alpha["acceptance_rate"] == 50.0

    classes = {row["class_name"]: row for row in metrics["top_vulnerability_classes"]}
    assert classes["IDOR"]["count"] == 2
    assert classes["IDOR"]["accepted_count"] == 2

    months = {row["month"]: row for row in metrics["monthly_activity"]}
    assert months["2026-05"]["paid"] == 1
    assert months["2026-05"]["retests_completed"] == 1

    outcomes = {row["outcome"]: row["count"] for row in metrics["outcome_distribution"]}
    assert outcomes["duplicate"] == 1
    assert metrics["retest_passed_count"] == 1
    assert metrics["retest_failed_count"] == 1
    assert 0 <= metrics["quality_indicators"]["score"] <= 100


def test_bug_intelligence_metrics_date_range_and_export_json(tmp_path):
    db_path = tmp_path / "metrics.db"
    _seed_metrics_db(db_path)

    metrics = build_bug_intelligence_metrics(range_name="custom", start_date="2026-05-01", end_date="2026-05-31", db_path=db_path)["bug_intelligence_metrics"]
    assert metrics["total_submissions"] == 1
    assert metrics["total_paid"] == 1

    exported = json.loads(export_metrics(format_name="json", db_path=db_path))
    assert exported["summary"]["total_submissions"] == 5
    assert "program_performance" in exported
    assert "vulnerability_classes" in exported
    assert "monthly_activity" in exported
    assert "outcome_distribution" in exported
