import json
from datetime import datetime, timezone

from scanner.duplicate_detection import check_duplicate, duplicate_summary, get_duplicate_group
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report
from scanner.submission_tracker import create_submission


def test_same_host_path_issue_parameter_is_exact_duplicate(tmp_path) -> None:
    db_path = tmp_path / "duplicates.db"
    first = check_duplicate(
        {"url": "http://127.0.0.1:8000/account?id=123", "issue_type": "idor_candidate", "parameter_names": ["id"]},
        db_path=db_path,
    )
    second = check_duplicate(
        {"url": "http://127.0.0.1:8000/account?id=456", "issue_type": "idor_candidate", "parameter_names": ["id"]},
        db_path=db_path,
    )

    assert first["duplicate_result"]["duplicate_status"] == "unique"
    assert second["duplicate_result"]["duplicate_status"] == "exact_duplicate"
    assert second["duplicate_result"]["duplicate_confidence"] == "Exact"


def test_same_host_path_issue_overlapping_parameters_is_likely_duplicate(tmp_path) -> None:
    db_path = tmp_path / "duplicates.db"
    check_duplicate(
        {"url": "http://127.0.0.1:8000/account?id=123&view=full", "issue_type": "idor_candidate", "parameter_names": ["id", "view"]},
        db_path=db_path,
    )
    result = check_duplicate(
        {"url": "http://127.0.0.1:8000/account?id=456", "issue_type": "idor_candidate", "parameter_names": ["id"]},
        db_path=db_path,
    )

    assert result["duplicate_result"]["duplicate_status"] == "likely_duplicate"
    assert result["duplicate_result"]["duplicate_confidence"] == "High"


def test_same_host_issue_different_path_is_related(tmp_path) -> None:
    db_path = tmp_path / "duplicates.db"
    check_duplicate(
        {"url": "http://127.0.0.1:8000/account?id=123", "issue_type": "idor_candidate", "parameter_names": ["id"], "source": "endpoint_discovery"},
        db_path=db_path,
    )
    result = check_duplicate(
        {"url": "http://127.0.0.1:8000/profile?id=456", "issue_type": "idor_candidate", "parameter_names": ["id"], "source": "endpoint_discovery"},
        db_path=db_path,
    )

    assert result["duplicate_result"]["duplicate_status"] == "related"
    assert result["duplicate_result"]["duplicate_confidence"] == "Medium"


def test_different_issue_types_are_unique(tmp_path) -> None:
    db_path = tmp_path / "duplicates.db"
    check_duplicate(
        {"url": "http://127.0.0.1:8000/account?id=123", "issue_type": "idor_candidate", "parameter_names": ["id"]},
        db_path=db_path,
    )
    result = check_duplicate(
        {"url": "http://127.0.0.1:8000/account?id=456", "issue_type": "open_redirect_candidate", "parameter_names": ["id"]},
        db_path=db_path,
    )

    assert result["duplicate_result"]["duplicate_status"] == "unique"


def test_duplicate_group_is_created_and_members_are_stored(tmp_path) -> None:
    db_path = tmp_path / "duplicates.db"
    check_duplicate(
        {"url": "http://127.0.0.1:8000/account?id=123", "issue_type": "idor_candidate", "parameter_names": ["id"]},
        db_path=db_path,
    )
    result = check_duplicate(
        {"url": "http://127.0.0.1:8000/account?id=456", "issue_type": "idor_candidate", "parameter_names": ["id"]},
        db_path=db_path,
    )
    group_id = result["duplicate_result"]["duplicate_group_id"]
    group = get_duplicate_group(group_id, db_path=db_path)
    summary = duplicate_summary(db_path=db_path)

    assert group is not None
    assert len(group["members"]) >= 2
    assert summary["exact_duplicates"] >= 1
    assert summary["duplicate_groups_count"] >= 1


def test_submission_creation_returns_duplicate_warning_metadata(tmp_path) -> None:
    db_path = tmp_path / "duplicates.db"
    first = create_submission(report_id="report-1", finding_title="IDOR Candidate", program_name="Demo Program", db_path=db_path)
    second = create_submission(report_id="report-2", finding_title="IDOR Candidate", program_name="Demo Program", db_path=db_path)

    assert first["duplicate_result"]["duplicate_status"] == "unique"
    assert second["duplicate_result"]["duplicate_status"] in {"exact_duplicate", "likely_duplicate", "related"}


def test_reports_include_duplicate_detection_summary(tmp_path) -> None:
    now = datetime.now(timezone.utc)
    scan_result = {
        "host": "127.0.0.1",
        "target": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "scan_mode": "test",
        "duration_seconds": 0,
        "open_ports": [],
        "findings": [],
        "duplicate_detection_summary": {
            "enabled": True,
            "total_fingerprints": 2,
            "exact_duplicates": 1,
            "likely_duplicates": 0,
            "related_findings": 0,
            "limitations": ["Metadata-only duplicate indicator."],
        },
    }

    json_path = save_json_report(scan_result, "VulScan", "18.8-test", now, now, reports_dir=tmp_path)
    html_path = save_html_report(scan_result, "VulScan", "18.8-test", now, now, reports_dir=tmp_path)

    assert json.loads(json_path.read_text(encoding="utf-8"))["duplicate_detection_summary"]["enabled"] is True
    assert "Duplicate Detection and Finding Fingerprinting" in html_path.read_text(encoding="utf-8")
