from scanner.prioritisation_trends import (
    build_finding_stable_key,
    build_prioritisation_trends,
    build_trend_finding,
)


def _finding(
    title: str,
    score: int,
    label: str,
    severity: str = "High",
    source: str = "cve_feed",
    port: int = 22,
) -> dict:
    return {
        "title": title,
        "source": source,
        "category": "Unit",
        "severity": severity,
        "affected_host": "127.0.0.1",
        "affected_port": port,
        "service": "ssh" if port == 22 else "http",
        "evidence": "Local unit evidence.",
        "priority_score": score,
        "priority_label": label,
    }


def test_build_stable_finding_key_consistently() -> None:
    first = build_finding_stable_key(_finding("A", 90, "Fix First"), "127.0.0.1")
    second = build_finding_stable_key(_finding("A", 50, "Monitor"), "127.0.0.1")

    assert first == second
    assert first.startswith("vs-priority-")


def test_detects_new_resolved_and_unchanged_findings() -> None:
    result = build_prioritisation_trends(
        target="127.0.0.1",
        current_prioritised_findings=[
            _finding("Persisting", 60, "Fix Soon"),
            _finding("New", 95, "Fix First", port=443),
        ],
        previous_scan={
            "scan_id": "scan-1",
            "scan_start_time": "2026-05-21T10:00:00+00:00",
            "prioritised_findings": [
                _finding("Persisting", 60, "Fix Soon"),
                _finding("Resolved", 80, "Fix First", port=80),
            ],
        },
    )
    trends = result["prioritisation_trends"]

    assert trends["status"] == "compared"
    assert trends["new_findings_count"] == 1
    assert trends["resolved_findings_count"] == 1
    assert trends["unchanged_findings_count"] == 1


def test_detects_priority_increased_decreased_and_label_changed() -> None:
    result = build_prioritisation_trends(
        target="target",
        current_prioritised_findings=[
            _finding("Increased", 90, "Fix First"),
            _finding("Decreased", 40, "Monitor", port=443),
        ],
        previous_scan={
            "scan_id": "scan-1",
            "scan_start_time": "2026-05-21T10:00:00+00:00",
            "prioritised_findings": [
                _finding("Increased", 50, "Monitor"),
                _finding("Decreased", 80, "Fix First", port=443),
            ],
        },
    )
    trends = result["prioritisation_trends"]

    assert trends["priority_increased_count"] == 1
    assert trends["priority_decreased_count"] == 1
    assert trends["priority_label_changed_count"] == 2
    assert result["prioritisation_trend_details"]["priority_increased"][0]["score_delta"] == 40


def test_detects_new_resolved_and_persisting_fix_first() -> None:
    result = build_prioritisation_trends(
        target="target",
        current_prioritised_findings=[
            _finding("Persisting Fix First", 90, "Fix First"),
            _finding("New Fix First", 95, "Fix First", port=443),
        ],
        previous_scan={
            "scan_id": "scan-1",
            "scan_start_time": "2026-05-21T10:00:00+00:00",
            "prioritised_findings": [
                _finding("Persisting Fix First", 90, "Fix First"),
                _finding("Resolved Fix First", 85, "Fix First", port=80),
            ],
        },
    )
    trends = result["prioritisation_trends"]

    assert trends["fix_first_new_count"] == 1
    assert trends["fix_first_resolved_count"] == 1
    assert trends["fix_first_persisting_count"] == 1


def test_calculates_average_and_highest_priority_delta() -> None:
    result = build_prioritisation_trends(
        target="target",
        current_prioritised_findings=[_finding("A", 90, "Fix First"), _finding("B", 50, "Monitor", port=443)],
        previous_scan={
            "scan_id": "scan-1",
            "scan_start_time": "2026-05-21T10:00:00+00:00",
            "prioritised_findings": [_finding("A", 80, "Fix First"), _finding("B", 40, "Monitor", port=443)],
        },
    )
    trends = result["prioritisation_trends"]

    assert trends["average_priority_delta"] == 10.0
    assert trends["highest_priority_delta"] == 10


def test_returns_baseline_when_no_previous_scan_exists() -> None:
    result = build_prioritisation_trends(
        target="target",
        current_prioritised_findings=[_finding("A", 90, "Fix First")],
        previous_scan=None,
    )
    trends = result["prioritisation_trends"]

    assert trends["status"] == "baseline"
    assert trends["risk_trend_label"] == "Baseline"
    assert trends["new_findings_count"] == 1


def test_risk_trend_worsened_when_new_fix_first_appears() -> None:
    result = build_prioritisation_trends(
        target="target",
        current_prioritised_findings=[_finding("New", 90, "Fix First")],
        previous_scan={"scan_id": "scan-1", "prioritised_findings": []},
    )

    assert result["prioritisation_trends"]["risk_trend_label"] == "Worsened"


def test_risk_trend_improved_when_fix_first_resolved_and_average_decreases() -> None:
    result = build_prioritisation_trends(
        target="target",
        current_prioritised_findings=[_finding("Lower", 30, "Monitor", port=443)],
        previous_scan={
            "scan_id": "scan-1",
            "prioritised_findings": [
                _finding("Resolved", 90, "Fix First"),
                _finding("Lower", 50, "Monitor", port=443),
            ],
        },
    )

    assert result["prioritisation_trends"]["risk_trend_label"] == "Improved"


def test_trend_finding_uses_standard_finding_model() -> None:
    compared = build_trend_finding("compared")
    baseline = build_trend_finding("baseline")

    assert compared.title == "Prioritisation Trend Analysis Completed"
    assert compared.source == "prioritisation_trends"
    assert baseline.title == "Prioritisation Trend Baseline Created"
