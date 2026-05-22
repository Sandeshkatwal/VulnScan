from scanner.prioritisation_report import (
    build_dashboard_finding,
    build_fix_first_dashboard,
)


def _finding(
    title: str,
    score: int,
    label: str,
    severity: str = "High",
    source: str = "cve_feed",
    criticality: str = "critical",
    cvss: float | None = None,
    epss: float | None = None,
    exploit_available: bool = False,
    maturity: str = "none",
    active: bool = False,
) -> dict:
    details = {
        "exploit_available": exploit_available,
        "exploit_maturity": maturity,
        "active_exploitation_reported": active,
    }
    if cvss is not None:
        details["cvss_score"] = cvss
    if epss is not None:
        details["epss_score"] = epss
    return {
        "id": "FINDING-0001",
        "title": title,
        "source": source,
        "category": "Unit",
        "severity": severity,
        "priority_score": score,
        "priority_label": label,
        "asset_criticality": criticality,
        "affected_host": "127.0.0.1",
        "affected_port": 22,
        "evidence": "Local unit evidence.",
        "recommendation": "Apply the tested remediation.",
        "limitation": "Local fake data only.",
        "priority_reasons": ["Unit reason."],
        "evidence_details": details,
    }


def test_build_dashboard_from_prioritised_findings() -> None:
    result = build_fix_first_dashboard(
        target="127.0.0.1",
        findings=[_finding("A", 95, "Fix First")],
        prioritised_findings=[_finding("A", 95, "Fix First")],
        generated_at="2026-05-22T10:00:00+00:00",
    )

    dashboard = result["fix_first_dashboard"]
    assert dashboard["enabled"] is True
    assert dashboard["target"] == "127.0.0.1"
    assert dashboard["total_prioritised_findings"] == 1


def test_dashboard_handles_no_findings_gracefully() -> None:
    result = build_fix_first_dashboard(target="127.0.0.1", findings=[], prioritised_findings=[])

    assert result["fix_first_dashboard"]["total_prioritised_findings"] == 0
    assert result["top_fix_first_findings"] == []
    assert result["priority_distribution"]["by_label"]["Fix First"] == 0


def test_dashboard_counts_priority_labels() -> None:
    result = build_fix_first_dashboard(
        target="target",
        findings=[],
        prioritised_findings=[
            _finding("Fix first", 95, "Fix First"),
            _finding("Fix soon", 70, "Fix Soon"),
            _finding("Schedule", 50, "Schedule", severity="Medium", criticality="medium"),
            _finding("Monitor", 20, "Monitor", severity="Low", criticality="low"),
            _finding("Info", 5, "Informational", severity="Informational", criticality="unknown"),
        ],
    )

    dashboard = result["fix_first_dashboard"]
    assert dashboard["fix_first_count"] == 1
    assert dashboard["fix_soon_count"] == 2
    assert dashboard["monitor_count"] == 1
    assert dashboard["informational_count"] == 1


def test_top_fix_first_findings_sorted_by_priority_score_descending() -> None:
    result = build_fix_first_dashboard(
        target="target",
        findings=[],
        prioritised_findings=[
            _finding("Lower", 70, "Fix Soon"),
            _finding("Higher", 95, "Fix First"),
        ],
    )

    assert result["top_fix_first_findings"][0]["title"] == "Higher"
    assert result["top_fix_first_findings"][0]["rank"] == 1


def test_priority_distribution_by_severity_source_and_asset_criticality() -> None:
    result = build_fix_first_dashboard(
        target="target",
        findings=[],
        prioritised_findings=[
            _finding("Critical", 95, "Fix First", severity="Critical", source="cve_feed", criticality="critical"),
            _finding("Web", 45, "Schedule", severity="Medium", source="web_header_audit", criticality="medium"),
        ],
    )
    distribution = result["priority_distribution"]

    assert distribution["by_severity"]["Critical"] == 1
    assert distribution["by_severity"]["Medium"] == 1
    assert distribution["by_source"]["cve_feed"] == 1
    assert distribution["by_source"]["web_dast"] == 1
    assert distribution["by_asset_criticality"]["critical"] == 1
    assert distribution["by_asset_criticality"]["medium"] == 1


def test_remediation_action_plan_groups() -> None:
    result = build_fix_first_dashboard(
        target="target",
        findings=[],
        prioritised_findings=[
            _finding("Immediate", 95, "Fix First", cvss=9.8),
            _finding("Planned", 55, "Schedule", criticality="low"),
            _finding("Monitor", 25, "Monitor", severity="Low", criticality="low"),
            _finding("Info", 5, "Informational", severity="Informational", criticality="unknown"),
        ],
    )
    plan = result["remediation_action_plan"]

    assert plan["immediate_actions"][0]["title"] == "Immediate"
    assert plan["planned_actions"][0]["title"] == "Planned"
    assert plan["monitoring_actions"][0]["title"] == "Monitor"
    assert plan["informational_actions"][0]["title"] == "Info"


def test_executive_summary_text_is_generated() -> None:
    result = build_fix_first_dashboard(
        target="target",
        findings=[],
        prioritised_findings=[_finding("A", 95, "Fix First", epss=0.8, exploit_available=True)],
    )

    assert "VulScan prioritised 1 findings" in result["executive_summary"]
    assert "does not confirm exploitability" in result["executive_summary"]


def test_dashboard_finding_uses_standard_finding_model() -> None:
    finding = build_dashboard_finding()

    assert finding.title == "Fix-First Dashboard Generated"
    assert finding.severity == "Informational"
    assert finding.source == "prioritisation_report"
