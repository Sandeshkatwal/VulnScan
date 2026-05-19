from scanner.finding import Finding, create_finding, finding_to_dict
from scanner.web_report_summary import (
    build_web_dast_sections,
    build_web_dast_summary,
    build_web_recommended_next_steps,
    build_web_report_consolidation_finding,
    count_web_findings_by_severity,
    get_highest_web_risk,
    get_web_findings,
)


def _finding(*, title: str, severity: str, source: str = "web_header_audit") -> Finding:
    return create_finding(
        title=title,
        severity=severity,
        category="Web DAST",
        evidence="Fake passive indicator.",
        confidence="High",
        impact="Used by unit tests.",
        recommendation="Review the passive indicator.",
        verification="Unit test only.",
        limitation="Fake data only.",
        source=source,
    )


def test_build_web_dast_summary_from_available_summaries() -> None:
    findings = [_finding(title="Missing Header", severity="Medium")]
    sections = build_web_dast_sections(
        web_scope_summary={"enabled": True, "same_host_only": True, "total_skipped_urls": 0},
        web_scan_summary={"enabled": True, "pages_crawled": 2, "forms_discovered": 1},
        web_header_summary={"enabled": True, "missing_header_counts": {"Content-Security-Policy": 1}},
        findings=findings,
    )

    summary = build_web_dast_summary(
        start_url="https://example.test/",
        web_dast_sections=sections,
        web_scan_summary={"enabled": True, "pages_crawled": 2, "forms_discovered": 1},
        web_header_summary={"enabled": True, "missing_header_counts": {"Content-Security-Policy": 1}},
        findings=findings,
    )

    assert summary["enabled"] is True
    assert summary["mode"] == "passive"
    assert summary["pages_crawled"] == 2
    assert summary["forms_discovered"] == 1
    assert summary["total_web_findings"] == 1
    assert "Review and implement missing security headers." in summary["recommended_next_steps"]


def test_build_web_dast_summary_handles_missing_optional_summaries() -> None:
    sections = build_web_dast_sections(findings=[])
    summary = build_web_dast_summary(start_url="https://example.test/", web_dast_sections=sections, findings=[])

    assert summary["start_url"] == "https://example.test/"
    assert summary["robots_found"] == "unknown"
    assert summary["sections_enabled"] == []
    assert summary["total_web_findings"] == 0
    assert summary["passive_risk_rating"] == "None"


def test_counts_only_web_related_findings() -> None:
    findings = [
        _finding(title="Web", severity="Low", source="web_cookie_audit"),
        _finding(title="Non-web", severity="High", source="port_scan"),
    ]

    assert len(get_web_findings(findings)) == 1
    counts = count_web_findings_by_severity(findings)
    assert counts["Low"] == 1
    assert counts["High"] == 0


def test_get_highest_web_risk() -> None:
    findings = [
        _finding(title="Low Web", severity="Low", source="web_form_audit"),
        _finding(title="High Web", severity="High", source="web_header_audit"),
    ]

    highest = get_highest_web_risk(findings)

    assert highest["score"] >= 70
    assert highest["title"] == "High Web"


def test_recommended_next_steps_from_cookie_and_form_issues() -> None:
    steps = build_web_recommended_next_steps(
        web_cookie_summary={"enabled": True, "cookies_missing_samesite": 1},
        web_form_summary={"enabled": True, "login_forms": 1, "upload_forms": 1},
    )

    assert "Review cookie flags for sensitive/session cookies." in steps
    assert "Verify HTTPS, CSRF protections, and anti-automation controls for login forms." in steps
    assert "Review upload validation and storage controls." in steps


def test_recommended_next_steps_from_robots_and_sitemap_scope_indicators() -> None:
    steps = build_web_recommended_next_steps(
        web_robots_summary={"enabled": True, "urls_skipped_by_robots": 1},
        web_sitemap_summary={"enabled": True, "out_of_scope_urls": 1},
    )

    assert "Confirm written authorisation before testing robots-disallowed areas." in steps
    assert "Review scope before including additional sitemap hosts or paths." in steps


def test_recommended_next_steps_from_request_errors_and_high_risk() -> None:
    steps = build_web_recommended_next_steps(
        summary={"passive_risk_rating": "High"},
        web_politeness_summary={"enabled": True, "request_errors": 2},
    )

    assert "Review target availability and reduce scan speed if needed." in steps
    assert "Manually review high-priority web findings before active testing." in steps


def test_consolidation_finding_uses_standard_model_and_deduplicates() -> None:
    findings = build_web_report_consolidation_finding()

    assert len(findings) == 1
    assert isinstance(findings[0], Finding)
    finding = finding_to_dict(findings[0])
    assert finding["title"] == "Web DAST Passive Report Consolidated"
    assert finding["source"] == "web_passive_summary"
    assert finding["severity"] == "Informational"
    assert build_web_report_consolidation_finding(existing_findings=findings) == []
