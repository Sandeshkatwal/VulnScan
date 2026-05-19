from scanner.finding import Finding, create_finding
from scanner.web_passive_summary import (
    build_passive_risk_rating,
    build_recommended_next_steps,
    build_web_passive_summary,
    build_web_passive_summary_findings,
    count_web_findings_by_severity,
    get_highest_web_risk,
    get_web_findings,
)


def _finding(title: str, severity: str, source: str = "web_header_audit") -> Finding:
    return create_finding(
        title=title,
        severity=severity,  # type: ignore[arg-type]
        category="Web DAST",
        affected_url="https://example.test/",
        service="http",
        evidence="Fake passive indicator.",
        confidence="High",
        impact="Supports passive review.",
        recommendation="Review the fake passive indicator.",
        verification="Review fake test data.",
        limitation="Fake data only.",
        source=source,
    )


def test_build_summary_from_empty_web_findings() -> None:
    summary = build_web_passive_summary(start_url="https://example.test/", findings=[])

    assert summary["enabled"] is True
    assert summary["total_web_findings"] == 0
    assert summary["passive_risk_rating"] == "None"
    assert summary["recommended_next_steps"] == ["Continue with authorised deeper testing if in scope."]


def test_build_summary_from_header_findings() -> None:
    summary = build_web_passive_summary(
        start_url="https://example.test/",
        web_header_summary={"missing_header_counts": {"Content-Security-Policy": 1}},
        findings=[_finding("Missing Content-Security-Policy", "Medium")],
    )

    assert summary["missing_security_headers"] == 1
    assert summary["medium_risk_indicators"] == ["Missing Content-Security-Policy"]


def test_build_summary_from_cookie_findings() -> None:
    summary = build_web_passive_summary(
        start_url="https://example.test/",
        web_cookie_summary={"cookies_observed": 1, "cookies_missing_httponly": 1},
        findings=[_finding("Cookie Missing HttpOnly Flag", "Medium", "web_cookie_audit")],
    )

    assert summary["cookies_observed"] == 1
    assert summary["cookie_issues"] == 1


def test_build_summary_from_form_findings() -> None:
    summary = build_web_passive_summary(
        start_url="https://example.test/",
        web_form_summary={"forms_discovered": 2, "login_forms": 1, "upload_forms": 1},
        findings=[_finding("File Upload Form Discovered", "Low", "web_form_audit")],
    )

    assert summary["forms_discovered"] == 2
    assert summary["login_forms"] == 1
    assert summary["upload_forms"] == 1


def test_calculates_high_passive_risk_when_high_finding_exists() -> None:
    assert build_passive_risk_rating([_finding("Login Form Served Over HTTP", "High", "web_form_audit")]) == "High"


def test_calculates_medium_passive_risk_without_high() -> None:
    assert build_passive_risk_rating([_finding("Missing HSTS", "Medium")]) == "Medium"


def test_calculates_low_passive_risk() -> None:
    assert build_passive_risk_rating([_finding("External Form Action Discovered", "Low", "web_form_audit")]) == "Low"


def test_calculates_informational_passive_risk() -> None:
    assert build_passive_risk_rating([_finding("Web Crawl Completed", "Informational", "web_crawler")]) == "Informational"


def test_recommended_next_steps_for_missing_headers() -> None:
    steps = build_recommended_next_steps({"missing_security_headers": 1})

    assert "Review and implement missing security headers." in steps


def test_recommended_next_steps_for_cookie_issues() -> None:
    steps = build_recommended_next_steps({"cookie_issues": 1})

    assert "Review cookie flags for session and sensitive cookies." in steps


def test_recommended_next_steps_for_login_forms() -> None:
    steps = build_recommended_next_steps({"login_forms": 1})

    assert "Verify login forms use HTTPS and anti-automation controls." in steps


def test_recommended_next_steps_for_upload_forms() -> None:
    steps = build_recommended_next_steps({"upload_forms": 1})

    assert "Review file upload validation and storage controls." in steps


def test_summary_finding_uses_standard_finding_model() -> None:
    summary = build_web_passive_summary(start_url="https://example.test/", findings=[])
    findings = build_web_passive_summary_findings(summary)

    assert isinstance(findings[0], Finding)
    assert findings[0].title == "Web Passive Risk Summary Completed"
    assert findings[0].source == "web_passive_summary"


def test_helper_functions_group_web_sources_and_risk() -> None:
    findings = [
        _finding("Cookie Missing Secure Flag", "Medium", "web_cookie_audit"),
        _finding("Non-web", "High", "port_scan"),
    ]

    assert len(get_web_findings(findings)) == 1
    assert count_web_findings_by_severity(findings)["Medium"] == 1
    assert get_highest_web_risk(findings)["severity"] == "Medium"


def test_summary_findings_are_not_duplicated() -> None:
    summary = build_web_passive_summary(start_url="https://example.test/", findings=[])
    first = build_web_passive_summary_findings(summary)
    second = build_web_passive_summary_findings(summary, existing_findings=first)

    assert second == []
