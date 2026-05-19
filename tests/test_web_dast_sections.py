from scanner.finding import create_finding
from scanner.web_report_summary import build_web_dast_sections


def test_web_dast_sections_mark_enabled_modules_success() -> None:
    finding = create_finding(
        title="Cookie Flag Indicator",
        severity="Low",
        category="Web Cookie Audit",
        evidence="Fake cookie metadata.",
        confidence="High",
        impact="Used by unit tests.",
        recommendation="Review cookie flags.",
        verification="Unit test only.",
        limitation="Fake data only.",
        source="web_cookie_audit",
    )

    sections = build_web_dast_sections(
        web_cookie_summary={
            "enabled": True,
            "cookies_observed": 2,
            "unique_cookie_names": 1,
            "cookies_missing_secure": 1,
            "cookies_missing_samesite": 0,
        },
        findings=[finding],
    )

    cookie_section = next(section for section in sections if section["section_id"] == "web_cookies")

    assert cookie_section["status"] == "success"
    assert cookie_section["enabled"] is True
    assert cookie_section["key_metrics"]["cookies_observed"] == 2
    assert cookie_section["findings_count"] == 1


def test_web_dast_sections_mark_missing_modules_skipped() -> None:
    sections = build_web_dast_sections(findings=[])

    assert all(section["status"] == "skipped" for section in sections)
    assert all(section["enabled"] is False for section in sections)


def test_web_dast_sections_mark_partial_when_summary_has_errors() -> None:
    sections = build_web_dast_sections(
        web_scan_summary={
            "enabled": True,
            "pages_crawled": 1,
            "errors_count": 1,
            "forms_discovered": 0,
            "unique_external_links": 0,
        },
        web_sitemap_summary={
            "enabled": True,
            "sitemap_urls_fetched": 1,
            "sitemap_urls_failed": 1,
            "url_entries_found": 0,
        },
        findings=[],
    )

    crawler_section = next(section for section in sections if section["section_id"] == "web_crawler")
    sitemap_section = next(section for section in sections if section["section_id"] == "web_sitemap")

    assert crawler_section["status"] == "partial"
    assert sitemap_section["status"] == "partial"
