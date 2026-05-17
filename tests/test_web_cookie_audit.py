import json
from datetime import datetime, timezone

from scanner.finding import Finding, assign_sequential_finding_ids
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report
from scanner.web_cookie_audit import audit_web_cookies, parse_set_cookie_headers


def _page(url: str, cookies: list[dict[str, object]]) -> dict[str, object]:
    return {"url": url, "status_code": 200, "cookies": cookies}


def test_parse_set_cookie_without_storing_value() -> None:
    cookies = parse_set_cookie_headers(
        ["SESSIONID=NeverStoreValue; Path=/; HttpOnly; SameSite=Lax"],
        "https://example.test/login",
    )

    assert cookies[0]["name"] == "SESSIONID"
    assert cookies[0]["path"] == "/"
    assert cookies[0]["httponly"] is True
    assert cookies[0]["samesite"] == "Lax"
    assert "NeverStoreValue" not in str(cookies)


def test_detects_missing_secure() -> None:
    cookies = parse_set_cookie_headers(["SESSIONID=fake; Path=/; HttpOnly; SameSite=Lax"], "https://example.test/")
    result = audit_web_cookies([_page("https://example.test/", cookies)])

    finding = next(finding for finding in result["findings"] if finding.title == "Cookie Missing Secure Flag")
    assert finding.severity == "Medium"
    assert result["web_cookie_summary"]["cookies_missing_secure"] == 1


def test_detects_missing_httponly() -> None:
    cookies = parse_set_cookie_headers(["SESSIONID=fake; Secure; SameSite=Lax"], "https://example.test/")
    result = audit_web_cookies([_page("https://example.test/", cookies)])

    assert any(finding.title == "Cookie Missing HttpOnly Flag" for finding in result["findings"])


def test_detects_missing_samesite() -> None:
    cookies = parse_set_cookie_headers(["SESSIONID=fake; Secure; HttpOnly"], "https://example.test/")
    result = audit_web_cookies([_page("https://example.test/", cookies)])

    assert any(finding.title == "Cookie Missing SameSite Attribute" for finding in result["findings"])


def test_detects_samesite_none_without_secure() -> None:
    cookies = parse_set_cookie_headers(["SESSIONID=fake; HttpOnly; SameSite=None"], "https://example.test/")
    result = audit_web_cookies([_page("https://example.test/", cookies)])

    assert any(finding.title == "Cookie SameSite=None Without Secure" for finding in result["findings"])


def test_detects_persistent_cookie_with_missing_security_flags() -> None:
    cookies = parse_set_cookie_headers(
        ["prefs=fake; Max-Age=3600; Path=/; Secure"],
        "https://example.test/",
    )
    result = audit_web_cookies([_page("https://example.test/", cookies)])

    assert any(finding.title == "Persistent Cookie Without Security Flags" for finding in result["findings"])
    assert result["web_cookie_summary"]["persistent_cookie_issues"] == 1


def test_deduplicates_same_cookie_issue_across_urls() -> None:
    first = parse_set_cookie_headers(["SESSIONID=fake; Path=/"], "https://example.test/login")
    second = parse_set_cookie_headers(["SESSIONID=fake; Path=/"], "https://example.test/account")

    result = audit_web_cookies(
        [
            _page("https://example.test/login", first),
            _page("https://example.test/account", second),
        ]
    )

    httponly_findings = [finding for finding in result["findings"] if finding.title == "Cookie Missing HttpOnly Flag"]
    assert len(httponly_findings) == 1
    assert "on 2 pages" in httponly_findings[0].evidence


def test_builds_web_cookie_summary_and_standard_findings() -> None:
    cookies = parse_set_cookie_headers(["SESSIONID=fake; Path=/"], "https://example.test/")
    result = audit_web_cookies([_page("https://example.test/", cookies)])
    summary = result["web_cookie_summary"]

    assert summary["enabled"] is True
    assert summary["pages_checked"] == 1
    assert summary["cookies_observed"] == 1
    assert summary["unique_cookie_names"] == 1
    assert summary["findings_count"] == len(result["findings"])
    assert all(isinstance(finding, Finding) for finding in result["findings"])


def test_cookie_values_not_in_json_output(tmp_path) -> None:
    secret_value = "NeverStoreValue"
    cookies = parse_set_cookie_headers([f"SESSIONID={secret_value}; Path=/"], "https://example.test/")
    cookie_result = audit_web_cookies([_page("https://example.test/", cookies)])
    findings = assign_sequential_finding_ids(cookie_result["findings"])
    scan_result = _scan_result(cookie_result, findings)

    path = save_json_report(
        scan_result=scan_result,
        scanner_name="VulScan",
        scanner_version="test",
        scan_start_time=datetime.now(timezone.utc),
        scan_end_time=datetime.now(timezone.utc),
        reports_dir=tmp_path,
    )
    report = json.loads(path.read_text(encoding="utf-8"))

    assert secret_value not in path.read_text(encoding="utf-8")
    assert report["web_cookie_results"][0]["cookie_name"] == "SESSIONID"


def test_cookie_values_not_in_html_output(tmp_path) -> None:
    secret_value = "NeverStoreValue"
    cookies = parse_set_cookie_headers([f"SESSIONID={secret_value}; Path=/"], "https://example.test/")
    cookie_result = audit_web_cookies([_page("https://example.test/", cookies)])
    findings = assign_sequential_finding_ids(cookie_result["findings"])
    scan_result = _scan_result(cookie_result, findings)

    path = save_html_report(
        scan_result=scan_result,
        scanner_name="VulScan",
        scanner_version="test",
        scan_start_time=datetime.now(timezone.utc),
        scan_end_time=datetime.now(timezone.utc),
        reports_dir=tmp_path,
    )
    html = path.read_text(encoding="utf-8")

    assert secret_value not in html
    assert "SESSIONID" in html


def _scan_result(cookie_result: dict[str, object], findings: list[dict[str, object]]) -> dict[str, object]:
    return {
        "host": "example.test",
        "resolved_ip": "",
        "scan_mode": "web-dast",
        "duration_seconds": 0.1,
        "open_ports": [],
        "findings": findings,
        "http_findings": [],
        "tls_findings": [],
        "ssh_findings": [],
        "windows_findings": [],
        "web_findings": findings,
        "ssh_audit": {"enabled": False, "status": "skipped"},
        "ssh_audit_summary": {"enabled": False, "status": "skipped"},
        "windows_audit_summary": {"enabled": False, "status": "skipped"},
        "windows_audit_sections": [],
        "credentialed_audits": [],
        "web_scan_summary": {
            "enabled": True,
            "start_url": "https://example.test/",
            "allowed_host": "example.test",
            "pages_crawled": 1,
            "pages_skipped": 0,
            "forms_discovered": 0,
            "password_forms_discovered": 0,
            "file_upload_forms_discovered": 0,
            "unique_external_links": 0,
            "errors_count": 0,
            "duration_seconds": 0.1,
            "limitations": [],
        },
        "web_header_summary": {"enabled": False, "status": "skipped"},
        "web_header_results": [],
        "web_cookie_summary": cookie_result["web_cookie_summary"],
        "web_cookie_results": cookie_result["web_cookie_results"],
        "crawled_pages": [],
        "discovered_forms": [],
    }
