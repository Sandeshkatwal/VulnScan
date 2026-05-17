from scanner.finding import Finding
from scanner.web_header_audit import audit_web_headers


def _page(
    url: str,
    headers: dict[str, str] | None = None,
    cookie_flags: list[dict[str, bool]] | None = None,
) -> dict[str, object]:
    return {
        "url": url,
        "status_code": 200,
        "response_headers": headers or {},
        "cookie_flags": cookie_flags or [],
    }


def test_detects_missing_csp() -> None:
    result = audit_web_headers([_page("https://example.test/", {"Strict-Transport-Security": "max-age=31536000"})])

    assert "Content-Security-Policy" in result["web_header_summary"]["missing_header_counts"]
    assert any(finding.title == "Missing Content-Security-Policy" for finding in result["findings"])


def test_detects_missing_hsts_on_https() -> None:
    result = audit_web_headers([_page("https://example.test/", {"Content-Security-Policy": "default-src 'self'"})])

    finding = next(finding for finding in result["findings"] if finding.title == "Missing Strict-Transport-Security")
    assert finding.severity == "Medium"


def test_does_not_flag_hsts_on_http_as_medium() -> None:
    result = audit_web_headers([_page("http://example.test/", {})])

    assert all(finding.title != "Missing Strict-Transport-Security" for finding in result["findings"])


def test_detects_server_header_disclosure() -> None:
    result = audit_web_headers([_page("https://example.test/", {"Server": "ExampleServer"})])

    assert any(finding.title == "Server Header Disclosure" for finding in result["findings"])
    assert result["web_header_summary"]["disclosure_header_counts"]["Server"] == 1


def test_detects_x_powered_by_disclosure() -> None:
    result = audit_web_headers([_page("https://example.test/", {"X-Powered-By": "ExampleFramework"})])

    finding = next(finding for finding in result["findings"] if finding.title == "X-Powered-By Header Disclosure")
    assert finding.severity == "Low"


def test_detects_cookie_missing_secure_on_https() -> None:
    result = audit_web_headers(
        [_page("https://example.test/", cookie_flags=[{"secure": False, "httponly": True, "samesite": True}])]
    )

    assert any(finding.title == "Cookie Missing Secure Flag" for finding in result["findings"])


def test_detects_cookie_missing_httponly() -> None:
    result = audit_web_headers(
        [_page("https://example.test/", cookie_flags=[{"secure": True, "httponly": False, "samesite": True}])]
    )

    assert any(finding.title == "Cookie Missing HttpOnly Flag" for finding in result["findings"])


def test_detects_cookie_missing_samesite() -> None:
    result = audit_web_headers(
        [_page("https://example.test/", cookie_flags=[{"secure": True, "httponly": True, "samesite": False}])]
    )

    assert any(finding.title == "Cookie Missing SameSite Flag" for finding in result["findings"])


def test_deduplicates_missing_header_findings_across_pages() -> None:
    result = audit_web_headers(
        [
            _page("https://example.test/one", {}),
            _page("https://example.test/two", {}),
        ]
    )

    csp_findings = [finding for finding in result["findings"] if finding.title == "Missing Content-Security-Policy"]
    assert len(csp_findings) == 1
    assert "Affected pages: 2 of 2" in csp_findings[0].evidence
    assert result["web_header_summary"]["missing_header_counts"]["Content-Security-Policy"] == 2


def test_builds_web_header_summary_and_standard_findings() -> None:
    result = audit_web_headers([_page("https://example.test/", {})])
    summary = result["web_header_summary"]

    assert summary["enabled"] is True
    assert summary["pages_checked"] == 1
    assert "Strict-Transport-Security" in summary["headers_checked"]
    assert summary["findings_count"] == len(result["findings"])
    assert all(isinstance(finding, Finding) for finding in result["findings"])
