from datetime import datetime
from pathlib import Path

from scanner.owasp_mapping import (
    attach_owasp_metadata,
    build_owasp_summary,
    load_owasp_mapping,
    map_endpoint_to_owasp,
    map_finding_to_owasp,
    map_parameter_to_owasp,
)
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report


def test_loads_owasp_mapping_file() -> None:
    mapping = load_owasp_mapping()
    assert mapping["version"] == "2025"
    assert len(mapping["categories"]) == 10


def test_maps_missing_header_finding_to_a02() -> None:
    mapped = map_finding_to_owasp(_finding("Missing Security Header", "web_header_audit", "Headers", "Missing security header."))
    assert mapped[0]["owasp_id"] == "A02:2025"


def test_maps_cve_component_finding_to_a03() -> None:
    mapped = map_finding_to_owasp(_finding("Local CVE Match", "vuln_intel", "Vulnerability Intelligence", "CVE indicator for outdated component."))
    assert mapped[0]["owasp_id"] == "A03:2025"


def test_maps_cookie_indicator_to_a04_or_a07() -> None:
    mapped = map_finding_to_owasp(_finding("Cookie Missing Secure Flag", "web_cookie_audit", "Cookie Security", "Session cookie missing secure flag."))
    assert {item["owasp_id"] for item in mapped}.intersection({"A04:2025", "A07:2025"})


def test_maps_idor_parameter_candidate_to_a01() -> None:
    mapped = map_parameter_to_owasp({"parameter_name": "account_id", "parameter_type": "idor", "path": "/account"})
    assert mapped[0]["owasp_id"] == "A01:2025"


def test_redirect_parameter_is_mapped_carefully() -> None:
    mapped = map_parameter_to_owasp({"parameter_name": "next", "parameter_type": "redirect", "path": "/redirect"})
    assert mapped == []


def test_maps_search_query_parameter_to_a05() -> None:
    mapped = map_parameter_to_owasp({"parameter_name": "q", "parameter_type": "injection_reflection", "path": "/search"})
    assert mapped[0]["owasp_id"] == "A05:2025"


def test_maps_file_upload_endpoint_to_a08() -> None:
    mapped = map_endpoint_to_owasp({"path": "/upload", "endpoint_category": "file_upload"})
    assert mapped[0]["owasp_id"] == "A08:2025"


def test_leaves_unrelated_informational_finding_unmapped() -> None:
    mapped = map_finding_to_owasp(_finding("Scan Completed", "scanner", "Informational", "Safe scan completed."))
    assert mapped == []


def test_limits_mapped_categories_to_top_three() -> None:
    mapped = map_finding_to_owasp(
        _finding(
            "Debug CVE Login Search Upload Error",
            "web_cookie_audit",
            "Mixed",
            "debug cve login search upload stack trace missing security header",
        )
    )
    assert len(mapped) <= 3


def test_generates_summary_counts_and_gaps() -> None:
    summary = build_owasp_summary(
        [_finding("Missing Security Header", "web_header_audit", "Headers", "Missing security header.")],
        [{"path": "/upload", "endpoint_category": "file_upload"}],
        [{"parameter_name": "id", "parameter_type": "idor", "path": "/account"}],
    )
    assert summary["mapped_findings_count"] == 1
    assert summary["mapped_endpoint_candidates_count"] == 1
    assert summary["mapped_parameter_candidates_count"] == 1
    assert summary["coverage_gaps"]


def test_json_report_includes_owasp_summary(tmp_path: Path) -> None:
    scan_result = _scan_result()
    attach_owasp_metadata(scan_result)
    path = save_json_report(scan_result, "VulScan", "test", datetime.now(), datetime.now(), reports_dir=tmp_path)
    text = path.read_text(encoding="utf-8")
    assert '"owasp_top10_summary"' in text
    assert '"owasp_top10_mapped_items"' in text


def test_html_report_renders_owasp_section(tmp_path: Path) -> None:
    scan_result = _scan_result()
    attach_owasp_metadata(scan_result)
    path = save_html_report(scan_result, "VulScan", "test", datetime.now(), datetime.now(), reports_dir=tmp_path)
    assert "OWASP Top 10 Indicator Mapping" in path.read_text(encoding="utf-8")


def _finding(title: str, source: str, category: str, evidence: str) -> dict:
    return {
        "id": "FINDING-0001",
        "title": title,
        "severity": "Informational",
        "category": category,
        "evidence": evidence,
        "confidence": "Medium",
        "impact": "Indicator only.",
        "recommendation": "Review manually.",
        "verification": "Manual validation.",
        "limitation": "Indicator only.",
        "source": source,
        "risk_score": 0,
        "risk_label": "Informational",
    }


def _scan_result() -> dict:
    return {
        "host": "owasp-test",
        "resolved_ip": "",
        "scan_mode": "test",
        "duration_seconds": 0,
        "open_ports": [],
        "findings": [_finding("Missing Security Header", "web_header_audit", "Headers", "Missing security header.")],
        "endpoint_results": [{"path": "/upload", "endpoint_category": "file_upload"}],
        "parameter_results": [{"parameter_name": "id", "parameter_type": "idor", "path": "/account"}],
    }
