from datetime import datetime
from pathlib import Path

from scanner.endpoint_discovery import (
    classify_endpoint,
    deduplicate_urls,
    extract_url_components,
    load_url_list,
    normalise_url,
    run_endpoint_discovery,
    score_endpoint,
)
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report


def test_load_url_file() -> None:
    urls = load_url_list("data/bug_bounty/endpoints/sample_urls.txt")
    assert "http://127.0.0.1:8000/login" in urls
    assert "/uploads" in urls


def test_normalise_url_removes_fragment_and_supports_base_url() -> None:
    assert normalise_url("/uploads?file=demo#section", base_url="http://127.0.0.1:8000") == "http://127.0.0.1:8000/uploads?file=demo"


def test_canonicalisation_sorts_query_parameters() -> None:
    result = run_endpoint_discovery(["http://127.0.0.1:8000/account?b=2&a=1"], input_source="test")
    assert result["endpoint_results"][0]["normalised_url"] == "http://127.0.0.1:8000/account?a=1&b=2"


def test_deduplicates_same_path_and_parameter_names() -> None:
    urls = deduplicate_urls([
        "http://127.0.0.1:8000/account?id=123",
        "http://127.0.0.1:8000/account?id=456",
    ])
    assert urls == ["http://127.0.0.1:8000/account?id=123"]


def test_redacts_sensitive_parameter_values() -> None:
    components = extract_url_components("http://127.0.0.1:8000/reset-password?token=secret-demo")
    assert components["parameters"][0]["name"] == "token"
    assert components["parameters"][0]["value"] == "REDACTED"
    assert components["parameters"][0]["value_redacted"] is True
    result = run_endpoint_discovery(["http://127.0.0.1:8000/reset-password?token=secret-demo"], input_source="test")
    assert "secret-demo" not in result["endpoint_results"][0]["normalised_url"]


def test_classifies_endpoint_categories() -> None:
    assert classify_endpoint("/admin") == "admin"
    assert classify_endpoint("/api/v1/users") == "api_endpoint"
    assert classify_endpoint("/login") == "authentication"


def test_scores_high_interest_endpoint() -> None:
    score, reasons = score_endpoint(
        "admin",
        [
            {"name": "account_id", "value": "123", "value_redacted": False},
            {"name": "token", "value": "REDACTED", "value_redacted": True},
        ],
        True,
    )
    assert score >= 60
    assert "Admin endpoint indicator" in reasons


def test_enforce_scope_skips_out_of_scope_url() -> None:
    result = run_endpoint_discovery(
        ["https://payments.demo-web.local/account?id=1"],
        scope_file="data/bug_bounty/sample_program_scope.json",
        enforce_scope=True,
        input_source="test",
    )
    assert result["endpoint_discovery"]["skipped_urls_count"] == 1
    assert result["endpoint_results"] == []


def test_generates_summary_counts() -> None:
    result = run_endpoint_discovery(
        [
            "http://127.0.0.1:8000/account?id=123",
            "http://127.0.0.1:8000/redirect?next=/dashboard",
            "http://127.0.0.1:8000/static/app.js",
        ],
        scope_file="data/bug_bounty/sample_program_scope.json",
        enforce_scope=False,
        input_source="test",
    )
    summary = result["endpoint_discovery"]
    assert summary["input_urls_count"] == 3
    assert summary["interesting_parameters_count"] >= 2
    assert summary["static_asset_count"] == 1


def test_json_report_includes_endpoint_discovery(tmp_path: Path) -> None:
    result = run_endpoint_discovery(["http://127.0.0.1:8000/account?id=123"], input_source="test")
    scan_result = _scan_result(result)
    path = save_json_report(scan_result, "VulScan", "test", datetime.now(), datetime.now(), reports_dir=tmp_path)
    assert '"endpoint_discovery"' in path.read_text(encoding="utf-8")
    assert '"parameter_results"' in path.read_text(encoding="utf-8")


def test_html_report_renders_endpoint_section(tmp_path: Path) -> None:
    result = run_endpoint_discovery(["http://127.0.0.1:8000/account?id=123"], input_source="test")
    scan_result = _scan_result(result)
    path = save_html_report(scan_result, "VulScan", "test", datetime.now(), datetime.now(), reports_dir=tmp_path)
    html = path.read_text(encoding="utf-8")
    assert "Bug Bounty Endpoint Discovery" in html
    assert "Parameter Intelligence" in html


def _scan_result(result: dict) -> dict:
    return {
        "host": "endpoint-discovery",
        "resolved_ip": "",
        "scan_mode": "endpoint-discovery",
        "duration_seconds": 0,
        "open_ports": [],
        "findings": result["findings"],
        "endpoint_discovery": result["endpoint_discovery"],
        "endpoint_results": result["endpoint_results"],
        "parameter_results": result["parameter_results"],
        "endpoint_skipped": result["endpoint_skipped"],
    }
