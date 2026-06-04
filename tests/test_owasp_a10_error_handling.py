from __future__ import annotations

from datetime import datetime, timezone

from scanner.owasp_a10_error_handling import (
    assess_a10_error_handling,
    assess_status_code_patterns,
    assess_verbose_errors,
    build_safe_error_snippet,
    detect_error_patterns,
    load_a10_rules,
)
from scanner.owasp_assessment import build_owasp_assessment
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report


def test_load_a10_rules() -> None:
    rules = load_a10_rules()
    assert rules["owasp_id"] == "A10:2025"
    assert "verbose_error_messages" in rules["rule_groups"]


def test_detects_verbose_error_patterns() -> None:
    samples = [
        ("Traceback (most recent call last):\n File \"app.py\", line 3", "traceback_detected"),
        ("PHP Fatal error: Undefined variable", "php_warning_notice_error"),
        ("java.lang.NullPointerException\n at com.example.App.main(App.java:12)", "java_exception_page"),
        ("TypeError: broken\n    at Object.handler (/app/server.js:12)", "node_stack_trace"),
        ("You're seeing this error because you have DEBUG = True", "django_debug_page"),
        ("Werkzeug Debugger active", "flask_debug_page"),
        ("Whoops! There was an error. Laravel Exception", "laravel_error_page"),
        ("Whitelabel Error Page Spring Boot", "spring_boot_error_page"),
        ("Server Error in '/' Application ASP.NET", "aspnet_error_page"),
        ("SQL syntax error near SELECT", "sql_error_message_detected"),
    ]
    for text, rule in samples:
        assert any(item["rule_id"] == rule for item in detect_error_patterns(text))


def test_safe_snippet_redacts_and_limits() -> None:
    text = "password=NeverStore token=NeverStoreToken Cookie: sessionid=NeverStoreCookie C:\\secret\\app.py " + ("x" * 2000)
    snippet = build_safe_error_snippet(text)
    assert len(snippet) <= 1000
    assert "NeverStore" not in snippet
    assert "[INTERNAL_PATH_REDACTED]" in snippet


def test_assess_verbose_errors_redacts_internal_path_and_token() -> None:
    items = assess_verbose_errors("https://example.test/error", 500, "Traceback token=NeverStoreToken File \"C:\\secret\\app.py\", line 4")
    assert any(item["rule_id"] == "traceback_detected" for item in items)
    assert any(item["rule_id"] == "source_path_disclosure_indicator" for item in items)
    assert "NeverStoreToken" not in str(items)
    assert "C:\\secret" not in str(items)


def test_status_patterns_and_fail_safe_manual_review() -> None:
    items = assess_status_code_patterns(
        [
            {"url": "https://example.test/login", "status_code": 500, "endpoint_category": "authentication"},
            {"url": "https://example.test/account", "status_code": 500, "endpoint_category": "user_account"},
        ]
    )
    assert any(item["rule_id"] == "repeated_500_responses" for item in items)
    fail_safe = [item for item in items if item["rule_group"] == "fail_open_manual_review"]
    assert fail_safe
    assert all(item["evidence_strength"] == "informational" for item in fail_safe)
    assert all(item["manual_validation_required"] for item in fail_safe)


def test_a10_summary_and_owasp_integration() -> None:
    result = assess_a10_error_handling(
        target="https://example.test",
        responses=[{"url": "https://example.test/error", "status_code": 500, "body_snippet": "Traceback (most recent call last): SQL syntax error"}],
    )
    summary = result["a10_error_handling_summary"]
    assert summary["strong_indicators_count"] >= 1
    assert summary["database_error_count"] >= 1
    assessment = build_owasp_assessment({"host": "example.test", "a10_error_handling_evidence": result["a10_error_handling_evidence"]})
    a10 = next(item for item in assessment["owasp_category_results"] if item["owasp_id"] == "A10:2025")
    assert a10["evidence_count"] >= 1


def test_reports_include_a10_and_do_not_store_full_body(tmp_path) -> None:
    result = assess_a10_error_handling(
        target="https://example.test",
        responses=[{"url": "https://example.test/error", "status_code": 500, "body_snippet": "Traceback password=NeverStore " + ("x" * 2000)}],
    )
    scan_result = {
        "host": "example.test",
        "resolved_ip": "",
        "scan_mode": "web-dast",
        "duration_seconds": 0,
        "open_ports": [],
        "findings": [],
        "a10_error_handling_summary": result["a10_error_handling_summary"],
        "a10_error_handling_evidence": result["a10_error_handling_evidence"],
    }
    now = datetime.now(timezone.utc)
    json_path = save_json_report(scan_result, "VulScan", "test", now, now, reports_dir=tmp_path)
    html_path = save_html_report(scan_result, "VulScan", "test", now, now, reports_dir=tmp_path)
    json_text = json_path.read_text(encoding="utf-8")
    html_text = html_path.read_text(encoding="utf-8")
    assert "a10_error_handling_summary" in json_text
    assert "A10 Error Handling and Exception Exposure" in html_text
    assert "NeverStore" not in json_text
    assert "x" * 1001 not in json_text
    assert "NeverStore" not in html_text
