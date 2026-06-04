from __future__ import annotations

from datetime import datetime, timezone

from scanner.owasp_a07_authentication import (
    assess_a07_authentication,
    assess_auth_cookies,
    assess_auth_endpoints,
    assess_auth_forms,
    assess_password_reset_indicators,
    assess_rate_limit_headers,
    load_a07_rules,
)
from scanner.owasp_assessment import build_owasp_assessment
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report


def test_load_a07_rules() -> None:
    rules = load_a07_rules()
    assert rules["owasp_id"] == "A07:2025"
    assert "auth_endpoint_discovery" in rules["rule_groups"]


def test_detects_auth_endpoints_and_protocol_surfaces() -> None:
    urls = [
        "https://example.test/login",
        "https://example.test/reset-password",
        "https://example.test/logout",
        "https://example.test/oauth/callback",
        "https://example.test/.well-known/openid-configuration",
    ]
    items = assess_auth_endpoints([], urls)
    rules = {item["rule_id"] for item in items}
    assert {"login_endpoint_detected", "password_reset_endpoint_detected", "logout_endpoint_detected", "oauth_callback_detected", "oauth_oidc_endpoint_detected"} <= rules


def test_session_cookie_indicators_redact_value() -> None:
    items = assess_auth_cookies("https://example.test/", ["SESSIONID=NeverStoreCookie; SameSite=None"])
    rules = {item["rule_id"] for item in items}
    assert {"session_cookie_detected", "session_cookie_missing_secure", "session_cookie_missing_httponly"} <= rules
    assert "NeverStoreCookie" not in str(items)


def test_remember_me_and_persistent_cookie_detected() -> None:
    items = assess_auth_cookies("https://example.test/", ["remember_me=fake; Secure; HttpOnly; Max-Age=3600"])
    rules = {item["rule_id"] for item in items}
    assert "remember_me_cookie_detected" in rules
    assert "persistent_session_cookie_detected" in rules


def test_auth_form_indicators_and_csrf_redaction() -> None:
    items = assess_auth_forms(
        "https://example.test/login",
        [
            {
                "page_url": "https://example.test/login",
                "resolved_action_url": "https://example.test/login",
                "has_password_field": True,
                "input_fields": [
                    {"name": "username", "type": "text"},
                    {"name": "password", "type": "password"},
                    {"name": "csrf_token", "type": "hidden", "value": "NeverStoreCsrf"},
                    {"name": "remember_me", "type": "checkbox"},
                ],
            }
        ],
    )
    rules = {item["rule_id"] for item in items}
    assert {"login_form_detected", "password_field_detected", "remember_me_checkbox_detected"} <= rules
    assert "NeverStoreCsrf" not in str(items)
    assert any(item.get("csrf_like_field_detected") is True for item in items)


def test_auth_form_without_csrf_and_over_http() -> None:
    items = assess_auth_forms("http://example.test/login", [{"page_url": "http://example.test/login", "has_password_field": True, "input_fields": [{"name": "password", "type": "password"}]}])
    rules = {item["rule_id"] for item in items}
    assert "auth_form_over_http" in rules
    assert "auth_form_without_csrf_indicator" in rules


def test_reset_token_parameter_redacted_and_strong() -> None:
    items = assess_password_reset_indicators(["https://example.test/reset-password?token=NeverStoreToken"], [])
    rules = {item["rule_id"] for item in items}
    assert {"reset_token_parameter_detected", "token_in_url_indicator"} <= rules
    assert any(item["evidence_strength"] == "strong_indicator" for item in items)
    assert "NeverStoreToken" not in str(items)


def test_rate_limit_headers_present_and_missing_is_weak_only() -> None:
    present = assess_rate_limit_headers("https://example.test/login", {"RateLimit-Limit": "10", "Retry-After": "60"})
    missing = assess_rate_limit_headers("https://example.test/login", {})
    assert any(item["rule_id"] == "rate_limit_headers_present" for item in present)
    assert any(item["rule_id"] == "retry_after_header_present" for item in present)
    missing_item = next(item for item in missing if item["rule_id"] == "login_endpoint_without_rate_limit_headers")
    assert missing_item["evidence_strength"] == "weak_indicator"


def test_summary_counts_and_owasp_a07_integration() -> None:
    result = assess_a07_authentication(
        target="https://example.test/login",
        set_cookie_headers=["SESSIONID=fake"],
        forms=[{"page_url": "https://example.test/login", "has_password_field": True, "input_fields": [{"name": "password", "type": "password"}]}],
    )
    summary = result["a07_authentication_summary"]
    assert summary["strong_indicators_count"] >= 1
    assert summary["weak_indicators_count"] >= 1
    assessment = build_owasp_assessment({"host": "example.test", "a07_authentication_evidence": result["a07_authentication_evidence"]})
    a07 = next(item for item in assessment["owasp_category_results"] if item["owasp_id"] == "A07:2025")
    assert a07["evidence_count"] >= 1


def test_json_and_html_reports_include_a07_section(tmp_path) -> None:
    result = assess_a07_authentication(target="https://example.test/reset-password?token=NeverStoreToken")
    scan_result = {
        "host": "example.test",
        "resolved_ip": "",
        "scan_mode": "web-dast",
        "duration_seconds": 0,
        "open_ports": [],
        "findings": [],
        "a07_authentication_summary": result["a07_authentication_summary"],
        "a07_authentication_evidence": result["a07_authentication_evidence"],
    }
    now = datetime.now(timezone.utc)
    json_path = save_json_report(scan_result, "VulScan", "test", now, now, reports_dir=tmp_path)
    html_path = save_html_report(scan_result, "VulScan", "test", now, now, reports_dir=tmp_path)
    json_text = json_path.read_text(encoding="utf-8")
    html_text = html_path.read_text(encoding="utf-8")
    assert "a07_authentication_summary" in json_text
    assert "A07 Authentication and Session Indicators" in html_text
    assert "NeverStoreToken" not in json_text
    assert "NeverStoreToken" not in html_text
