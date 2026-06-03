from __future__ import annotations

from datetime import datetime, timedelta, timezone

from scanner.owasp_a04_crypto import (
    assess_a04_crypto,
    assess_cookie_security,
    assess_hsts,
    assess_mixed_content,
    assess_transport_security,
    load_a04_rules,
)
from scanner.owasp_assessment import build_owasp_assessment
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report


def test_load_a04_rules() -> None:
    rules = load_a04_rules()
    assert rules["owasp_id"] == "A04:2025"
    assert "transport_security" in rules["rule_groups"]


def test_detects_http_and_sensitive_parameter_without_value() -> None:
    items = assess_transport_security("http://example.test/login?token=NeverStoreToken")
    assert {item["rule_id"] for item in items} >= {"http_url_detected", "token_parameter_over_http"}
    assert "NeverStoreToken" not in str(items)


def test_detects_login_form_over_http() -> None:
    result = assess_a04_crypto(
        target="http://example.test/login",
        forms=[{"page_url": "http://example.test/login", "classification": "login_form", "has_password_field": True}],
        collect_tls=False,
    )
    assert any(item["rule_id"] == "login_form_over_http" for item in result["a04_crypto_evidence"])


def test_hsts_missing_low_max_age_and_preload_informational() -> None:
    missing = assess_hsts("https://example.test/", {})
    assert missing[0]["rule_id"] == "missing_hsts"
    low = assess_hsts("https://example.test/", {"Strict-Transport-Security": "max-age=300"})
    by_rule = {item["rule_id"]: item for item in low}
    assert by_rule["hsts_max_age_low"]["evidence_strength"] == "weak_indicator"
    assert by_rule["hsts_preload_missing"]["evidence_strength"] == "informational"


def test_cookie_security_redacts_values_and_detects_attributes() -> None:
    items = assess_cookie_security("https://example.test/", ["SESSIONID=NeverStoreCookie; SameSite=None"])
    rules = {item["rule_id"] for item in items}
    assert {"secure_missing", "httponly_missing", "samesite_none_without_secure", "session_cookie_insecure"} <= rules
    assert "NeverStoreCookie" not in str(items)
    assert any(item.get("cookie_name") == "SESSIONID" for item in items)


def test_cookie_samesite_missing_and_csrftoken_not_session() -> None:
    items = assess_cookie_security("https://example.test/", ["csrftoken=fake; Secure"])
    rules = {item["rule_id"] for item in items}
    assert "samesite_missing" in rules
    assert "session_cookie_insecure" not in rules


def test_mixed_content_strengths() -> None:
    html = """
    <script src="http://cdn.example.test/app.js"></script>
    <form action="http://example.test/login"></form>
    <img src="http://cdn.example.test/logo.png">
    """
    items = assess_mixed_content("https://example.test/", html)
    by_rule = {item["rule_id"]: item for item in items}
    assert by_rule["http_script_source_on_https_page"]["evidence_strength"] == "strong_indicator"
    assert by_rule["http_form_action_on_https_page"]["evidence_strength"] == "strong_indicator"
    assert by_rule["http_image_source_on_https_page"]["evidence_strength"] == "weak_indicator"


def test_summary_counts_and_owasp_assessment_integration() -> None:
    result = assess_a04_crypto(
        target="https://example.test/",
        headers={},
        set_cookie_headers=["sessionid=fake; Path=/"],
        html_snippet='<script src="http://cdn.example.test/app.js"></script>',
        collect_tls=False,
    )
    summary = result["a04_crypto_summary"]
    assert summary["strong_indicators_count"] >= 1
    assert summary["weak_indicators_count"] >= 1
    assessment = build_owasp_assessment({"host": "example.test", "a04_crypto_evidence": result["a04_crypto_evidence"]})
    a04 = next(item for item in assessment["owasp_category_results"] if item["owasp_id"] == "A04:2025")
    assert a04["evidence_count"] >= 1


def test_tls_metadata_evidence_from_mock() -> None:
    future = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT")
    result = assess_a04_crypto(
        target="https://example.test/",
        tls_metadata={
            "host": "example.test",
            "metadata_available": True,
            "issuer_common_name": "Example CA",
            "subject_common_name": "example.test",
            "not_after": future,
            "expired": False,
            "days_until_expiry": 10,
            "hostname_match": True,
            "self_signed_indicator": False,
        },
        collect_tls=False,
    )
    assert any(item["rule_id"] == "certificate_near_expiry" for item in result["a04_crypto_evidence"])


def test_json_and_html_reports_include_a04_section(tmp_path) -> None:
    result = assess_a04_crypto(target="http://example.test/login?token=NeverStore", collect_tls=False)
    scan_result = {
        "host": "example.test",
        "resolved_ip": "",
        "scan_mode": "web-dast",
        "duration_seconds": 0,
        "open_ports": [],
        "findings": [],
        "a04_crypto_summary": result["a04_crypto_summary"],
        "a04_crypto_evidence": result["a04_crypto_evidence"],
        "a04_tls_metadata": result["a04_tls_metadata"],
    }
    now = datetime.now(timezone.utc)
    json_path = save_json_report(scan_result, "VulScan", "test", now, now, reports_dir=tmp_path)
    html_path = save_html_report(scan_result, "VulScan", "test", now, now, reports_dir=tmp_path)
    json_text = json_path.read_text(encoding="utf-8")
    html_text = html_path.read_text(encoding="utf-8")
    assert "a04_crypto_summary" in json_text
    assert "A04 Cryptographic Failures and Transport Security" in html_text
    assert "NeverStore" not in json_text
    assert "NeverStore" not in html_text
