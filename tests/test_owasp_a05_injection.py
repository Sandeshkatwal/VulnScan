from scanner.owasp_a05_injection import (
    assess_a05_injection,
    assess_api_input_candidates,
    assess_form_input_candidates,
    assess_injection_parameter_candidates,
    load_a05_rules,
)
from scanner.owasp_assessment import build_owasp_assessment


def test_load_a05_rules() -> None:
    rules = load_a05_rules()
    assert rules["owasp_id"] == "A05:2025"
    assert "parameter_candidates" in rules["rule_groups"]


def test_classifies_parameter_candidate_groups() -> None:
    evidence = assess_injection_parameter_candidates(
        [
            {"url": "http://example.test/search?q=test", "parameter_name": "q"},
            {"url": "http://example.test/item?id=1", "parameter_name": "id"},
            {"url": "http://example.test/api?filter=a&sort=b", "parameter_name": "filter"},
            {"url": "http://example.test/api?callback=x", "parameter_name": "callback"},
            {"url": "http://example.test/view?template=home", "parameter_name": "template"},
            {"url": "http://example.test/file?path=/tmp", "parameter_name": "path"},
        ],
        [],
    )
    rule_ids = {item["rule_id"] for item in evidence}
    assert "search_parameter_detected" in rule_ids
    assert "query_parameter_detected" in rule_ids
    assert "filter_parameter_detected" in rule_ids
    assert "callback_parameter_detected" in rule_ids
    assert "template_parameter_detected" in rule_ids
    assert all(item["manual_validation_required"] for item in evidence)


def test_form_analysis_detects_text_textarea_and_does_not_store_values() -> None:
    forms = [
        {
            "action": "http://example.test/comment",
            "fields": [
                {"name": "comment", "type": "text", "value": "do-not-store"},
                {"name": "body", "tag": "textarea", "value": "do-not-store"},
                {"name": "csrf_token", "type": "hidden", "value": "secret-token"},
            ],
        }
    ]
    evidence = assess_form_input_candidates(forms)
    rule_ids = {item["rule_id"] for item in evidence}
    assert "text_input_detected" in rule_ids
    assert "textarea_detected" in rule_ids
    assert "hidden_input_names_only" in rule_ids
    text = str(evidence)
    assert "do-not-store" not in text
    assert "secret-token" not in text
    assert "csrf_token" in text


def test_api_endpoint_candidate_detected() -> None:
    evidence = assess_api_input_candidates(
        [{"url": "http://example.test/api/items?filter=open&sort=name"}, {"url": "http://example.test/graphql"}],
        [],
    )
    rule_ids = {item["rule_id"] for item in evidence}
    assert "api_endpoint_with_query_params" in rule_ids
    assert "graphql_endpoint_detected" in rule_ids


def test_a05_summary_counts_and_feeds_owasp_assessment() -> None:
    payload = assess_a05_injection(
        target="http://example.test",
        parameter_results=[{"url": "http://example.test/search?q=test", "parameter_name": "q"}],
        endpoint_results=[{"url": "http://example.test/api/items?filter=open"}],
        forms=[{"action": "http://example.test/search", "fields": [{"name": "q", "type": "search"}]}],
    )
    summary = payload["a05_injection_summary"]
    assert summary["weak_indicators_count"] >= 2
    assert summary["parameter_candidate_count"] >= 1
    scan_result = {
        "host": "example.test",
        "findings": [],
        "a05_injection_evidence": payload["a05_injection_evidence"],
    }
    assessment = build_owasp_assessment(scan_result)
    a05 = next(item for item in assessment["owasp_category_results"] if item["owasp_id"] == "A05:2025")
    assert a05["evidence_count"] >= 1
    assert a05["manual_validation_required_count"] >= 1
