from scanner.integrity_indicators import make_a08_evidence_item
from scanner.sri_analysis import assess_subresource_integrity


def test_sri_analysis_detects_external_resources_without_fetching() -> None:
    evidence = assess_subresource_integrity(
        scripts=[{"src": "https://cdn.example.test/app.js"}],
        stylesheets=[{"href": "https://cdn.example.test/site.css"}],
        target="http://app.example.test",
        evidence_factory=make_a08_evidence_item,
    )
    rule_ids = {item["rule_id"] for item in evidence}
    assert "third_party_script_without_sri" in rule_ids
    assert "external_stylesheet_without_sri" in rule_ids
    assert all(item["evidence_strength"] != "confirmed_finding" for item in evidence)
    assert all("fetch" not in item["safe_evidence_summary"].lower() for item in evidence)


def test_sri_analysis_detects_integrity_and_inline_script_review() -> None:
    evidence = assess_subresource_integrity(
        scripts=[{"src": "https://cdn.example.test/app.js", "integrity": "sha384-test"}],
        stylesheets=[],
        html_snippet="<script>window.test=true</script>",
        target="http://app.example.test",
        evidence_factory=make_a08_evidence_item,
    )
    assert any(item["rule_id"] == "sri_attribute_present" for item in evidence)
    assert any(item["rule_id"] == "sri_missing_crossorigin_context" for item in evidence)
    assert any(item["rule_id"] == "inline_script_integrity_review" for item in evidence)
    assert not any("window.test" in str(item) for item in evidence)
