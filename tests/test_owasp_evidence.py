from scanner.owasp_evidence import build_owasp_evidence_items
from scanner.owasp_rules import load_owasp_assessment_rules


def test_builds_evidence_item_from_missing_csp_finding() -> None:
    items = build_owasp_evidence_items({"findings": [_finding("Missing Content Security Policy", "web_header_audit", "Headers", "Missing CSP header.")]})
    assert any(item["owasp_id"] == "A02:2025" for item in items)


def test_builds_evidence_item_from_cookie_flag_issue() -> None:
    items = build_owasp_evidence_items({"findings": [_finding("Cookie Missing Secure Flag", "web_cookie_audit", "Cookie Security", "Session cookie missing Secure flag.")]})
    assert {item["owasp_id"] for item in items}.intersection({"A04:2025", "A07:2025"})


def test_builds_low_confidence_idor_parameter_evidence() -> None:
    items = build_owasp_evidence_items({"parameter_results": [{"url": "http://127.0.0.1/account?id=1", "parameter_name": "id", "parameter_type": "idor"}]})
    item = next(item for item in items if item["owasp_id"] == "A01:2025")
    assert item["confidence"] == "Low"
    assert item["manual_validation_required"] is True
    assert item["assessment_status"] == "needs_manual_validation"


def test_reflected_input_validation_is_stronger_than_parameter_only() -> None:
    items = build_owasp_evidence_items(
        {
            "parameter_results": [{"url": "http://127.0.0.1/search?q=test", "parameter_name": "q", "parameter_type": "injection_reflection"}],
            "safe_active_validation_results": [{
                "url": "http://127.0.0.1/search?q=test",
                "parameter": "q",
                "check_name": "reflected_input_observation",
                "indicator_found": True,
                "evidence_summary": {"marker_reflected": True},
            }],
        }
    )
    a05_items = [item for item in items if item["owasp_id"] == "A05:2025"]
    assert {item["evidence_strength"] for item in a05_items} == {"weak_indicator", "strong_indicator"}


def test_builds_evidence_item_from_cve_component_finding() -> None:
    items = build_owasp_evidence_items({"findings": [_finding("Local CVE Match", "vuln_intel", "Vulnerability Intelligence", "CVE indicator for outdated component.")]})
    item = next(item for item in items if item["owasp_id"] == "A03:2025")
    assert item["confidence"] == "High"


def test_loads_owasp_assessment_rules() -> None:
    rules = load_owasp_assessment_rules()
    assert rules["version"] == "2025"
    assert len(rules["categories"]) == 10


def _finding(title: str, source: str, category: str, evidence: str) -> dict:
    return {
        "title": title,
        "severity": "Informational",
        "category": category,
        "evidence": evidence,
        "confidence": "Medium",
        "recommendation": "Review manually.",
        "source": source,
    }
