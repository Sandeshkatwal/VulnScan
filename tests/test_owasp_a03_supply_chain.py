import json
from datetime import datetime

from scanner.owasp_a03_supply_chain import assess_a03_supply_chain, attach_a03_supply_chain, load_a03_rules
from scanner.owasp_assessment import attach_owasp_assessment
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report


def _feed() -> dict:
    return {
        "feed_name": "unit",
        "feed_version": "2026.06",
        "items": [
            {
                "cve": "CVE-2099-0001",
                "vendor": "jquery",
                "product": "jquery",
                "affected_versions": [{"operator": "less_than_or_equal", "version": "3.6.0"}],
                "cvss_score": 7.5,
                "epss_score": 0.42,
                "exploit_available": False,
            }
        ],
    }


def test_loads_a03_rules() -> None:
    rules = load_a03_rules()
    assert rules["owasp_id"] == "A03:2025"
    assert "dependency_metadata_exposure" in rules["rule_groups"]


def test_assesses_a03_summary_and_cve_enrichment() -> None:
    payload = assess_a03_supply_chain(
        target="http://example.test",
        scripts=["/static/jquery-3.6.0.min.js", "https://cdn.thirdparty.test/lib.js"],
        endpoint_results=[{"url": "http://example.test/package.json"}, {"url": "http://example.test/app.js.map"}],
        sbom_components=[{"name": "jquery", "version": "3.6.0", "type": "library", "cpe": "cpe:2.3:a:jquery:jquery:3.6.0:*:*:*:*:*:*:*"}],
        vuln_intel={"cve_feed": _feed()},
    )
    summary = payload["a03_supply_chain_summary"]
    evidence = payload["a03_supply_chain_evidence"]
    assert summary["total_evidence_items"] >= 5
    assert summary["dependency_metadata_exposure_count"] == 1
    assert summary["source_map_indicator_count"] >= 1
    assert summary["third_party_script_count"] == 1
    assert summary["cve_match_count"] >= 1
    assert any(item["rule_group"] == "cve_cpe_enrichment" for item in evidence)
    assert "registry" in " ".join(summary["limitations"]).lower()


def test_a03_evidence_feeds_owasp_assessment_and_reports(tmp_path) -> None:
    scan_result = {
        "host": "example.test",
        "resolved_ip": "",
        "scan_mode": "unit",
        "duration_seconds": 0.1,
        "open_ports": [],
        "findings": [],
        "endpoint_results": [{"url": "http://example.test/package-lock.json"}],
        "demo_mode": False,
        "demo_notice": "",
    }
    attach_a03_supply_chain(scan_result)
    attach_owasp_assessment(scan_result)
    assert any(item["owasp_id"] == "A03:2025" for item in scan_result["owasp_evidence_items"])
    now = datetime.now()
    json_path = save_json_report(scan_result, "VulScan", "test", now, now, reports_dir=tmp_path)
    html_path = save_html_report(scan_result, "VulScan", "test", now, now, reports_dir=tmp_path)
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["a03_supply_chain_summary"]["enabled"] is True
    assert "A03 Software Supply Chain" in html_path.read_text(encoding="utf-8")
