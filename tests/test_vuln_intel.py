from scanner.software_inventory import build_software_inventory
from scanner.vuln_intel import (
    build_vulnerability_intelligence_findings,
    build_vulnerability_intelligence_summary,
    match_rules,
)


def _inventory_items() -> list[dict]:
    scan_result = {
        "host": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "open_ports": [
            {
                "host": "127.0.0.1",
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "status": "open",
                "confidence": "high",
                "evidence": "TCP connection successful",
            },
            {
                "host": "127.0.0.1",
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "status": "open",
                "confidence": "high",
                "evidence": "TCP connection successful",
            },
        ],
    }
    inventory = build_software_inventory(scan_result)
    inventory["items"].append(
        {
            "asset": "127.0.0.1",
            "host": "127.0.0.1",
            "port": 8080,
            "protocol": "tcp",
            "service_name": "http",
            "product": "ExampleServer",
            "version": "2.4.58",
            "source": "web_header_audit",
            "evidence": "Server header observed.",
            "confidence": "Low",
            "metadata": {},
        }
    )
    inventory["total_items"] = len(inventory["items"])
    return inventory["items"]


def test_matches_rule_by_service_name() -> None:
    matches = match_rules(_inventory_items(), [{"rule_id": "R1", "title": "SSH", "match": {"service_name": "ssh"}}])

    assert matches[0]["matched_item"]["service_name"] == "ssh"


def test_matches_rule_by_port() -> None:
    matches = match_rules(_inventory_items(), [{"rule_id": "R2", "title": "HTTPS", "match": {"port": 443}}])

    assert matches[0]["matched_item"]["port"] == 443


def test_matches_rule_by_protocol() -> None:
    matches = match_rules(_inventory_items(), [{"rule_id": "R3", "title": "TCP", "match": {"protocol": "tcp"}}])

    assert len(matches) >= 2


def test_matches_rule_by_product_and_version_contains() -> None:
    matches = match_rules(
        _inventory_items(),
        [
            {
                "rule_id": "R4",
                "title": "ExampleServer 2.4",
                "match": {"product": "ExampleServer", "version_contains": "2.4"},
            }
        ],
    )

    assert matches[0]["matched_item"]["product"] == "ExampleServer"


def test_generates_vulnerability_intelligence_summary() -> None:
    inventory = {"items": _inventory_items(), "total_items": len(_inventory_items())}
    matches = match_rules(inventory["items"], [{"rule_id": "R5", "title": "SSH", "match": {"service_name": "ssh"}}])

    summary = build_vulnerability_intelligence_summary(
        ruleset={"ruleset_name": "Unit", "ruleset_version": "1.0", "rules": [{"rule_id": "R5"}]},
        inventory=inventory,
        matches=matches,
    )

    assert summary["enabled"] is True
    assert summary["rules_loaded"] == 1
    assert summary["inventory_items_checked"] == inventory["total_items"]
    assert summary["matches_found"] == 1


def test_generates_standard_findings_and_conservative_cve_wording() -> None:
    inventory = {"items": _inventory_items(), "total_items": len(_inventory_items())}
    matches = match_rules(
        inventory["items"],
        [
            {
                "rule_id": "R6",
                "title": "Local CVE Indicator",
                "match": {"product": "ExampleServer", "version_contains": "2.4"},
                "cve": "CVE-2099-0001",
                "cvss_score": 7.5,
                "epss_score": 0.2,
                "exploit_available": True,
                "severity": "High",
                "category": "Local CVE Indicator",
                "confidence": "Medium",
                "recommendation": "Validate the exact version and patch status.",
                "limitation": "Local rule only.",
            }
        ],
    )
    summary = build_vulnerability_intelligence_summary(
        ruleset={"ruleset_name": "Unit", "ruleset_version": "1.0", "rules": [{"rule_id": "R6"}]},
        inventory=inventory,
        matches=matches,
    )

    findings = build_vulnerability_intelligence_findings(matches, summary, {"host": "127.0.0.1"})

    assert findings[0].title == "Vulnerability Intelligence Matching Completed"
    cve_finding = findings[1]
    assert cve_finding.source == "vuln_intel"
    assert cve_finding.evidence_details["cve"] == "CVE-2099-0001"
    assert cve_finding.evidence_details["cvss_score"] == 7.5
    assert "does not confirm vulnerability" in cve_finding.evidence
    assert "confirmed vulnerable" not in cve_finding.evidence.lower()
