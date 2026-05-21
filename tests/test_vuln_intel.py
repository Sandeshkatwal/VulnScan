from scanner.software_inventory import build_software_inventory
from scanner.vuln_intel import (
    build_vulnerability_intelligence_findings,
    build_vulnerability_intelligence_summary,
    match_rules,
    run_vulnerability_intelligence,
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


def test_matches_version_less_than() -> None:
    matches = match_rules(
        _inventory_items(),
        [{"rule_id": "RLT", "title": "Old", "match": {"product": "ExampleServer", "version_less_than": "2.5.0"}}],
    )

    assert matches[0]["match_status"] == "matched"
    assert matches[0]["version_condition"]["operator"] == "version_less_than"


def test_matches_version_greater_than() -> None:
    matches = match_rules(
        _inventory_items(),
        [{"rule_id": "RGT", "title": "New", "match": {"product": "ExampleServer", "version_greater_than": "2.0.0"}}],
    )

    assert matches[0]["match_status"] == "matched"


def test_matches_version_between() -> None:
    matches = match_rules(
        _inventory_items(),
        [{"rule_id": "RB", "title": "Between", "match": {"product": "ExampleServer", "version_between": ["2.4.0", "2.4.99"]}}],
    )

    assert matches[0]["match_status"] == "matched"


def test_version_specific_rule_does_not_create_match_when_version_missing() -> None:
    items = [{"host": "127.0.0.1", "service_name": "ssh", "product": "openssh", "version": None, "port": 22, "protocol": "tcp"}]

    matches = match_rules(items, [{"rule_id": "RUNK", "title": "Unknown", "match": {"product": "openssh", "version_less_than": "9.6"}}])

    assert matches[0]["match_status"] == "insufficient_evidence"


def test_allow_unknown_version_only_when_explicit_and_low_confidence() -> None:
    items = [{"host": "127.0.0.1", "service_name": "ssh", "version": None, "port": 22, "protocol": "tcp"}]

    no_allow = match_rules(items, [{"rule_id": "R1", "title": "No", "match": {"service_name": "ssh", "version_less_than": "9.6"}}])
    allow = match_rules(
        items,
        [{"rule_id": "R2", "title": "Allow", "match": {"service_name": "ssh", "version_less_than": "9.6"}, "allow_unknown_version": True}],
    )

    assert no_allow[0]["match_status"] == "insufficient_evidence"
    assert allow[0]["match_status"] == "unknown_version"
    assert allow[0]["match_confidence"] == "Low"


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
    assert "unknown_version_count" in summary


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
    assert "requires validation" in cve_finding.evidence
    assert "confirmed vulnerable" not in cve_finding.evidence.lower()


def test_generates_finding_for_confirmed_version_match() -> None:
    inventory = {"items": _inventory_items(), "total_items": len(_inventory_items())}
    matches = match_rules(
        inventory["items"],
        [
            {
                "rule_id": "RV",
                "title": "Version Match",
                "match": {"product": "ExampleServer", "version_less_than": "2.5.0"},
                "fixed_version": "2.5.0",
                "severity": "Medium",
                "confidence": "Medium",
            }
        ],
    )
    summary = build_vulnerability_intelligence_summary(
        ruleset={"ruleset_name": "Unit", "ruleset_version": "1.0", "rules": [{"rule_id": "RV", "match": {"version_less_than": "2.5.0"}}]},
        inventory=inventory,
        matches=matches,
    )

    findings = build_vulnerability_intelligence_findings(matches, summary, {"host": "127.0.0.1"})

    assert len(findings) == 2
    assert "version 2.4.58" in findings[1].evidence
    assert findings[1].evidence_details["fixed_version"] == "2.5.0"


def test_unknown_version_finding_does_not_claim_confirmed_vulnerability() -> None:
    items = [{"host": "127.0.0.1", "service_name": "ssh", "version": None, "port": 22, "protocol": "tcp"}]
    matches = match_rules(
        items,
        [{"rule_id": "RU", "title": "Possible Old SSH", "match": {"service_name": "ssh", "version_less_than": "9.6"}, "allow_unknown_version": True}],
    )
    summary = build_vulnerability_intelligence_summary(
        ruleset={"ruleset_name": "Unit", "ruleset_version": "1.0", "rules": [{"rule_id": "RU", "match": {"version_less_than": "9.6"}}]},
        inventory={"items": items, "total_items": 1},
        matches=matches,
    )

    findings = build_vulnerability_intelligence_findings(matches, summary, {"host": "127.0.0.1"})

    assert findings[1].confidence == "Low"
    assert "version was not confirmed" in findings[1].evidence
    assert "confirmed vulnerability" not in findings[1].evidence.lower()


def test_run_vulnerability_intelligence_includes_local_cve_feed(tmp_path) -> None:
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(
        """
        {
          "ruleset_name": "Unit Rules",
          "ruleset_version": "1.0",
          "rules": [
            {"rule_id": "R1", "title": "SSH", "match": {"service_name": "ssh"}}
          ]
        }
        """,
        encoding="utf-8",
    )
    feed_path = tmp_path / "feed.json"
    feed_path.write_text(
        """
        {
          "feed_name": "Unit CVE Feed",
          "feed_version": "1.0",
          "items": [
            {
              "cve": "LOCAL-CVE-DEMO-0001",
              "title": "Demo OpenSSH Version Below Policy Threshold",
              "vendor": "openbsd",
              "product": "openssh",
              "cpe_prefix": "cpe:2.3:a:openbsd:openssh",
              "affected_versions": {"less_than": "9.6"},
              "fixed_version": "9.6",
              "cvss_score": 7.5,
              "severity": "High",
              "exploit_available": false,
              "references": []
            }
          ]
        }
        """,
        encoding="utf-8",
    )
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
                "evidence": "SSH-2.0-OpenSSH_8.9p1",
                "banner": "SSH-2.0-OpenSSH_8.9p1",
                "metadata": {"vendor": "openbsd", "cpe": "cpe:2.3:a:openbsd:openssh:8.9p1"},
            }
        ],
    }

    inventory, summary, findings = run_vulnerability_intelligence(
        scan_result=scan_result,
        rules_path=rules_path,
        use_cve_feed=True,
        cve_feed_path=feed_path,
    )

    assert inventory["items"][0]["product"] == "openssh"
    assert summary["cve_feed_enabled"] is True
    assert summary["cve_feed_matches_found"] == 1
    assert summary["cve_feed_matches"][0]["cve"] == "LOCAL-CVE-DEMO-0001"
    assert any(finding.source == "cve_feed" for finding in findings)


def test_run_vulnerability_intelligence_enriches_cve_feed_with_epss(tmp_path) -> None:
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(
        """
        {
          "ruleset_name": "Unit Rules",
          "ruleset_version": "1.0",
          "rules": [
            {"rule_id": "R1", "title": "SSH", "match": {"service_name": "ssh"}}
          ]
        }
        """,
        encoding="utf-8",
    )
    feed_path = tmp_path / "feed.json"
    feed_path.write_text(
        """
        {
          "feed_name": "Unit CVE Feed",
          "feed_version": "1.0",
          "items": [
            {
              "cve": "LOCAL-CVE-DEMO-0001",
              "title": "Demo OpenSSH Version Below Policy Threshold",
              "vendor": "openbsd",
              "product": "openssh",
              "cpe_prefix": "cpe:2.3:a:openbsd:openssh",
              "affected_versions": {"less_than": "9.6"},
              "fixed_version": "9.6",
              "cvss_score": 7.5,
              "severity": "High",
              "exploit_available": false,
              "references": []
            }
          ]
        }
        """,
        encoding="utf-8",
    )
    epss_path = tmp_path / "epss.csv"
    epss_path.write_text("cve,epss,percentile\nLOCAL-CVE-DEMO-0001,0.72,0.94\n", encoding="utf-8")
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
                "evidence": "SSH-2.0-OpenSSH_8.9p1",
                "banner": "SSH-2.0-OpenSSH_8.9p1",
                "metadata": {"vendor": "openbsd", "cpe": "cpe:2.3:a:openbsd:openssh:8.9p1"},
            }
        ],
    }

    _, summary, findings = run_vulnerability_intelligence(
        scan_result=scan_result,
        rules_path=rules_path,
        use_cve_feed=True,
        cve_feed_path=feed_path,
        use_epss=True,
        epss_file=epss_path,
    )

    assert summary["epss_enabled"] is True
    assert summary["epss_records_loaded"] == 1
    assert summary["epss_matches_enriched"] == 1
    assert summary["highest_epss_score"] == 0.72
    assert summary["cve_feed_matches"][0]["epss_enriched"] is True
    assert summary["cve_feed_matches"][0]["epss_percentile"] == 0.94
    assert any(finding.source == "epss_importer" for finding in findings)
