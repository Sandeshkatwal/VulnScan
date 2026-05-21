import json

import pytest

from scanner.cve_feed import (
    CveFeedError,
    build_cve_feed_findings,
    build_cve_feed_summary,
    load_cve_feed,
    match_cve_feed,
    validate_cve_feed,
)


def _feed(items: list[dict]) -> dict:
    return {
        "feed_name": "Unit CVE Feed",
        "feed_version": "1.0",
        "items": items,
    }


def _openssh_item(version: str | None = "8.9p1") -> dict:
    return {
        "asset": "127.0.0.1",
        "host": "127.0.0.1",
        "port": 22,
        "protocol": "tcp",
        "service_name": "ssh",
        "vendor": "openbsd",
        "product": "openssh",
        "version": version,
        "cpe": "cpe:2.3:a:openbsd:openssh:8.9p1",
        "source": "service_detect",
        "evidence": "OpenSSH_8.9p1 banner observed.",
        "confidence": "Medium",
        "metadata": {},
    }


def _openssh_feed_item(**overrides: object) -> dict:
    item = {
        "cve": "LOCAL-CVE-DEMO-UNIT",
        "title": "Demo OpenSSH Local Feed Item",
        "vendor": "openbsd",
        "product": "openssh",
        "cpe_prefix": "cpe:2.3:a:openbsd:openssh",
        "affected_versions": {"less_than": "9.6"},
        "fixed_version": "9.6",
        "cvss_score": 7.5,
        "cvss_vector": "LOCAL-DEMO",
        "severity": "High",
        "exploit_available": False,
        "references": [{"label": "Local", "url": "local-only"}],
        "limitation": "Unit local feed item.",
    }
    item.update(overrides)
    return item


def test_loads_valid_local_cve_feed(tmp_path) -> None:
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(_feed([_openssh_feed_item()])), encoding="utf-8")

    feed = load_cve_feed(path)

    assert feed["feed_name"] == "Unit CVE Feed"
    assert feed["items"][0]["product"] == "openssh"
    assert feed["items"][0]["cvss_score"] == 7.5


def test_rejects_missing_feed_gracefully(tmp_path) -> None:
    with pytest.raises(CveFeedError, match="not found"):
        load_cve_feed(tmp_path / "missing.json")


def test_rejects_invalid_json_gracefully(tmp_path) -> None:
    path = tmp_path / "feed.json"
    path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(CveFeedError, match="not valid JSON"):
        load_cve_feed(path)


def test_validates_feed_with_missing_items() -> None:
    with pytest.raises(CveFeedError, match="items"):
        validate_cve_feed({"feed_name": "Bad", "feed_version": "1.0"})


def test_matches_by_cpe_prefix_and_less_than() -> None:
    matches = match_cve_feed([_openssh_item()], _feed([_openssh_feed_item()]))

    assert matches[0]["match_status"] == "matched"
    assert matches[0]["identity_method"] == "cpe_prefix"
    assert matches[0]["affected_condition"]["operator"] == "less_than"
    assert matches[0]["match_confidence"] == "High"


def test_matches_by_vendor_product() -> None:
    item = _openssh_item()
    item["cpe"] = None

    matches = match_cve_feed([item], _feed([_openssh_feed_item(cpe_prefix=None)]))

    assert matches[0]["match_status"] == "matched"
    assert matches[0]["identity_method"] == "vendor_product"


def test_matches_affected_versions_between() -> None:
    matches = match_cve_feed(
        [_openssh_item("8.9p1")],
        _feed([_openssh_feed_item(affected_versions={"between": ["8.0", "9.5"]})]),
    )

    assert matches[0]["match_status"] == "matched"
    assert matches[0]["affected_condition"]["operator"] == "between"


def test_missing_inventory_version_is_insufficient_evidence_and_no_cve_finding() -> None:
    matches = match_cve_feed([_openssh_item(None)], _feed([_openssh_feed_item()]))
    summary = build_cve_feed_summary(feed=_feed([_openssh_feed_item()]), matches=matches, enabled=True)
    findings = build_cve_feed_findings(matches, summary, {"host": "127.0.0.1"})

    assert matches[0]["match_status"] == "insufficient_evidence"
    assert summary["cve_feed_insufficient_evidence_count"] == 1
    assert summary["cve_feed_matches_found"] == 0
    assert len([finding for finding in findings if finding.title.startswith("LOCAL-CVE")]) == 0


def test_includes_cvss_fixed_version_and_generates_findings() -> None:
    matches = match_cve_feed([_openssh_item()], _feed([_openssh_feed_item()]))
    summary = build_cve_feed_summary(feed=_feed([_openssh_feed_item()]), matches=matches, enabled=True)
    findings = build_cve_feed_findings(matches, summary, {"host": "127.0.0.1"})

    assert summary["cve_feed_highest_cvss"] == 7.5
    assert summary["cve_feed_matches_found"] == 1
    assert findings[0].title == "Local CVE Feed Import Completed"
    assert findings[1].source == "cve_feed"
    assert findings[1].evidence_details["cvss_score"] == 7.5
    assert findings[1].evidence_details["fixed_version"] == "9.6"
    assert "version 8.9p1" in findings[1].evidence
    assert "system is vulnerable" not in findings[1].evidence.lower()
