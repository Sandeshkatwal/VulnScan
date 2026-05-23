from scanner.api_filters import filter_findings, paginate_items, sort_findings


FINDINGS = [
    {
        "title": "OpenSSH CVE-2026-0001",
        "severity": "High",
        "source": "cve_feed",
        "category": "Vulnerability Intelligence",
        "risk_score": 80,
        "priority_score": 90,
        "priority_label": "Fix First",
        "evidence": "Matched CVE-2026-0001.",
    },
    {
        "title": "HTTP Header",
        "severity": "Medium",
        "source": "web_header_audit",
        "category": "Web",
        "risk_score": 45,
        "priority_score": 50,
        "priority_label": "Fix Soon",
        "evidence": "Missing header.",
    },
    {
        "title": "Info",
        "severity": "Informational",
        "source": "port_scan",
        "category": "Discovery",
        "risk_score": 0,
        "priority_score": None,
        "priority_label": "Monitor",
        "evidence": "Open port.",
    },
]


def test_paginate_items_returns_correct_slice() -> None:
    page, metadata = paginate_items([1, 2, 3, 4], limit=2, offset=1)

    assert page == [2, 3]
    assert metadata["returned"] == 2


def test_pagination_metadata_has_next_and_previous() -> None:
    _page, metadata = paginate_items([1, 2, 3, 4, 5], limit=2, offset=2)

    assert metadata["has_next"] is True
    assert metadata["has_previous"] is True
    assert metadata["next_offset"] == 4
    assert metadata["previous_offset"] == 0


def test_filter_findings_by_severity() -> None:
    assert [item["title"] for item in filter_findings(FINDINGS, {"severity": "high"})] == ["OpenSSH CVE-2026-0001"]


def test_filter_findings_by_source() -> None:
    assert [item["title"] for item in filter_findings(FINDINGS, {"source": "web_header_audit"})] == ["HTTP Header"]


def test_filter_findings_by_category() -> None:
    assert [item["title"] for item in filter_findings(FINDINGS, {"category": "discovery"})] == ["Info"]


def test_filter_findings_by_priority_label() -> None:
    assert [item["title"] for item in filter_findings(FINDINGS, {"priority_label": "Fix First"})] == ["OpenSSH CVE-2026-0001"]


def test_filter_findings_by_min_priority_score() -> None:
    assert [item["title"] for item in filter_findings(FINDINGS, {"min_priority_score": 75})] == ["OpenSSH CVE-2026-0001"]


def test_filter_findings_by_min_risk_score() -> None:
    assert [item["title"] for item in filter_findings(FINDINGS, {"min_risk_score": 40})] == ["OpenSSH CVE-2026-0001", "HTTP Header"]


def test_filter_findings_by_cve() -> None:
    assert [item["title"] for item in filter_findings(FINDINGS, {"cve": "CVE-2026-0001"})] == ["OpenSSH CVE-2026-0001"]


def test_sort_findings_by_priority_score_desc() -> None:
    assert [item["title"] for item in sort_findings(FINDINGS, "priority_score", "desc")] == [
        "OpenSSH CVE-2026-0001",
        "HTTP Header",
        "Info",
    ]


def test_sort_findings_by_severity_order() -> None:
    assert [item["severity"] for item in sort_findings(FINDINGS, "severity", "desc")] == [
        "High",
        "Medium",
        "Informational",
    ]
