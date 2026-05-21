from scanner.risk_score import score_finding


def _finding(epss_score: float | None) -> dict:
    return {
        "title": "Local CVE",
        "severity": "Medium",
        "affected_port": None,
        "service": "ssh",
        "source": "cve_feed",
        "confidence": "High",
        "evidence_details": {
            "cvss_score": 5.0,
            "epss_score": epss_score,
            "exploit_available": False,
        },
    }


def test_high_epss_adds_conservative_risk_boost() -> None:
    base_score, _, _ = score_finding(_finding(None))
    high_score, _, _ = score_finding(_finding(0.72))

    assert high_score > base_score
    assert high_score <= base_score + 8


def test_low_epss_does_not_inflate_risk() -> None:
    base_score, _, _ = score_finding(_finding(None))
    low_score, _, _ = score_finding(_finding(0.1))

    assert low_score == base_score
