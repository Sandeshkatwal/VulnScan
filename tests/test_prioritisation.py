from scanner.prioritisation import build_prioritisation


def _finding(severity: str = "Medium", risk_score: int = 50) -> dict:
    return {
        "id": "FINDING-0001",
        "title": "Unit Finding",
        "severity": severity,
        "category": "Unit",
        "affected_host": "127.0.0.1",
        "affected_port": None,
        "affected_url": None,
        "service": None,
        "evidence": "Local test evidence.",
        "confidence": "High",
        "impact": "Local test impact.",
        "recommendation": "Review.",
        "verification": "Unit test.",
        "limitation": "Local fake data only.",
        "source": "unit",
        "risk_score": risk_score,
        "risk_label": "Medium priority",
        "fix_priority": "Schedule remediation",
        "created_at": "2026-05-22T10:00:00+00:00",
    }


def _asset_context(criticality: str) -> dict:
    return {
        "enabled": True,
        "target": "127.0.0.1",
        "criticality": criticality,
        "criticality_source": "direct",
        "business_owner": "Lab",
        "environment": "local",
        "tags": ["lab"],
    }


def test_critical_asset_increases_priority_score() -> None:
    summary, findings = build_prioritisation([_finding()], _asset_context("critical"), enabled=True)

    assert findings[0]["priority_score"] == 70
    assert "Asset criticality is critical, increasing priority." in findings[0]["priority_reasons"]
    assert summary["critical_asset_findings_count"] == 1


def test_high_asset_increases_priority_score() -> None:
    _, findings = build_prioritisation([_finding()], _asset_context("high"), enabled=True)

    assert findings[0]["priority_score"] == 62


def test_medium_asset_slightly_increases_priority_score() -> None:
    _, findings = build_prioritisation([_finding()], _asset_context("medium"), enabled=True)

    assert findings[0]["priority_score"] == 56
    assert "Asset criticality is medium, slightly increasing priority." in findings[0]["priority_reasons"]


def test_low_asset_does_not_increase_priority_score() -> None:
    _, findings = build_prioritisation([_finding()], _asset_context("low"), enabled=True)

    assert findings[0]["priority_score"] == 50


def test_unknown_asset_does_not_increase_priority_score() -> None:
    _, findings = build_prioritisation([_finding()], _asset_context("unknown"), enabled=True)

    assert findings[0]["priority_score"] == 50
    assert "Asset criticality is unknown, no asset criticality boost applied." in findings[0]["priority_reasons"]


def test_informational_finding_is_not_fix_first_only_from_criticality() -> None:
    _, findings = build_prioritisation(
        [_finding(severity="Informational", risk_score=10)],
        _asset_context("critical"),
        enabled=True,
    )

    assert findings[0]["priority_score"] == 30
    assert findings[0]["priority_label"] == "Monitor"


def test_summary_includes_asset_criticality_fields() -> None:
    summary, _ = build_prioritisation([_finding()], _asset_context("medium"), enabled=True)

    assert summary["asset_criticality_enabled"] is True
    assert summary["asset_criticality"] == "medium"
    assert summary["asset_criticality_source"] == "direct"
    assert summary["medium_asset_findings_count"] == 1


def test_prioritised_findings_include_asset_fields() -> None:
    _, findings = build_prioritisation([_finding()], _asset_context("high"), enabled=True)

    assert findings[0]["asset_criticality"] == "high"
    assert findings[0]["asset_environment"] == "local"
    assert findings[0]["asset_business_owner"] == "Lab"
    assert findings[0]["asset_tags"] == ["lab"]
