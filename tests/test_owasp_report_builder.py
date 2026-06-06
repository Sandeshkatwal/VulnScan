from __future__ import annotations

import json
from datetime import datetime, timezone

from scanner.owasp_report_builder import build_unified_owasp_report, save_markdown_report
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report


def _sample_evidence() -> list[dict[str, object]]:
    return [
        {
            "evidence_id": "ev-a01",
            "source": "owasp_a01",
            "title": "Admin endpoint candidate",
            "owasp_id": "A01:2025",
            "owasp_name": "Broken Access Control",
            "confidence": "Medium",
            "evidence_strength": "weak_indicator",
            "manual_validation_required": True,
        },
        {
            "evidence_id": "ev-a02",
            "source": "owasp_a02",
            "title": "Missing Content-Security-Policy",
            "owasp_id": "A02:2025",
            "owasp_name": "Security Misconfiguration",
            "confidence": "High",
            "evidence_strength": "strong_indicator",
            "manual_validation_required": False,
        },
        {
            "evidence_id": "ev-a05",
            "source": "safe_validation",
            "title": "Reflection candidate",
            "owasp_id": "A05:2025",
            "owasp_name": "Injection",
            "confidence": "Medium",
            "evidence_strength": "weak_indicator",
            "manual_validation_required": True,
        },
    ]


def _sample_scan_result() -> dict[str, object]:
    evidence = _sample_evidence()
    report = build_unified_owasp_report(target="http://127.0.0.1:8000", owasp_evidence_items=evidence, scan_result={"target": "http://127.0.0.1:8000"})
    return {
        "host": "127.0.0.1",
        "target": "http://127.0.0.1:8000",
        "resolved_ip": "127.0.0.1",
        "scan_mode": "web",
        "duration_seconds": 1.0,
        "open_ports": [],
        "findings": [],
        "owasp_assessment_summary": {"enabled": True, "owasp_version": "2025", "generated_at": "2026-06-06T10:00:00+00:00"},
        "owasp_assessment_report": report,
        "owasp_category_results": [],
        "owasp_evidence_items": evidence,
        "owasp_coverage_matrix": report["category_results"],
        "owasp_manual_validation_checklist": report["manual_validation_summary"]["checklist"],
        "owasp_developer_recommendations": report["developer_recommendations"],
        "owasp_coverage_gaps": report["coverage_gaps"],
        "demo_mode": False,
    }


def test_unified_report_contains_required_sections_and_counts() -> None:
    report = build_unified_owasp_report(target="http://127.0.0.1:8000", owasp_evidence_items=_sample_evidence())

    assert report["report_id"].startswith("owasp_assessment_")
    assert report["executive_summary"]["categories_with_indicators_count"] == 3
    assert report["evidence_strength_summary"]["strong_indicators_count"] == 1
    assert report["evidence_strength_summary"]["weak_indicators_count"] == 2
    assert len(report["category_results"]) == 10
    assert report["manual_validation_summary"]["checklist"]
    assert report["developer_recommendations"]
    assert report["coverage_gaps"]


def test_a06_and_a09_default_to_coverage_gap() -> None:
    report = build_unified_owasp_report(target="demo", owasp_evidence_items=_sample_evidence())
    by_id = {row["owasp_id"]: row for row in report["category_results"]}

    assert by_id["A06:2025"]["coverage_status"] == "coverage_gap"
    assert by_id["A06:2025"]["manual_validation_required"] is True
    assert by_id["A09:2025"]["coverage_status"] == "coverage_gap"
    assert by_id["A09:2025"]["manual_validation_required"] is True


def test_quality_score_is_valid_and_not_security_score() -> None:
    report = build_unified_owasp_report(target="demo", owasp_evidence_items=_sample_evidence())
    quality = report["assessment_quality_score"]

    assert 0 <= quality["score"] <= 100
    assert quality["label"] in {"Limited Assessment", "Developing Coverage", "Good OWASP Coverage", "Strong OWASP Coverage"}
    assert "not application security" in quality["limitation"]


def test_markdown_report_is_generated_and_redacted(tmp_path) -> None:
    report = build_unified_owasp_report(
        target="demo",
        owasp_evidence_items=[
            {
                **_sample_evidence()[0],
                "evidence_summary": "Authorization: Bearer secret-token password=secret",
            }
        ],
    )

    path = save_markdown_report(report, tmp_path)
    text = path.read_text(encoding="utf-8")

    assert path.name.startswith("owasp_assessment_")
    assert "# VulScan OWASP Assessment Report" in text
    assert "secret-token" not in text
    assert "password=secret" not in text


def test_json_report_includes_unified_owasp_model(tmp_path) -> None:
    scan_result = _sample_scan_result()
    path = save_json_report(scan_result, "VulScan", "20.9", datetime.now(timezone.utc), datetime.now(timezone.utc), tmp_path)

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["owasp_assessment_report"]["executive_summary"]
    assert payload["owasp_coverage_matrix"]
    assert payload["owasp_manual_validation_checklist"]
    assert payload["owasp_developer_recommendations"]


def test_html_report_includes_owasp_coverage_matrix(tmp_path) -> None:
    scan_result = _sample_scan_result()
    path = save_html_report(scan_result, "VulScan", "20.9", datetime.now(timezone.utc), datetime.now(timezone.utc), tmp_path)
    text = path.read_text(encoding="utf-8")

    assert "OWASP Executive Summary" in text
    assert "OWASP Coverage Matrix" in text
    assert "Developer Remediation Guidance" in text
