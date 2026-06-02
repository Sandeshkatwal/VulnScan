from datetime import datetime
from pathlib import Path

from scanner.owasp_assessment import attach_owasp_assessment, build_owasp_assessment
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report


def test_category_result_counts_weak_and_strong_indicators() -> None:
    assessment = build_owasp_assessment(_scan_result())
    a05 = _category(assessment, "A05:2025")
    assert a05["weak_indicator_count"] == 1
    assert a05["strong_indicator_count"] == 1


def test_coverage_gaps_and_manual_only_categories_are_generated() -> None:
    assessment = build_owasp_assessment(_scan_result())
    gaps = assessment["owasp_coverage_gaps"]
    assert gaps
    a09 = _category(assessment, "A09:2025")
    assert a09["coverage_status"] == "manual_only"


def test_assessment_quality_score_returns_valid_range() -> None:
    summary = build_owasp_assessment(_scan_result())["owasp_assessment_summary"]
    assert 0 <= summary["assessment_quality_score"] <= 100
    assert summary["assessment_quality_label"] in {"Limited", "Developing", "Good Coverage", "Strong Coverage"}


def test_attach_owasp_assessment_adds_report_keys() -> None:
    scan_result = _scan_result()
    attach_owasp_assessment(scan_result)
    assert scan_result["owasp_assessment_summary"]["enabled"] is True
    assert scan_result["owasp_category_results"]
    assert scan_result["owasp_evidence_items"]
    assert scan_result["owasp_coverage_gaps"]


def test_json_report_includes_owasp_assessment(tmp_path: Path) -> None:
    scan_result = _scan_result()
    attach_owasp_assessment(scan_result)
    path = save_json_report(scan_result, "VulScan", "test", datetime.now(), datetime.now(), reports_dir=tmp_path)
    text = path.read_text(encoding="utf-8")
    assert '"owasp_assessment_summary"' in text
    assert '"owasp_category_results"' in text
    assert '"owasp_evidence_items"' in text
    assert '"owasp_coverage_gaps"' in text


def test_html_report_renders_owasp_assessment_section(tmp_path: Path) -> None:
    scan_result = _scan_result()
    attach_owasp_assessment(scan_result)
    path = save_html_report(scan_result, "VulScan", "test", datetime.now(), datetime.now(), reports_dir=tmp_path)
    text = path.read_text(encoding="utf-8")
    assert "OWASP Assessment Engine" in text
    assert "Manual Validation Required" in text


def _category(assessment: dict, owasp_id: str) -> dict:
    return next(item for item in assessment["owasp_category_results"] if item["owasp_id"] == owasp_id)


def _scan_result() -> dict:
    return {
        "host": "owasp-test",
        "resolved_ip": "",
        "scan_mode": "test",
        "duration_seconds": 0,
        "open_ports": [],
        "findings": [
            {
                "title": "Missing Content Security Policy",
                "severity": "Low",
                "category": "Headers",
                "evidence": "Missing CSP header.",
                "confidence": "Medium",
                "recommendation": "Review headers.",
                "source": "web_header_audit",
            }
        ],
        "endpoint_results": [{"normalised_url": "http://127.0.0.1/admin", "endpoint_category": "admin"}],
        "parameter_results": [{"url": "http://127.0.0.1/search?q=test", "parameter_name": "q", "parameter_type": "injection_reflection"}],
        "safe_active_validation_results": [{
            "url": "http://127.0.0.1/search?q=test",
            "parameter": "q",
            "check_name": "reflected_input_observation",
            "indicator_found": True,
            "evidence_summary": {"marker_reflected": True},
        }],
    }
