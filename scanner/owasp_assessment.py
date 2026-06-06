"""OWASP Assessment Engine foundation for report-ready category results."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.finding import create_finding, finding_to_dict
from scanner.owasp_evidence import CONFIDENCE_ORDER, STRENGTH_ORDER, build_owasp_evidence_items, strongest_item
from scanner.owasp_report_builder import build_unified_owasp_report
from scanner.owasp_rules import OWASPAssessmentRulesError, categories_by_id, load_owasp_assessment_rules


ASSESSMENT_DATA_DIR = Path("data") / "owasp" / "assessment"
ASSESSMENT_REPORTS_DIR = Path("reports") / "owasp"
ASSESSMENT_LIMITATIONS = [
    "OWASP Assessment Engine results are evidence and coverage oriented, not a security rating.",
    "No indicator found does not mean the category is secure; it may mean the category was not assessed or requires authenticated/manual testing.",
    "Confirmed Finding is used only when supplied evidence is already strong enough to support that status.",
]


def assess_owasp_category(category: dict[str, Any], evidence_items: list[dict[str, Any]]) -> dict[str, Any]:
    category_items = [item for item in evidence_items if item.get("owasp_id") == category.get("owasp_id")]
    counts = Counter(str(item.get("evidence_strength") or "") for item in category_items)
    confirmed_count = counts.get("confirmed_finding", 0)
    strong_count = counts.get("strong_indicator", 0)
    weak_count = counts.get("weak_indicator", 0)
    manual_count = sum(1 for item in category_items if item.get("manual_validation_required"))
    strongest = strongest_item(category_items)
    if confirmed_count:
        status = "confirmed"
        coverage = "assessed"
    elif strong_count or weak_count or counts.get("informational", 0):
        status = "needs_manual_validation" if manual_count else "detected_indicator"
        coverage = "partially_assessed" if manual_count else "assessed"
    elif category.get("manual_validation_required"):
        status = "coverage_gap"
        coverage = "manual_only"
    else:
        status = "not_assessed"
        coverage = "not_assessed"
    return {
        "owasp_id": category.get("owasp_id"),
        "name": category.get("name"),
        "assessment_status": status,
        "highest_confidence": strongest.get("confidence") if strongest else "Low",
        "evidence_count": len(category_items),
        "confirmed_count": confirmed_count,
        "strong_indicator_count": strong_count,
        "weak_indicator_count": weak_count,
        "manual_validation_required_count": manual_count,
        "coverage_status": coverage,
        "top_evidence": category_items[:5],
        "recommendation_themes": category.get("recommendation_themes") or [],
        "limitations": category.get("limitations") or "",
    }


def build_owasp_assessment(scan_result: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
    rules = kwargs.pop("rules", None) or load_owasp_assessment_rules()
    categories = rules.get("categories", [])
    scan_result = scan_result or {}
    evidence_items = build_owasp_evidence_items(scan_result, rules=rules, **kwargs)
    category_results = [assess_owasp_category(category, evidence_items) for category in categories]
    coverage_gaps = _coverage_gaps(category_results)
    summary = _build_summary(scan_result, evidence_items, category_results, coverage_gaps)
    unified_report = build_unified_owasp_report(
        target=str(scan_result.get("target") or scan_result.get("host") or ""),
        owasp_assessment_summary=summary,
        owasp_category_results=category_results,
        owasp_evidence_items=evidence_items,
        owasp_coverage_gaps=coverage_gaps,
        scan_result=scan_result,
    )
    return {
        "owasp_assessment_summary": summary,
        "owasp_category_results": category_results,
        "owasp_evidence_items": evidence_items,
        "owasp_coverage_gaps": coverage_gaps,
        "owasp_assessment_report": unified_report,
        "owasp_coverage_matrix": unified_report["category_results"],
        "owasp_manual_validation_checklist": unified_report["manual_validation_summary"]["checklist"],
        "owasp_developer_recommendations": unified_report["developer_recommendations"],
    }


def attach_owasp_assessment(scan_result: dict[str, Any]) -> dict[str, Any]:
    assessment = build_owasp_assessment(scan_result)
    scan_result.update(assessment)
    scan_result.setdefault("findings", [])
    scan_result["findings"].append(_assessment_completed_finding(assessment["owasp_assessment_summary"]))
    return scan_result


def ensure_owasp_dirs() -> None:
    ASSESSMENT_DATA_DIR.mkdir(parents=True, exist_ok=True)
    ASSESSMENT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _build_summary(
    scan_result: dict[str, Any],
    evidence_items: list[dict[str, Any]],
    category_results: list[dict[str, Any]],
    coverage_gaps: list[dict[str, Any]],
) -> dict[str, Any]:
    strength_counts = Counter(str(item.get("evidence_strength") or "") for item in evidence_items)
    categories_with_evidence = [result for result in category_results if result.get("evidence_count", 0) > 0]
    score = _quality_score(evidence_items, category_results)
    return {
        "enabled": True,
        "owasp_version": "2025",
        "target": scan_result.get("host") or scan_result.get("target") or "",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_evidence_items": len(evidence_items),
        "confirmed_findings_count": strength_counts.get("confirmed_finding", 0),
        "strong_indicators_count": strength_counts.get("strong_indicator", 0),
        "weak_indicators_count": strength_counts.get("weak_indicator", 0),
        "manual_validation_required_count": sum(1 for item in evidence_items if item.get("manual_validation_required")),
        "categories_assessed_count": sum(1 for result in category_results if result.get("coverage_status") in {"assessed", "partially_assessed"}),
        "categories_with_indicators_count": len(categories_with_evidence),
        "coverage_gaps_count": len(coverage_gaps),
        "highest_signal_categories": _highest_signal_categories(category_results),
        "assessment_quality_score": score,
        "assessment_quality_label": _quality_label(score),
        "limitations": ASSESSMENT_LIMITATIONS,
    }


def _quality_score(evidence_items: list[dict[str, Any]], category_results: list[dict[str, Any]]) -> int:
    categories_with_evidence = sum(1 for result in category_results if result.get("evidence_count", 0) > 0)
    strong = sum(1 for item in evidence_items if item.get("evidence_strength") == "strong_indicator")
    confirmed = sum(1 for item in evidence_items if item.get("evidence_strength") == "confirmed_finding")
    manual_only = sum(1 for result in category_results if result.get("coverage_status") == "manual_only")
    gaps = sum(1 for result in category_results if result.get("coverage_status") in {"coverage_gap", "not_assessed", "manual_only"})
    score = categories_with_evidence * 7 + min(strong * 5, 25) + min(confirmed * 8, 20) - manual_only * 3 - gaps * 2
    if evidence_items:
        score += 10
    return max(0, min(100, score))


def _quality_label(score: int) -> str:
    if score >= 80:
        return "Strong Coverage"
    if score >= 55:
        return "Good Coverage"
    if score >= 25:
        return "Developing"
    return "Limited"


def _highest_signal_categories(category_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked = sorted(
        [result for result in category_results if result.get("evidence_count", 0) > 0],
        key=lambda result: (
            int(result.get("confirmed_count", 0)),
            int(result.get("strong_indicator_count", 0)),
            int(result.get("weak_indicator_count", 0)),
            CONFIDENCE_ORDER.get(str(result.get("highest_confidence")), 0),
        ),
        reverse=True,
    )
    return [
        {
            "owasp_id": result.get("owasp_id"),
            "owasp_name": result.get("name"),
            "evidence_count": result.get("evidence_count", 0),
            "highest_confidence": result.get("highest_confidence", "Low"),
        }
        for result in ranked[:3]
    ]


def _coverage_gaps(category_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    gaps = []
    for result in category_results:
        if result.get("evidence_count", 0) == 0 or result.get("coverage_status") in {"manual_only", "coverage_gap", "not_assessed"}:
            gaps.append(
                {
                    "owasp_id": result.get("owasp_id"),
                    "owasp_name": result.get("name"),
                    "coverage_status": result.get("coverage_status"),
                    "explanation": "No indicator found does not mean the category is secure. It may mean the category was not assessed or requires authenticated/manual testing.",
                    "manual_validation_required": result.get("coverage_status") == "manual_only",
                }
            )
    return gaps


def _assessment_completed_finding(summary: dict[str, Any]) -> dict[str, Any]:
    return finding_to_dict(
        create_finding(
            title="OWASP Assessment Engine Completed",
            severity="Informational",
            category="OWASP Assessment Engine",
            affected_host="owasp-assessment",
            evidence=f"Assessment generated {summary.get('total_evidence_items', 0)} OWASP evidence item(s) across {summary.get('categories_with_indicators_count', 0)} categories.",
            recommendation="Review OWASP Category Results, OWASP Evidence, OWASP Coverage, and Manual Validation Required sections.",
            source="owasp_assessment",
            confidence="High",
            impact="Report-ready OWASP Top 10:2025 category results were generated from existing VulScan evidence.",
            verification="Review owasp_assessment_summary, owasp_category_results, owasp_evidence_items, and owasp_coverage_gaps.",
            limitation="Assessment quality score reflects coverage and evidence quality, not application security posture.",
        )
    )
