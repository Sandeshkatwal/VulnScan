"""Evidence Quality Score helpers."""

from __future__ import annotations

from typing import Any


def quality_label(score: int, item: dict[str, Any] | None = None) -> str:
    item = item or {}
    if score < 30 or item.get("secret_detection_status") == "failed" or item.get("redaction_status") == "failed_secret_check":
        return "Blocked"
    if score >= 85:
        return "Excellent Evidence"
    if score >= 70:
        return "Good Evidence"
    if score >= 50:
        return "Needs Improvement"
    return "Weak Evidence"


def calculate_evidence_quality_score(evidence_item: dict[str, Any]) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []
    suggestions: list[str] = []

    checks = [
        ("title", 10, "clear title"),
        ("source_module", 10, "source module present"),
        ("evidence_strength", 10, "evidence strength present"),
        ("confidence", 10, "confidence present"),
        ("safe_summary", 10, "safe summary present"),
    ]
    for field, points, reason in checks:
        if evidence_item.get(field):
            score += points
            reasons.append(reason)
        else:
            suggestions.append(f"Add {field.replace('_', ' ')}.")

    if evidence_item.get("related_target") or evidence_item.get("related_url") or evidence_item.get("related_host"):
        score += 10
        reasons.append("related target or URL present")
    else:
        score -= 10
        suggestions.append("Add related target, URL, or host.")

    if evidence_item.get("related_owasp_categories"):
        score += 10
        reasons.append("OWASP category linked")
    else:
        suggestions.append("Link an OWASP category where applicable.")

    if evidence_item.get("redacted_request_summary") or evidence_item.get("redacted_response_summary"):
        score += 10
        reasons.append("request/response summary redacted")
    else:
        suggestions.append("Add redacted request or response summary when useful.")

    if evidence_item.get("redaction_status") in {"redacted", "not_required"} and evidence_item.get("secret_detection_status") == "passed":
        score += 10
        reasons.append("redaction check passed")

    if evidence_item.get("safe_observed_value") or evidence_item.get("validation_status") or evidence_item.get("evidence_strength") in {"manually_verified_issue", "manually_verified_secure", "confirmed_finding"}:
        score += 10
        reasons.append("manual observation or validation context present")

    if evidence_item.get("attachment_metadata"):
        score += 5
        reasons.append("attachment/reference metadata present")
    if evidence_item.get("timeline_events"):
        score += 5
        reasons.append("timeline events present")

    if not evidence_item.get("safe_summary"):
        score -= 15
    if evidence_item.get("redaction_status") == "pending_redaction":
        score -= 25
    if evidence_item.get("secret_detection_status") == "warning":
        score -= 30
    if evidence_item.get("secret_detection_status") == "failed":
        score -= 60
    if evidence_item.get("redaction_status") == "blocked_from_export":
        score -= 50
    if not evidence_item.get("source_module"):
        score -= 10

    score = max(0, min(100, score))
    return {"score": score, "label": quality_label(score, evidence_item), "reasons": reasons, "suggestions": suggestions}
