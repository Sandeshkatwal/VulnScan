"""Professional Finding Builder for safe evidence-linked finding drafts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scanner.evidence_export_safety import can_export_evidence
from scanner.evidence_redaction import redact_mapping_values, redact_secrets, validate_redaction
from scanner.evidence_vault import load_evidence_item
from scanner.finding_models import build_professional_finding, now_iso, normalise_severity
from scanner.report_remediation_library import remediation_text


FINDINGS_DIR = Path("data") / "findings"
SEVERITY_BASE = {"Informational": 5, "Low": 20, "Medium": 45, "High": 70, "Critical": 90}
CONFIDENCE_WEIGHT = {"Low": 0.55, "Medium": 0.75, "High": 0.9, "Confirmed": 1.0}
STRENGTH_BONUS = {"informational": -10, "weak_indicator": -5, "strong_indicator": 5, "manually_verified_secure": -20, "manually_verified_issue": 10, "confirmed_finding": 12}


def ensure_findings_dir() -> None:
    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)


def finding_path(finding_id: str) -> Path:
    safe_id = "".join(ch for ch in finding_id if ch.isalnum() or ch in {"-", "_"}) or "finding"
    return FINDINGS_DIR / f"{safe_id}.json"


def save_finding(finding: dict[str, Any]) -> Path:
    ensure_findings_dir()
    safe = redact_mapping_values(apply_finding_wording_policy(dict(finding)))
    path = finding_path(str(safe["finding_id"]))
    path.write_text(json.dumps(safe, indent=2), encoding="utf-8")
    return path


def load_finding(finding_id: str) -> dict[str, Any] | None:
    path = finding_path(finding_id)
    if not path.exists():
        ensure_findings_dir()
        for candidate in FINDINGS_DIR.glob("*.json"):
            try:
                payload = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict) and payload.get("finding_id") == finding_id:
                return redact_mapping_values(payload)
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return redact_mapping_values(payload) if isinstance(payload, dict) else None


def list_findings() -> list[dict[str, Any]]:
    ensure_findings_dir()
    findings: list[dict[str, Any]] = []
    for path in sorted(FINDINGS_DIR.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict) and payload.get("finding_id"):
            findings.append(redact_mapping_values(payload))
    return findings


def load_findings_file(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and "findings" in payload:
        payload = payload["findings"]
    if isinstance(payload, dict) and payload.get("finding_id"):
        payload = [payload]
    if not isinstance(payload, list):
        raise ValueError("Findings file must contain one finding or a list of findings.")
    return [redact_mapping_values(item) for item in payload if isinstance(item, dict)]


def evidence_safety_for_references(evidence_ids: list[str]) -> dict[str, Any]:
    checked = []
    blocked = []
    for evidence_id in evidence_ids:
        item = load_evidence_item(evidence_id)
        if item is None:
            blocked.append({"evidence_id": evidence_id, "reasons": ["Evidence Item was not found."]})
            continue
        check = can_export_evidence(item)
        checked.append({"evidence_id": evidence_id, "export_allowed": check["export_allowed"], "reasons": check["reasons"]})
        if not check["export_allowed"]:
            blocked.append({"evidence_id": evidence_id, "reasons": check["reasons"]})
    return {"export_allowed": not blocked, "checked_evidence": checked, "blocked_evidence": blocked}


def apply_finding_wording_policy(finding: dict[str, Any]) -> dict[str, Any]:
    updated = dict(finding)
    validation = str(updated.get("validation_status") or "candidate")
    title = str(updated.get("title") or "Professional Finding Draft")
    current_summary = redact_secrets(str(updated.get("technical_summary") or ""))
    if validation in {"candidate", "indicator_only", "manual_validation_required"}:
        prefix = "VulScan identified a candidate requiring manual validation. This indicator suggests a possible area for review. The evidence does not confirm exploitability."
        updated["confidence"] = "High" if updated.get("confidence") == "Confirmed" else updated.get("confidence", "Low")
    elif validation == "manually_verified_issue" or updated.get("evidence_strength") == "confirmed_finding":
        prefix = "Manual validation confirmed that observed behaviour indicates a security issue. The issue should be remediated and retested."
        updated["confidence"] = "Confirmed"
    elif validation == "manually_verified_secure":
        prefix = "Manual validation did not confirm a vulnerability. Expected security control was observed."
    elif validation == "false_positive":
        prefix = "This item was marked false positive based on manual review."
    elif validation == "retest_passed":
        prefix = "Retest indicates the issue has been remediated."
    elif validation == "retest_failed":
        prefix = "Retest indicates remediation was not fully effective and follow-up is required."
    else:
        prefix = "This Technical Finding is provided for professional review."
    if not current_summary.startswith(prefix):
        updated["technical_summary"] = f"{prefix} {current_summary}".strip()
    if not updated.get("executive_summary"):
        updated["executive_summary"] = f"{title}: {prefix}"
    return updated


def calculate_finding_risk_score(finding: dict[str, Any]) -> dict[str, Any]:
    severity = normalise_severity(finding.get("severity"))
    confidence = str(finding.get("confidence") or "Low")
    base = SEVERITY_BASE[severity]
    score = base * CONFIDENCE_WEIGHT.get(confidence, 0.55)
    score += STRENGTH_BONUS.get(str(finding.get("evidence_strength") or "informational"), 0)
    if any("admin" in str(role).lower() or "privileged" in str(role).lower() for role in finding.get("affected_roles") or []):
        score += 5
    if any(str(cat).startswith("A01") or str(cat).startswith("A07") for cat in finding.get("owasp_categories") or []):
        score += 4
    if finding.get("retest_status") == "retest_passed" or finding.get("validation_status") in {"retest_passed", "manually_verified_secure", "false_positive"}:
        score = min(score, 15)
    if confidence == "Low":
        score = min(score, 55)
    score = max(0, min(100, round(score)))
    suggestion = "Critical" if score >= 90 else "High" if score >= 70 else "Medium" if score >= 40 else "Low" if score >= 15 else "Informational"
    return {
        "risk_score": score,
        "severity_suggestion": suggestion,
        "confidence_explanation": f"Confidence is {confidence}; candidate and low-confidence indicators are not overstated.",
        "risk_rationale": f"Risk score combines severity {severity}, confidence {confidence}, evidence strength {finding.get('evidence_strength')}, OWASP context, and retest status {finding.get('retest_status')}.",
    }


def _finalise_finding(finding: dict[str, Any]) -> dict[str, Any]:
    safety = evidence_safety_for_references(list(finding.get("evidence_references") or []))
    warnings = list(finding.get("warnings") or [])
    if not safety["export_allowed"]:
        finding["status"] = "draft"
        warnings.append("Linked evidence did not pass export safety checks; export is blocked until resolved.")
    finding["export_safety_status"] = safety
    if not finding.get("remediation"):
        finding["remediation"] = remediation_text(list(finding.get("owasp_categories") or []), str(finding.get("finding_type") or ""))
    risk = calculate_finding_risk_score(finding)
    finding["risk_score"] = risk["risk_score"]
    finding["risk_rating"] = risk
    finding["warnings"] = warnings
    finding["updated_at"] = now_iso()
    return apply_finding_wording_policy(finding)


def build_finding_from_evidence_vault_item(evidence_item: dict[str, Any]) -> dict[str, Any]:
    strength = str(evidence_item.get("evidence_strength") or "informational")
    validation = "manually_verified_issue" if strength in {"manually_verified_issue", "confirmed_finding"} else "manually_verified_secure" if strength == "manually_verified_secure" else "manual_validation_required"
    finding = build_professional_finding(
        title=evidence_item.get("title") or "Evidence-backed Finding Draft",
        finding_type="evidence_note" if validation != "manually_verified_issue" else "manually_verified_issue",
        owasp_categories=evidence_item.get("related_owasp_categories") or [],
        affected_targets=[evidence_item.get("related_target") or evidence_item.get("related_host") or ""],
        affected_urls=[evidence_item.get("related_url") or ""],
        severity=evidence_item.get("severity_context") or "Informational",
        confidence=evidence_item.get("confidence") or "Low",
        evidence_strength=strength,
        validation_status=validation,
        technical_summary=evidence_item.get("safe_summary") or "",
        evidence_references=[evidence_item.get("evidence_id")],
        evidence_quality_summary={"score": evidence_item.get("evidence_quality_score"), "label": evidence_item.get("evidence_quality_label")},
        source_modules=[evidence_item.get("source_module") or "evidence_vault"],
    )
    return _finalise_finding(finding)


def build_finding_from_owasp_evidence(owasp_evidence_item: dict[str, Any]) -> dict[str, Any]:
    finding = build_professional_finding(
        title=owasp_evidence_item.get("title") or owasp_evidence_item.get("category") or "OWASP Indicator Finding Draft",
        finding_type="owasp_indicator",
        owasp_categories=[owasp_evidence_item.get("category") or owasp_evidence_item.get("owasp_category") or ""],
        affected_urls=[owasp_evidence_item.get("affected_url") or owasp_evidence_item.get("url") or ""],
        severity=owasp_evidence_item.get("severity") or "Informational",
        confidence=owasp_evidence_item.get("confidence") or "Low",
        evidence_strength=owasp_evidence_item.get("evidence_strength") or "weak_indicator",
        validation_status="manual_validation_required",
        technical_summary=owasp_evidence_item.get("evidence_summary") or owasp_evidence_item.get("observed_signal") or "",
        source_modules=["owasp_assessment"],
    )
    return _finalise_finding(finding)


def build_finding_from_access_control_test(test_plan: dict[str, Any], observation: dict[str, Any] | None = None) -> dict[str, Any]:
    observed = observation or {}
    issue = observed.get("observed_access_result") == "unexpectedly_allowed"
    finding = build_professional_finding(
        title=f"Access Control Review: {test_plan.get('endpoint') or test_plan.get('url') or 'endpoint'}",
        finding_type="access_control_issue",
        owasp_categories=["A01:2025"],
        affected_urls=[test_plan.get("endpoint") or test_plan.get("url") or ""],
        affected_roles=[test_plan.get("role") or test_plan.get("role_label") or ""],
        severity="Medium" if issue else "Informational",
        confidence="Confirmed" if issue else "Low",
        evidence_strength="manually_verified_issue" if issue else "strong_indicator",
        validation_status="manually_verified_issue" if issue else "manual_validation_required",
        technical_summary=observed.get("evidence_summary") or test_plan.get("expected_behavior") or "",
        safe_reproduction_notes="Use the Access Control Manual Test Planner record. Do not include unsafe request payloads.",
        source_modules=["access_control_test_planner"],
    )
    return _finalise_finding(finding)


def build_finding_from_parameter_replay_plan(replay_plan: dict[str, Any], observation: dict[str, Any] | None = None) -> dict[str, Any]:
    observed = observation or {}
    issue = observed.get("observed_access_result") in {"unexpectedly_allowed", "reflected_with_context_risk"}
    finding = build_professional_finding(
        title=f"Parameter Replay Review: {replay_plan.get('parameter') or 'parameter'}",
        finding_type="access_control_issue",
        owasp_categories=["A01:2025"],
        affected_urls=[replay_plan.get("endpoint") or ""],
        affected_parameters=[replay_plan.get("parameter") or ""],
        severity="Medium" if issue else "Informational",
        confidence="Confirmed" if issue else "Low",
        evidence_strength="manually_verified_issue" if issue else "strong_indicator",
        validation_status="manually_verified_issue" if issue else "manual_validation_required",
        technical_summary=observed.get("evidence_summary") or replay_plan.get("intent") or "",
        safe_reproduction_notes="Use redacted request templates only. Do not include tokens, cookies, passwords, or unsafe payloads.",
        source_modules=["parameter_replay_planner"],
    )
    return _finalise_finding(finding)


def build_finding_from_business_logic_plan(review_plan: dict[str, Any], observation: dict[str, Any] | None = None) -> dict[str, Any]:
    observed = observation or {}
    issue = observed.get("observed_result") in {"unexpected_success", "control_missing"}
    finding = build_professional_finding(
        title=f"Business Logic Review: {review_plan.get('workflow') or review_plan.get('workflow_name') or 'workflow'}",
        finding_type="business_logic_issue",
        owasp_categories=["A04:2025"],
        affected_urls=[review_plan.get("endpoint") or ""],
        affected_workflows=[review_plan.get("workflow") or review_plan.get("workflow_name") or ""],
        severity="Medium" if issue else "Informational",
        confidence="Confirmed" if issue else "Low",
        evidence_strength="manually_verified_issue" if issue else "strong_indicator",
        validation_status="manually_verified_issue" if issue else "manual_validation_required",
        technical_summary=observed.get("evidence_summary") or review_plan.get("review_objective") or "",
        source_modules=["business_logic_review"],
    )
    return _finalise_finding(finding)


def build_finding_from_vuln_intel_match(vuln_intel_item: dict[str, Any]) -> dict[str, Any]:
    finding = build_professional_finding(
        title=vuln_intel_item.get("title") or vuln_intel_item.get("cve") or "Vulnerability Intelligence Match",
        finding_type="vulnerability_intelligence_match",
        owasp_categories=vuln_intel_item.get("owasp_categories") or ["A03:2025"],
        affected_targets=[vuln_intel_item.get("host") or vuln_intel_item.get("target") or ""],
        affected_components=[vuln_intel_item.get("component") or vuln_intel_item.get("package") or ""],
        severity=vuln_intel_item.get("severity") or vuln_intel_item.get("risk_label") or "Informational",
        confidence=vuln_intel_item.get("confidence") or "Low",
        evidence_strength="strong_indicator",
        validation_status="manual_validation_required",
        technical_summary=vuln_intel_item.get("summary") or vuln_intel_item.get("evidence") or "",
        source_modules=["vulnerability_intelligence"],
    )
    return _finalise_finding(finding)


def build_finding_from_manual_input(data: dict[str, Any]) -> dict[str, Any]:
    safe_data = redact_mapping_values(data)
    text = json.dumps(safe_data, sort_keys=True, default=str)
    check = validate_redaction(text)
    finding = build_professional_finding(**safe_data)
    if not check["passed"]:
        finding["status"] = "draft"
        finding.setdefault("warnings", []).append("Manual finding input contained secret-like content and was redacted.")
    return _finalise_finding(finding)
