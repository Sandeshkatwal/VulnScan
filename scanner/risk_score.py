"""Heuristic risk scoring for VulScan findings."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from scanner.finding import Finding, finding_to_dict


BASE_SEVERITY_SCORES = {
    "Critical": 90,
    "High": 75,
    "Medium": 50,
    "Low": 25,
    "Informational": 10,
}

SENSITIVE_PORTS = {445, 3389, 3306, 5432, 6379}
REMOTE_MANAGEMENT_PORTS = {5985, 5986}


def score_finding(finding: Finding | dict[str, Any]) -> tuple[int, str, str]:
    """Return risk score, risk label, and fix priority for a finding."""
    finding_dict = finding_to_dict(finding)
    score = BASE_SEVERITY_SCORES.get(str(finding_dict.get("severity")), 0)
    affected_port = finding_dict.get("affected_port")
    service = str(finding_dict.get("service") or "").lower()
    source = str(finding_dict.get("source") or "")
    severity = str(finding_dict.get("severity") or "")
    confidence = str(finding_dict.get("confidence") or "")
    evidence_details = finding_dict.get("evidence_details") or {}

    if affected_port in SENSITIVE_PORTS:
        score += 10
    if affected_port in REMOTE_MANAGEMENT_PORTS:
        score += 5
    if service == "telnet":
        score += 20
    if service == "ftp":
        score += 10
    if source == "http_audit" and severity == "Medium":
        score += 5
    if source == "tls_audit" and severity == "High":
        score += 10
    if source in {"vuln_intel", "cve_feed"}:
        cvss_score = _safe_float(evidence_details.get("cvss_score"))
        if cvss_score is not None:
            score = max(score, int(round(cvss_score * 10)))
        epss_score = _safe_float(evidence_details.get("epss_score"))
        if epss_score is not None:
            if epss_score >= 0.7:
                score += 8
            elif epss_score >= 0.2:
                score += 3
        if evidence_details.get("exploit_available") is True:
            score += 5
    if confidence == "Low":
        score -= 10
    if confidence == "Medium":
        score -= 5

    score = max(0, min(100, score))
    risk_label = _risk_label(score)
    return score, risk_label, _fix_priority(risk_label)


def _safe_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def apply_risk_scores(findings: list[Finding | dict[str, Any]]) -> list[Finding | dict[str, Any]]:
    """Apply risk score fields to all findings."""
    scored_findings: list[Finding | dict[str, Any]] = []

    for finding in findings:
        risk_score, risk_label, fix_priority = score_finding(finding)
        if isinstance(finding, Finding):
            scored_findings.append(
                replace(
                    finding,
                    risk_score=risk_score,
                    risk_label=risk_label,
                    fix_priority=fix_priority,
                )
            )
            continue

        scored_finding = finding.copy()
        scored_finding["risk_score"] = risk_score
        scored_finding["risk_label"] = risk_label
        scored_finding["fix_priority"] = fix_priority
        scored_findings.append(scored_finding)

    return scored_findings


def _risk_label(score: int) -> str:
    if score >= 90:
        return "Critical priority"
    if score >= 70:
        return "High priority"
    if score >= 40:
        return "Medium priority"
    if score >= 10:
        return "Low priority"
    return "Informational"


def _fix_priority(risk_label: str) -> str:
    priorities = {
        "Critical priority": "Fix immediately",
        "High priority": "Fix soon",
        "Medium priority": "Schedule remediation",
        "Low priority": "Review when possible",
        "Informational": "Document and monitor",
    }
    return priorities[risk_label]
