"""A01 Broken Access Control candidate engine.

Version 20.6 is candidate and planning only. It does not perform auth bypass,
cross-account testing, privilege changes, or state-changing requests.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.access_control_candidates import (
    assess_api_access_control_candidates,
    assess_function_level_candidates,
    assess_object_identifier_candidates,
    assess_role_permission_indicators,
    assess_sensitive_resource_candidates,
    assess_tenant_boundary_candidates,
    build_a01_evidence_template,
    build_a01_manual_validation_plan,
    collect_a01_candidate_evidence,
)
from scanner.evidence import redact_nested
from scanner.finding import create_finding, finding_to_dict


A01_RULES_PATH = Path("data") / "owasp" / "a01" / "a01_rules.json"
A01_REPORTS_DIR = Path("reports") / "owasp" / "a01"
LIMITATIONS = [
    "A01 Broken Access Control checks are candidate-based and require manual validation.",
    "No auth bypass automation, cross-account testing, credential attack, privilege escalation attempt, or state-changing request is performed.",
    "Object identifiers are normalised where possible and parameter values are not retained unnecessarily.",
    "Use authorised test accounts, approved test tenants, and programme-approved test data only.",
]


class A01RulesError(ValueError):
    """Raised when A01 rules are unavailable or invalid."""


def load_a01_rules(path: str | Path = A01_RULES_PATH) -> dict[str, Any]:
    rules_path = Path(path)
    try:
        payload = json.loads(rules_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise A01RulesError(f"A01 rules file was not found: {rules_path}") from exc
    except json.JSONDecodeError as exc:
        raise A01RulesError(f"A01 rules file is not valid JSON: {rules_path}") from exc
    if payload.get("owasp_id") != "A01:2025":
        raise A01RulesError("A01 rules file must describe A01:2025.")
    if not isinstance(payload.get("rule_groups"), dict):
        raise A01RulesError("A01 rules file must include rule_groups.")
    return payload


def ensure_a01_dirs() -> None:
    A01_RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    A01_REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def assess_a01_access_control(
    *,
    target: str = "",
    endpoint_results: list[dict[str, Any]] | None = None,
    parameter_results: list[dict[str, Any]] | None = None,
    evidence_records: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    ensure_a01_dirs()
    load_a01_rules()
    evidence = collect_a01_candidate_evidence(endpoint_results, parameter_results, evidence_records)
    summary = build_a01_summary(target=target or _first_target(endpoint_results, parameter_results, evidence_records), evidence=evidence)
    findings = build_a01_findings(summary, evidence)
    return redact_nested({"a01_access_control_summary": summary, "a01_access_control_evidence": evidence, "findings": findings})


def attach_a01_access_control(scan_result: dict[str, Any]) -> dict[str, Any]:
    payload = assess_a01_access_control(
        target=str(scan_result.get("target") or scan_result.get("url") or scan_result.get("host") or ""),
        endpoint_results=scan_result.get("endpoint_results") or _endpoints_from_validation(scan_result.get("safe_active_validation_results") or []),
        parameter_results=scan_result.get("parameter_results") or _parameters_from_validation(scan_result.get("safe_active_validation_results") or []),
        evidence_records=scan_result.get("evidence_records") or [],
    )
    findings = list(payload.get("findings", []))
    payload_without_findings = dict(payload)
    payload_without_findings.pop("findings", None)
    scan_result.update(payload_without_findings)
    scan_result.setdefault("findings", [])
    scan_result["findings"].extend(findings)
    return scan_result


def build_a01_summary(target: str, evidence: list[dict[str, Any]]) -> dict[str, Any]:
    interest_counts = Counter(str(item.get("interest_label") or "Informational") for item in evidence)
    group_counts = Counter(str(item.get("rule_group") or "") for item in evidence)
    confidence_order = {"Low": 1, "Medium": 2, "High": 3}
    highest = "Low"
    for item in evidence:
        confidence = str(item.get("confidence") or "Low")
        if confidence_order.get(confidence, 0) > confidence_order.get(highest, 0):
            highest = confidence
    return {
        "enabled": True,
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_evidence_items": len(evidence),
        "high_interest_count": interest_counts.get("High Interest", 0),
        "medium_interest_count": interest_counts.get("Medium Interest", 0),
        "low_interest_count": interest_counts.get("Low Interest", 0),
        "informational_count": interest_counts.get("Informational", 0),
        "manual_validation_required_count": sum(1 for item in evidence if item.get("manual_validation_required")),
        "object_id_candidate_count": group_counts.get("object_level_authorization_candidates", 0),
        "function_level_candidate_count": group_counts.get("function_level_authorization_candidates", 0),
        "tenant_boundary_candidate_count": group_counts.get("tenant_boundary_candidates", 0),
        "sensitive_resource_candidate_count": group_counts.get("sensitive_resource_candidates", 0),
        "role_permission_indicator_count": group_counts.get("role_and_permission_indicators", 0),
        "api_access_control_candidate_count": group_counts.get("api_access_control_candidates", 0),
        "rule_group_counts": dict(group_counts),
        "highest_confidence": highest,
        "top_candidates": [
            {
                "title": item.get("title"),
                "affected_url": item.get("affected_url"),
                "affected_parameter": item.get("affected_parameter"),
                "candidate_score": item.get("candidate_score"),
                "confidence": item.get("confidence"),
                "access_control_candidate_type": item.get("access_control_candidate_type"),
                "manual_test_plan_id": item.get("manual_test_plan_id"),
            }
            for item in sorted(evidence, key=lambda row: int(row.get("candidate_score") or 0), reverse=True)[:10]
        ],
        "recommendations": [
            "Review A01 Broken Access Control candidates using authorised test accounts and programme-approved test data.",
            "Prioritise tenant boundary candidates, role or permission indicators, admin surfaces, and export/download workflows with object identifiers.",
            "Confirm server-side object ownership, function authorization, and tenant isolation manually before reporting impact.",
        ],
        "limitations": LIMITATIONS,
    }


def build_a01_findings(summary: dict[str, Any], evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = [
        finding_to_dict(
            create_finding(
                title="A01 Broken Access Control Candidate Assessment Completed",
                severity="Informational",
                category="OWASP A01 Broken Access Control",
                affected_host=str(summary.get("target") or "owasp-a01"),
                evidence=f"VulScan evaluated available endpoints, parameters, object identifiers, and access-control candidate signals. {summary.get('total_evidence_items', 0)} candidate item(s) were identified.",
                recommendation="Review A01 candidates using authorised test accounts and programme-approved test data.",
                source="owasp_a01",
                confidence=str(summary.get("highest_confidence") or "Low"),
                impact="Access-control candidate evidence is available for manual validation planning.",
                verification="Review a01_access_control_summary and a01_access_control_evidence.",
                limitation="A01 checks are candidate-based and do not perform auth bypass or cross-account testing.",
            )
        )
    ]
    grouped = {
        "object_level_authorization_candidates": (
            "Object-Level Authorization Candidate",
            "Object identifier parameters or paths were observed.",
            "Manually validate object ownership enforcement.",
            "Object identifiers alone do not prove broken access control.",
        ),
        "function_level_authorization_candidates": (
            "Function-Level Authorization Candidate",
            "Admin, management, role, or sensitive function endpoints were observed.",
            "Manually validate authorization using authorised roles.",
            "Endpoint discovery does not prove unauthorised access.",
        ),
        "tenant_boundary_candidates": (
            "Tenant Boundary Candidate",
            "Tenant/workspace/org identifiers were observed in URLs or parameters.",
            "Manually validate tenant isolation using approved test tenants.",
            "VulScan does not access third-party tenant data.",
        ),
    }
    for group, (title, evidence_text, recommendation, limitation) in grouped.items():
        rows = [item for item in evidence if item.get("rule_group") == group]
        if not rows:
            continue
        max_score = max(int(item.get("candidate_score") or 0) for item in rows)
        severity = "Medium" if max_score >= 70 else ("Low" if max_score >= 45 else "Informational")
        findings.append(
            finding_to_dict(
                create_finding(
                    title=title,
                    severity=severity,
                    category="OWASP A01 Broken Access Control",
                    affected_host=str(summary.get("target") or "owasp-a01"),
                    evidence=f"{evidence_text} {len(rows)} candidate item(s) grouped for review.",
                    recommendation=recommendation,
                    source="owasp_a01",
                    confidence="Medium" if max_score >= 45 else "Low",
                    impact="Potential access-control relevance if manual validation confirms missing enforcement.",
                    verification="Review grouped A01 candidate evidence and generated manual validation plans.",
                    limitation=limitation,
                )
            )
        )
    return findings


def build_a01_manual_plan_response(evidence_item: dict[str, Any]) -> dict[str, Any]:
    return {
        "manual_validation_plan": build_a01_manual_validation_plan(evidence_item),
        "evidence_template": build_a01_evidence_template(evidence_item),
    }


def _first_target(*collections: list[dict[str, Any]] | None) -> str:
    for collection in collections:
        for item in collection or []:
            value = str(item.get("url") or item.get("normalised_url") or item.get("affected_url") or item.get("target") or "")
            if value:
                return value
    return ""


def _endpoints_from_validation(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"url": item.get("url") or item.get("affected_url") or "", "endpoint_category": item.get("candidate_type") or item.get("check_name") or ""} for item in results or []]


def _parameters_from_validation(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for item in results or []:
        parameter = str(item.get("parameter") or item.get("affected_parameter") or "")
        if parameter:
            rows.append({"url": item.get("url") or item.get("affected_url") or "", "parameter_name": parameter})
    return rows
