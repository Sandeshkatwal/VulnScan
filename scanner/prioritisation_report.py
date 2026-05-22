"""Fix-first dashboard reporting for prioritised VulScan findings."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from scanner.finding import Finding, create_finding


DASHBOARD_LIMIT = 10
PRIORITY_LABELS = ("Fix First", "Fix Soon", "Monitor", "Informational")
SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
ASSET_CRITICALITIES = ("critical", "high", "medium", "low", "unknown")
EXPLOIT_MATURITIES = ("none", "unknown", "poc", "weaponized", "active_exploitation_reported")


def build_fix_first_dashboard(
    *,
    target: str,
    findings: list[dict[str, Any]] | None = None,
    prioritised_findings: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    top_limit: int = DASHBOARD_LIMIT,
) -> dict[str, Any]:
    """Build dashboard, distributions, top list, action plan, and executive summary."""
    findings = findings or []
    prioritised = [_normalise_prioritised_finding(item) for item in (prioritised_findings or [])]
    prioritised.sort(key=lambda item: (-_safe_int(item.get("priority_score")), str(item.get("title") or "")))
    generated = generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    distribution = build_priority_distribution(prioritised)
    top_findings = build_top_fix_first_findings(prioritised, limit=top_limit)
    action_plan = build_remediation_action_plan(prioritised)
    highest = prioritised[0] if prioritised else {}

    dashboard = {
        "enabled": True,
        "generated_at": generated,
        "target": str(target or ""),
        "total_findings": len(findings),
        "total_prioritised_findings": len(prioritised),
        "fix_first_count": distribution["by_label"]["Fix First"],
        "fix_soon_count": distribution["by_label"]["Fix Soon"],
        "monitor_count": distribution["by_label"]["Monitor"],
        "informational_count": distribution["by_label"]["Informational"],
        "highest_priority_score": _safe_int(highest.get("priority_score")) if highest else 0,
        "highest_priority_title": str(highest.get("title") or ""),
        "highest_priority_source": str(highest.get("source") or ""),
        "critical_asset_findings_count": distribution["by_asset_criticality"]["critical"],
        "high_asset_findings_count": distribution["by_asset_criticality"]["high"],
        "exploitable_metadata_count": _count_exploit_metadata(prioritised),
        "active_exploitation_reported_count": sum(
            1 for item in prioritised if _evidence_bool(item, "active_exploitation_reported")
        ),
        "high_epss_count": sum(1 for item in prioritised if _safe_float(_evidence_value(item, "epss_score")) >= 0.7),
        "high_cvss_count": sum(1 for item in prioritised if _safe_float(_evidence_value(item, "cvss_score")) >= 7.0),
        "overdue_remediation_count": _count_overdue_remediation(prioritised),
        "top_recommended_actions": _top_recommended_actions(top_findings),
        "dashboard_limitations": [
            "The dashboard is generated from existing prioritised findings and does not perform new scanning or exploit checks.",
            "Rankings are decision-support outputs and require human validation before remediation decisions.",
            "SLA hints are generic and should be customised for local policy and business impact.",
        ],
    }
    executive_summary = build_executive_summary(dashboard)
    return {
        "fix_first_dashboard": dashboard,
        "priority_distribution": distribution,
        "top_fix_first_findings": top_findings,
        "remediation_action_plan": action_plan,
        "executive_summary": executive_summary,
    }


def disabled_fix_first_dashboard(target: str) -> dict[str, Any]:
    """Return disabled dashboard defaults for reports."""
    return {
        "fix_first_dashboard": {
            "enabled": False,
            "generated_at": "",
            "target": str(target or ""),
            "total_findings": 0,
            "total_prioritised_findings": 0,
            "fix_first_count": 0,
            "fix_soon_count": 0,
            "monitor_count": 0,
            "informational_count": 0,
            "highest_priority_score": 0,
            "highest_priority_title": "",
            "highest_priority_source": "",
            "critical_asset_findings_count": 0,
            "high_asset_findings_count": 0,
            "exploitable_metadata_count": 0,
            "active_exploitation_reported_count": 0,
            "high_epss_count": 0,
            "high_cvss_count": 0,
            "overdue_remediation_count": 0,
            "top_recommended_actions": [],
            "dashboard_limitations": ["Fix-first dashboard was not enabled."],
        },
        "priority_distribution": _empty_distribution(),
        "top_fix_first_findings": [],
        "remediation_action_plan": {
            "immediate_actions": [],
            "planned_actions": [],
            "monitoring_actions": [],
            "informational_actions": [],
        },
        "executive_summary": "Fix-first dashboard was not enabled.",
    }


def build_priority_distribution(prioritised_findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Count prioritised findings by dashboard dimensions."""
    distribution = _empty_distribution()
    for finding in prioritised_findings:
        label = _normalise_priority_label(finding.get("priority_label"))
        severity = str(finding.get("severity") or "Informational")
        source = _normalise_source(finding.get("source"))
        criticality = _normalise_asset_criticality(finding.get("asset_criticality"))
        maturity = _normalise_exploit_maturity(_evidence_value(finding, "exploit_maturity"))

        distribution["by_label"][label] += 1
        distribution["by_severity"][severity if severity in SEVERITIES else "Informational"] += 1
        distribution["by_source"][source] = distribution["by_source"].get(source, 0) + 1
        distribution["by_asset_criticality"][criticality] += 1
        distribution["by_exploit_maturity"][maturity] += 1
    return distribution


def build_top_fix_first_findings(
    prioritised_findings: list[dict[str, Any]],
    limit: int = DASHBOARD_LIMIT,
) -> list[dict[str, Any]]:
    """Return ranked top prioritised findings for fix-first review."""
    rows: list[dict[str, Any]] = []
    for rank, finding in enumerate(prioritised_findings[: max(0, limit)], start=1):
        rows.append(
            {
                "rank": rank,
                "title": str(finding.get("title") or ""),
                "source": str(finding.get("source") or ""),
                "category": str(finding.get("category") or ""),
                "severity": str(finding.get("severity") or "Informational"),
                "priority_score": _safe_int(finding.get("priority_score")),
                "priority_label": _normalise_priority_label(finding.get("priority_label")),
                "asset_criticality": _normalise_asset_criticality(finding.get("asset_criticality")),
                "asset_exposure": _asset_exposure(finding),
                "cvss_score": _evidence_value(finding, "cvss_score"),
                "epss_score": _evidence_value(finding, "epss_score"),
                "exploit_available": _evidence_bool(finding, "exploit_available"),
                "exploit_maturity": _normalise_exploit_maturity(_evidence_value(finding, "exploit_maturity")),
                "active_exploitation_reported": _evidence_bool(finding, "active_exploitation_reported"),
                "remediation_status": str(finding.get("remediation_status") or "Not tracked"),
                "recommended_action": _recommended_action(finding),
                "sla_hint": _sla_hint(finding),
                "priority_reasons": list(finding.get("priority_reasons") or []),
                "evidence": str(finding.get("evidence") or ""),
                "limitation": str(finding.get("limitation") or ""),
            }
        )
    return rows


def build_remediation_action_plan(prioritised_findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group prioritised findings into dashboard action buckets."""
    plan = {
        "immediate_actions": [],
        "planned_actions": [],
        "monitoring_actions": [],
        "informational_actions": [],
    }
    for finding in prioritised_findings:
        action = _action_item(finding)
        if _is_immediate_action(finding):
            plan["immediate_actions"].append(action)
        elif _normalise_priority_label(finding.get("priority_label")) == "Fix Soon":
            plan["planned_actions"].append(action)
        elif str(finding.get("severity") or "") == "Informational":
            plan["informational_actions"].append(action)
        else:
            plan["monitoring_actions"].append(action)
    return plan


def build_executive_summary(dashboard: dict[str, Any]) -> str:
    """Generate concise factual dashboard text."""
    total = _safe_int(dashboard.get("total_prioritised_findings"))
    fix_first = _safe_int(dashboard.get("fix_first_count"))
    fix_soon = _safe_int(dashboard.get("fix_soon_count"))
    drivers: list[str] = []
    if _safe_int(dashboard.get("high_cvss_count")):
        drivers.append("high CVSS metadata")
    if _safe_int(dashboard.get("high_epss_count")):
        drivers.append("high EPSS metadata")
    if _safe_int(dashboard.get("exploitable_metadata_count")):
        drivers.append("local exploit availability metadata")
    if _safe_int(dashboard.get("critical_asset_findings_count")):
        drivers.append("critical asset context")
    driver_text = ", ".join(drivers) if drivers else "local severity, exposure, and context signals"
    return (
        f"VulScan prioritised {total} findings. {fix_first} findings are marked Fix First and "
        f"{fix_soon} are marked Fix Soon, mainly due to {driver_text}. Review these findings first, "
        "validate affected versions and applicability, and plan remediation using the suggested generic SLA hints. "
        "The dashboard is decision support only and does not confirm exploitability."
    )


def build_dashboard_finding() -> Finding:
    """Create the standard informational dashboard finding."""
    return create_finding(
        title="Fix-First Dashboard Generated",
        severity="Informational",
        category="Prioritisation",
        evidence="VulScan generated a fix-first dashboard from prioritised findings.",
        confidence="High",
        impact="The dashboard supports remediation triage and stakeholder reporting.",
        recommendation="Use the dashboard to guide validation, remediation planning, and stakeholder reporting.",
        verification="Review the Fix-First Dashboard section in terminal, JSON, or HTML output.",
        limitation="Dashboard rankings are decision-support outputs and require human review.",
        source="prioritisation_report",
    )


def _empty_distribution() -> dict[str, dict[str, int]]:
    return {
        "by_label": {label: 0 for label in PRIORITY_LABELS},
        "by_severity": {severity: 0 for severity in SEVERITIES},
        "by_source": {
            "port_scan": 0,
            "service_detect": 0,
            "ssh_audit": 0,
            "windows_audit": 0,
            "web_dast": 0,
            "vuln_intel": 0,
            "cve_feed": 0,
            "prioritisation": 0,
        },
        "by_asset_criticality": {criticality: 0 for criticality in ASSET_CRITICALITIES},
        "by_exploit_maturity": {maturity: 0 for maturity in EXPLOIT_MATURITIES},
    }


def _normalise_prioritised_finding(finding: dict[str, Any]) -> dict[str, Any]:
    normalised = dict(finding)
    normalised["priority_score"] = _safe_int(normalised.get("priority_score"))
    normalised["priority_label"] = _normalise_priority_label(normalised.get("priority_label"))
    if str(normalised.get("severity") or "") == "Informational" and normalised["priority_label"] == "Monitor":
        normalised["priority_label"] = "Informational"
    normalised["asset_criticality"] = _normalise_asset_criticality(normalised.get("asset_criticality"))
    return normalised


def _normalise_priority_label(value: Any) -> str:
    label = str(value or "").strip()
    if label == "Fix First":
        return "Fix First"
    if label in {"Fix Soon", "Schedule"}:
        return "Fix Soon"
    if label == "Informational":
        return "Informational"
    return "Monitor"


def _normalise_source(value: Any) -> str:
    source = str(value or "prioritisation").strip()
    if source.startswith("web_"):
        return "web_dast"
    if source in {"package_audit", "ssh_hardening", "linux_config_audit"}:
        return "ssh_audit"
    if source in {"windows_security_audit", "windows_policy_audit", "windows_registry_audit", "windows_demo"}:
        return "windows_audit"
    if source in {"asset_criticality", "prioritisation_report"}:
        return "prioritisation"
    return source or "prioritisation"


def _normalise_asset_criticality(value: Any) -> str:
    criticality = str(value or "unknown").lower()
    return criticality if criticality in ASSET_CRITICALITIES else "unknown"


def _normalise_exploit_maturity(value: Any) -> str:
    maturity = str(value or "unknown").lower()
    return maturity if maturity in EXPLOIT_MATURITIES else "unknown"


def _is_immediate_action(finding: dict[str, Any]) -> bool:
    return bool(
        _normalise_priority_label(finding.get("priority_label")) == "Fix First"
        or _safe_float(_evidence_value(finding, "cvss_score")) >= 7.0
        or _safe_float(_evidence_value(finding, "epss_score")) >= 0.7
        or _evidence_bool(finding, "exploit_available")
        or _evidence_bool(finding, "active_exploitation_reported")
        or _normalise_asset_criticality(finding.get("asset_criticality")) in {"critical", "high"}
    )


def _action_item(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "title": str(finding.get("title") or ""),
        "priority_label": _normalise_priority_label(finding.get("priority_label")),
        "recommended_action": _recommended_action(finding),
        "sla_hint": _sla_hint(finding),
        "validation_note": "Validate affected asset, version evidence, compensating controls, and business impact before remediation.",
        "remediation_status": str(finding.get("remediation_status") or "Not tracked"),
    }


def _recommended_action(finding: dict[str, Any]) -> str:
    recommendation = str(finding.get("recommendation") or "").strip()
    if recommendation:
        return recommendation
    label = _normalise_priority_label(finding.get("priority_label"))
    if label == "Fix First":
        return "Validate the finding and begin remediation planning immediately."
    if label == "Fix Soon":
        return "Validate the finding and schedule remediation."
    return "Monitor, document, and review during normal security operations."


def _sla_hint(finding: dict[str, Any]) -> str:
    label = _normalise_priority_label(finding.get("priority_label"))
    if label == "Fix First" or _is_immediate_action(finding):
        return "Review within 24-72 hours; customise to local policy."
    if label == "Fix Soon":
        return "Review within 7-14 days; customise to local policy."
    return "Review during the next routine security cycle."


def _asset_exposure(finding: dict[str, Any]) -> str:
    if finding.get("affected_url"):
        return str(finding["affected_url"])
    host = finding.get("affected_host")
    port = finding.get("affected_port")
    if host and port:
        return f"{host}:{port}"
    if host:
        return str(host)
    if port:
        return f"port {port}"
    return "n/a"


def _evidence_value(finding: dict[str, Any], key: str) -> Any:
    details = finding.get("evidence_details") or {}
    return details.get(key)


def _evidence_bool(finding: dict[str, Any], key: str) -> bool:
    value = _evidence_value(finding, key)
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() == "true"


def _count_exploit_metadata(findings: list[dict[str, Any]]) -> int:
    return sum(
        1
        for finding in findings
        if _evidence_bool(finding, "exploit_available")
        or _normalise_exploit_maturity(_evidence_value(finding, "exploit_maturity")) in {"poc", "weaponized", "active_exploitation_reported"}
    )


def _count_overdue_remediation(findings: list[dict[str, Any]]) -> int:
    return sum(1 for finding in findings if str(finding.get("remediation_status") or "").lower() == "overdue")


def _top_recommended_actions(top_findings: list[dict[str, Any]]) -> list[str]:
    actions: list[str] = []
    for finding in top_findings[:5]:
        action = str(finding.get("recommended_action") or "")
        if action and action not in actions:
            actions.append(action)
    return actions


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
