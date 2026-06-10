"""A08 Software or Data Integrity Failures indicator checks.

Version 20.8 is passive and candidate-based. It does not upload files, submit
forms, trigger webhooks, call update endpoints, or perform bypass testing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scanner.evidence import redact_nested
from scanner.finding import create_finding, finding_to_dict
from scanner.integrity_indicators import (
    build_a08_evidence_template,
    build_a08_manual_validation_plan,
    build_a08_summary,
    collect_a08_integrity_evidence,
)


A08_RULES_PATH = Path("data") / "owasp" / "a08" / "a08_rules.json"
A08_REPORTS_DIR = Path("reports") / "owasp" / "a08"

LIMITATIONS = [
    "A08 Software or Data Integrity Failures checks are candidate-based and require manual validation.",
    "No uploads, form submissions, webhook triggering, update calls, deserialisation payloads, unsafe artifact testing, or control-circumvention testing are performed.",
    "Only supplied endpoint, parameter, form, script, stylesheet, and limited HTML metadata are analysed.",
    "Missing Subresource Integrity is context-dependent and is not treated as a confirmed finding.",
]


class A08RulesError(ValueError):
    """Raised when A08 rules are unavailable or invalid."""


def load_a08_rules(path: str | Path = A08_RULES_PATH) -> dict[str, Any]:
    rules_path = Path(path)
    try:
        payload = json.loads(rules_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise A08RulesError(f"A08 rules file was not found: {rules_path}") from exc
    except json.JSONDecodeError as exc:
        raise A08RulesError(f"A08 rules file is not valid JSON: {rules_path}") from exc
    if payload.get("owasp_id") != "A08:2025":
        raise A08RulesError("A08 rules file must describe A08:2025.")
    if not isinstance(payload.get("rule_groups"), dict):
        raise A08RulesError("A08 rules file must include rule_groups.")
    return payload


def ensure_a08_dirs() -> None:
    A08_RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    A08_REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def assess_a08_integrity(
    *,
    target: str = "",
    endpoint_results: list[dict[str, Any]] | None = None,
    parameter_results: list[dict[str, Any]] | None = None,
    forms: list[dict[str, Any]] | None = None,
    scripts: list[Any] | None = None,
    stylesheets: list[Any] | None = None,
    html_snippet: str = "",
    evidence_records: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assess passive A08 integrity indicators from supplied metadata only."""
    ensure_a08_dirs()
    load_a08_rules()
    evidence = collect_a08_integrity_evidence(
        endpoint_results=endpoint_results or [],
        parameter_results=parameter_results or [],
        forms=forms or [],
        scripts=scripts or [],
        stylesheets=stylesheets or [],
        html_snippet=html_snippet or "",
        target=target,
    )
    evidence.extend(_manual_a08_records(evidence_records or []))
    evidence = _dedupe_evidence(evidence)
    summary = build_a08_summary(target=target or _first_target(endpoint_results or []), evidence=evidence)
    summary["limitations"] = LIMITATIONS + [item for item in summary.get("limitations", []) if item not in LIMITATIONS]
    findings = build_a08_findings(summary, evidence)
    return redact_nested({"a08_integrity_summary": summary, "a08_integrity_evidence": evidence, "findings": findings})


def attach_a08_integrity(scan_result: dict[str, Any]) -> dict[str, Any]:
    payload = assess_a08_integrity(
        target=str(scan_result.get("target") or scan_result.get("url") or scan_result.get("host") or ""),
        endpoint_results=scan_result.get("endpoint_results") or _endpoints_from_scan_result(scan_result),
        parameter_results=scan_result.get("parameter_results") or [],
        forms=_forms_from_scan_result(scan_result),
        scripts=_scripts_from_scan_result(scan_result),
        stylesheets=_stylesheets_from_scan_result(scan_result),
        html_snippet=_html_snippet_from_scan_result(scan_result),
        evidence_records=scan_result.get("evidence_records") or [],
    )
    findings = list(payload.get("findings", []))
    business_logic_plans = [plan for plan in scan_result.get("business_logic_review_plans") or [] if "A08" in (plan.get("related_owasp_categories") or [])]
    if business_logic_plans:
        payload["a08_integrity_summary"].update(
            {
                "business_logic_review_plans_count": len(business_logic_plans),
                "business_logic_manual_observations_count": len(scan_result.get("business_logic_observations") or []),
            }
        )
    payload_without_findings = dict(payload)
    payload_without_findings.pop("findings", None)
    scan_result.update(payload_without_findings)
    scan_result.setdefault("findings", [])
    scan_result["findings"].extend(findings)
    return scan_result


def build_a08_manual_plan_response(evidence_item: dict[str, Any]) -> dict[str, Any]:
    return redact_nested(
        {
            "manual_validation_plan": build_a08_manual_validation_plan(evidence_item),
            "evidence_template": build_a08_evidence_template(evidence_item),
        }
    )


def build_a08_findings(summary: dict[str, Any], evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    target = str(summary.get("target") or "owasp-a08")
    findings = [
        finding_to_dict(
            create_finding(
                title="A08 Software/Data Integrity Assessment Completed",
                severity="Informational",
                category="OWASP A08 Software or Data Integrity Failures",
                affected_host=target,
                evidence=f"VulScan evaluated available endpoints, parameters, forms, scripts, and integrity-related workflow indicators. {summary.get('total_evidence_items', 0)} integrity indicator item(s) were identified.",
                recommendation="Review integrity candidates manually and validate trust-boundary protections.",
                source="owasp_a08",
                confidence=str(summary.get("highest_confidence") or "Low"),
                impact="Integrity-related workflow indicators are available for authorised manual validation.",
                verification="Review a08_integrity_summary and a08_integrity_evidence.",
                limitation="A08 checks are candidate-based and do not perform uploads, webhook triggering, update calls, or bypass testing.",
            )
        )
    ]
    grouped = [
        (
            {"upload_workflow_indicators", "import_export_integrity_indicators"},
            "Upload or Import Integrity Candidate",
            "Upload/import workflow indicators were observed.",
            "Manually review file/data validation, authorization, and safe processing.",
            "No file upload or data import testing was performed.",
        ),
        (
            {"webhook_callback_indicators", "trusted_data_boundary_indicators"},
            "Webhook or Callback Integrity Candidate",
            "Webhook/callback/signature/state indicators were observed.",
            "Manually validate signature verification, replay protection, and callback restrictions.",
            "VulScan does not trigger webhooks or test SSRF.",
        ),
        (
            {"subresource_integrity_indicators"},
            "Subresource Integrity Indicator",
            "External scripts/stylesheets may not use integrity attributes.",
            "Review CSP/SRI strategy for third-party resources.",
            "Missing SRI is context-dependent and not always a vulnerability.",
        ),
        (
            {"update_workflow_indicators", "deserialisation_data_handling_candidates"},
            "Update or Trusted-Data Handling Integrity Candidate",
            "Update/plugin or trusted-data handling indicators were observed.",
            "Manually review signing, trusted sources, safe parsers, and audit controls.",
            "VulScan does not call update endpoints or submit deserialisation payloads.",
        ),
    ]
    for groups, title, evidence_text, recommendation, limitation in grouped:
        rows = [item for item in evidence if str(item.get("rule_group") or "") in groups]
        if not rows:
            continue
        max_score = max(int(item.get("candidate_score") or 0) for item in rows)
        severity = "Medium" if max_score >= 70 else ("Low" if max_score >= 45 else "Informational")
        confidence = _highest_confidence(rows)
        findings.append(
            finding_to_dict(
                create_finding(
                    title=title,
                    severity=severity,
                    category="OWASP A08 Software or Data Integrity Failures",
                    affected_host=target,
                    evidence=f"{evidence_text} {len(rows)} indicator item(s) grouped for manual validation.",
                    recommendation=recommendation,
                    source="owasp_a08",
                    confidence=confidence,
                    impact="Potential integrity risk if manual validation confirms missing trust-boundary protections.",
                    verification="Review grouped A08 integrity evidence and manual validation plans.",
                    limitation=limitation,
                )
            )
        )
    return findings


def _manual_a08_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for record in records:
        category_text = " ".join(
            [
                str(record.get("owasp_id") or ""),
                str(record.get("category") or ""),
                str(record.get("title") or ""),
            ]
        ).lower()
        if "a08" not in category_text and "integrity" not in category_text:
            continue
        from scanner.integrity_indicators import make_a08_evidence_item

        strength = "confirmed_finding" if record.get("manual_confirmed") is True else str(record.get("evidence_strength") or "strong_indicator")
        if strength == "confirmed_finding" and str(record.get("confidence") or "") != "High":
            strength = "strong_indicator"
        results.append(
            make_a08_evidence_item(
                rule_id=str(record.get("rule_id") or "manual_integrity_evidence"),
                rule_group=str(record.get("rule_group") or "manual_validation_plans"),
                title=str(record.get("title") or "A08 manual integrity evidence"),
                affected_url=str(record.get("affected_url") or ""),
                affected_parameter=str(record.get("affected_parameter") or ""),
                workflow_type=str(record.get("workflow_type") or "manual_integrity_review"),
                integrity_candidate_type=str(record.get("integrity_candidate_type") or "integrity indicator"),
                evidence_strength=strength,
                confidence=str(record.get("confidence") or "Medium"),
                candidate_score=int(record.get("candidate_score") or 65),
                safe_evidence_summary=str(record.get("safe_evidence_summary") or record.get("evidence_summary") or "Manual A08 integrity evidence requires review."),
                recommendation=str(record.get("recommendation") or "Review manually confirmed integrity evidence and remediate according to programme scope."),
                source="manual_evidence",
            )
        )
    return results


def _endpoints_from_scan_result(scan_result: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in ("discovered_endpoints", "urls", "crawled_urls"):
        for item in scan_result.get(key) or []:
            rows.append(item if isinstance(item, dict) else {"url": str(item)})
    for item in scan_result.get("safe_active_validation_results") or []:
        if isinstance(item, dict):
            rows.append({"url": str(item.get("url") or ""), "parameters": [{"name": item.get("parameter")}] if item.get("parameter") else []})
    web_scan = scan_result.get("web_scan") or {}
    for key in ("crawl_results", "crawled_urls", "links"):
        for item in web_scan.get(key) or []:
            rows.append(item if isinstance(item, dict) else {"url": str(item)})
    return rows


def _forms_from_scan_result(scan_result: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in ("forms", "form_results", "web_form_results", "discovered_forms"):
        for item in scan_result.get(key) or []:
            if isinstance(item, dict):
                rows.append(item)
    web_scan = scan_result.get("web_scan") or {}
    for key in ("forms", "form_results", "web_form_results", "discovered_forms"):
        for item in web_scan.get(key) or []:
            if isinstance(item, dict):
                rows.append(item)
    return rows


def _scripts_from_scan_result(scan_result: dict[str, Any]) -> list[Any]:
    return _resource_list(scan_result, ("scripts", "script_urls", "external_scripts"))


def _stylesheets_from_scan_result(scan_result: dict[str, Any]) -> list[Any]:
    return _resource_list(scan_result, ("stylesheets", "stylesheet_urls", "css_urls"))


def _resource_list(scan_result: dict[str, Any], keys: tuple[str, ...]) -> list[Any]:
    rows: list[Any] = []
    for key in keys:
        rows.extend(scan_result.get(key) or [])
    web_scan = scan_result.get("web_scan") or {}
    for key in keys:
        rows.extend(web_scan.get(key) or [])
    passive = scan_result.get("web_passive_summary") or web_scan.get("web_passive_summary") or {}
    for key in keys:
        rows.extend(passive.get(key) or [])
    return rows


def _html_snippet_from_scan_result(scan_result: dict[str, Any]) -> str:
    for key in ("html_snippet", "limited_html_snippet"):
        value = scan_result.get(key)
        if value:
            return str(value)[:5000]
    web_scan = scan_result.get("web_scan") or {}
    for key in ("html_snippet", "limited_html_snippet"):
        value = web_scan.get(key)
        if value:
            return str(value)[:5000]
    return ""


def _first_target(endpoint_results: list[dict[str, Any]]) -> str:
    for item in endpoint_results:
        value = str(item.get("url") or item.get("normalised_url") or item.get("path") or "")
        if value:
            return value
    return ""


def _highest_confidence(rows: list[dict[str, Any]]) -> str:
    order = {"Low": 1, "Medium": 2, "High": 3}
    highest = "Low"
    for row in rows:
        confidence = str(row.get("confidence") or "Low")
        if order.get(confidence, 0) > order.get(highest, 0):
            highest = confidence
    return highest


def _dedupe_evidence(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for item in evidence:
        key = str(item.get("evidence_id") or item.get("duplicate_fingerprint", {}).get("fingerprint_hash") or "")
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        result.append(item)
    return result
