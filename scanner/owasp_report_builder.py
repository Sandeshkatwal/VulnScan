"""Unified OWASP Assessment report builder.

The builder consolidates existing VulScan OWASP evidence. It does not run
additional checks or upgrade indicator wording into confirmed impact.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.evidence import redact_nested
from scanner.owasp_evidence import CONFIDENCE_ORDER, STRENGTH_ORDER, strongest_item
from scanner.owasp_rules import load_owasp_assessment_rules


OWASP_REPORTS_DIR = Path("reports") / "owasp"
SAFE_TESTING_STATEMENT = (
    "This OWASP Assessment consolidates evidence from authorised, non-destructive VulScan workflows. "
    "It does not execute exploitation, brute force, credential attacks, destructive tests, or out-of-scope scanning."
)
QUALITY_LIMITATION = "Assessment quality score reflects evidence coverage, not application security."
REPORT_LIMITATIONS = [
    QUALITY_LIMITATION,
    "Automated evidence cannot confirm business logic, tenant-boundary, access-control, or logging impact without manual validation.",
    "No indicator observed does not mean the category is secure; it may reflect limited coverage or unavailable evidence.",
    "Authenticated testing, source-code review, design review, and operational logging review are represented as coverage gaps unless evidence was supplied.",
]


MANUAL_CHECKLIST_TEMPLATES: dict[str, list[tuple[str, str, str, str]]] = {
    "A01:2025": [
        ("object ownership validation", "high", "Access-control impact requires authorised cross-role or object-ownership review.", "Role-scoped request/response comparison notes without secrets."),
        ("tenant boundary validation", "high", "Tenant isolation cannot be confirmed from passive indicators alone.", "Authorised tenant-boundary test notes and screenshots with sensitive values redacted."),
        ("admin/function authorization validation", "high", "Admin and privileged functions require server-side authorization confirmation.", "Role matrix and denied-access observations."),
    ],
    "A05:2025": [
        ("output encoding validation", "high", "Reflection and input indicators require contextual encoding review.", "Template/context review and safe rendered-output observations."),
        ("server-side input validation", "medium", "Input handling should be validated server-side, not only client-side.", "Validation rules and rejected-input evidence."),
        ("query parameterisation review", "high", "Database query construction cannot be verified from passive evidence.", "Code or configuration review confirming parameterised queries."),
        ("reflection context review", "medium", "Reflection context determines risk and remediation approach.", "Context notes for HTML, attribute, script, JSON, or URL output."),
    ],
    "A06:2025": [
        ("business logic review", "high", "Design weaknesses require business-context validation.", "Workflow notes covering state transitions and trust boundaries."),
        ("threat modelling/design review", "high", "Automated checks cannot replace design-level threat modelling.", "Threat model or design-review notes."),
        ("abuse-case review", "medium", "Sensitive workflows should be reviewed for misuse patterns.", "Documented abuse cases and control mapping."),
    ],
    "A07:2025": [
        ("login/session/password reset review", "high", "Authentication workflows require authorised manual validation.", "Session lifecycle and password-reset review notes."),
        ("MFA/2FA review if applicable", "medium", "MFA coverage depends on application design and user populations.", "MFA policy and enrollment evidence."),
        ("account lockout/rate limit review", "medium", "Rate limiting requires authorised operational validation.", "Lockout/rate-limit configuration or safe test notes."),
    ],
    "A08:2025": [
        ("file upload/import/webhook integrity review", "high", "Integrity-sensitive workflows require manual control validation.", "Upload/import/webhook validation notes."),
        ("SRI/third-party script review", "medium", "Third-party script integrity depends on deployment and change workflow.", "Script inventory and SRI/provenance review notes."),
    ],
    "A09:2025": [
        ("logging and alerting review", "high", "Logging coverage is usually unavailable to unauthenticated automated assessment.", "Security event logging matrix."),
        ("incident detection review", "medium", "Alert routing and detection quality require operational evidence.", "Detection rule, alert, and escalation evidence."),
        ("sensitive event audit coverage", "high", "Sensitive actions should produce actionable audit records.", "Audit-event examples with sensitive values redacted."),
    ],
    "A10:2025": [
        ("fail-safe review", "medium", "Exceptional-condition behavior needs manual fail-safe validation.", "Error-path review notes."),
        ("generic error handling review", "medium", "Verbose client-facing errors may disclose implementation details.", "Redacted examples of generic client errors and server-side log detail."),
        ("debug mode disabled validation", "high", "Debug tooling should not be exposed in production.", "Configuration review or production setting evidence."),
    ],
}


DEVELOPER_GUIDANCE: dict[str, list[dict[str, str]]] = {
    "A01:2025": [{"issue_theme": "authorization", "recommendation": "Enforce server-side object ownership checks and deny-by-default authorization.", "implementation_hint": "Centralise authorization checks around user, role, tenant, and object ownership before data access.", "validation_hint": "Review role matrix behavior with authorised test accounts and confirm denied access is logged.", "references_label": "OWASP A01 Broken Access Control"}],
    "A02:2025": [{"issue_theme": "security configuration", "recommendation": "Configure CSP, HSTS, X-Content-Type-Options, Referrer-Policy, and related hardening headers.", "implementation_hint": "Apply tested baseline headers at the edge or application layer and remove debug surfaces from production.", "validation_hint": "Review response headers and confirm debug endpoints are unavailable in production.", "references_label": "OWASP A02 Security Misconfiguration"}],
    "A03:2025": [{"issue_theme": "component governance", "recommendation": "Maintain an SBOM and validate dependency, component, and third-party script provenance.", "implementation_hint": "Track package versions, review advisories, and document update ownership.", "validation_hint": "Compare deployed component evidence with the approved inventory and vendor guidance.", "references_label": "OWASP A03 Software Supply Chain Failures"}],
    "A04:2025": [{"issue_theme": "transport and cookie protection", "recommendation": "Enforce HTTPS, set HSTS, and use Secure, HttpOnly, and SameSite cookie attributes where appropriate.", "implementation_hint": "Redirect HTTP to HTTPS, deploy HSTS after compatibility testing, and protect sensitive cookies.", "validation_hint": "Review TLS metadata, response headers, and cookie attributes without storing cookie values.", "references_label": "OWASP A04 Cryptographic Failures"}],
    "A05:2025": [{"issue_theme": "input handling", "recommendation": "Use parameterised queries, contextual output encoding, and allowlist validation.", "implementation_hint": "Keep validation server-side and separate encoded output by context.", "validation_hint": "Review code paths and safely validate reflected contexts with manual controls.", "references_label": "OWASP A05 Injection"}],
    "A06:2025": [{"issue_theme": "design assurance", "recommendation": "Threat model sensitive workflows and define abuse-case controls before implementation.", "implementation_hint": "Document trust boundaries, state transitions, limits, and fail-safe behavior.", "validation_hint": "Run a manual design review for business logic, workflow bypass, and abuse cases.", "references_label": "OWASP A06 Insecure Design"}],
    "A07:2025": [{"issue_theme": "authentication and session management", "recommendation": "Harden session cookies, password reset flows, MFA, and rate limiting.", "implementation_hint": "Use secure session lifecycle controls, strong recovery workflows, and account protection monitoring.", "validation_hint": "Perform authorised manual review of login, logout, reset, lockout, and MFA behavior.", "references_label": "OWASP A07 Authentication Failures"}],
    "A08:2025": [{"issue_theme": "integrity-sensitive workflows", "recommendation": "Validate uploads/imports, verify webhook signatures, and use SRI for third-party scripts where appropriate.", "implementation_hint": "Check content type, provenance, signature, and integrity before processing trusted data.", "validation_hint": "Review workflow controls manually without uploading unsafe content or triggering external callbacks.", "references_label": "OWASP A08 Software/Data Integrity Failures"}],
    "A09:2025": [{"issue_theme": "logging and alerting", "recommendation": "Define sensitive security events, alert routing, and audit coverage.", "implementation_hint": "Log authentication, authorization, administrative, data export, and exceptional-condition events with redaction.", "validation_hint": "Review generated audit records and alert delivery with operational owners.", "references_label": "OWASP A09 Security Logging & Alerting Failures"}],
    "A10:2025": [{"issue_theme": "exception handling", "recommendation": "Disable verbose errors in production and log diagnostic detail server-side.", "implementation_hint": "Return generic client errors while preserving actionable server-side traces with redaction.", "validation_hint": "Review observed error responses and production debug-mode configuration.", "references_label": "OWASP A10 Mishandling of Exceptional Conditions"}],
}


def build_unified_owasp_report(
    *,
    target: str = "",
    assessment_scope: dict[str, Any] | None = None,
    owasp_assessment_summary: dict[str, Any] | None = None,
    owasp_category_results: list[dict[str, Any]] | None = None,
    owasp_evidence_items: list[dict[str, Any]] | None = None,
    owasp_coverage_gaps: list[dict[str, Any]] | None = None,
    scan_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    scan_result = scan_result or {}
    target = target or str(scan_result.get("target") or scan_result.get("host") or "")
    summary = dict(owasp_assessment_summary or scan_result.get("owasp_assessment_summary") or {})
    evidence = list(owasp_evidence_items if owasp_evidence_items is not None else scan_result.get("owasp_evidence_items", []) or [])
    category_results = list(owasp_category_results if owasp_category_results is not None else scan_result.get("owasp_category_results", []) or [])
    coverage_gaps = list(owasp_coverage_gaps if owasp_coverage_gaps is not None else scan_result.get("owasp_coverage_gaps", []) or [])
    coverage_matrix = build_coverage_matrix(category_results, evidence)
    coverage_gaps = _merge_coverage_gaps(coverage_gaps, build_coverage_gaps(coverage_matrix, scan_result))
    evidence_summary = build_evidence_strength_summary(evidence)
    manual_checklist = build_manual_validation_checklist(coverage_matrix, evidence)
    developer_recommendations = build_developer_recommendations()
    quality = build_assessment_quality_score(coverage_matrix, evidence_summary, manual_checklist, coverage_gaps)
    executive_summary = build_executive_summary(target, coverage_matrix, evidence_summary, coverage_gaps, summary)
    generated_at = str(summary.get("generated_at") or datetime.now(timezone.utc).isoformat(timespec="seconds"))
    report_id = _report_id(target, generated_at)
    report = {
        "report_id": report_id,
        "target": target,
        "generated_at": generated_at,
        "owasp_version": str(summary.get("owasp_version") or "2025"),
        "assessment_scope": assessment_scope or _assessment_scope(scan_result),
        "executive_summary": executive_summary,
        "assessment_quality_score": quality,
        "overall_coverage_status": _overall_coverage_status(coverage_matrix),
        "category_results": coverage_matrix,
        "evidence_strength_summary": evidence_summary,
        "manual_validation_summary": {
            "manual_validation_required_count": len([item for item in manual_checklist if item.get("status") == "pending"]),
            "checklist": manual_checklist,
        },
        "coverage_gaps": coverage_gaps,
        "top_risks": _top_risks(coverage_matrix),
        "developer_recommendations": developer_recommendations,
        "report_limitations": REPORT_LIMITATIONS,
        "safe_testing_statement": SAFE_TESTING_STATEMENT,
    }
    return redact_nested(report)


def build_coverage_matrix(category_results: list[dict[str, Any]], evidence_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rules = load_owasp_assessment_rules()
    by_id = {str(item.get("owasp_id")): dict(item) for item in category_results}
    evidence_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in evidence_items:
        evidence_by_id[str(item.get("owasp_id"))].append(item)
    rows: list[dict[str, Any]] = []
    for category in rules.get("categories", []):
        owasp_id = str(category.get("owasp_id"))
        result = by_id.get(owasp_id, {})
        items = evidence_by_id.get(owasp_id, [])
        strongest = strongest_item(items)
        coverage_status = _coverage_status(owasp_id, result, items, category)
        assessment_status = _assessment_status(result, items, coverage_status)
        recommendation_summary = _first(DEVELOPER_GUIDANCE.get(owasp_id, [{}])).get("recommendation") or _first(category.get("recommendation_themes")) or ""
        rows.append(
            {
                "category": owasp_id,
                "owasp_id": owasp_id,
                "name": category.get("name") or result.get("name") or "",
                "coverage_status": coverage_status,
                "assessment_status": assessment_status,
                "evidence_count": len(items) if items else int(result.get("evidence_count", 0) or 0),
                "strongest_evidence": strongest.get("title") if strongest else "",
                "highest_confidence": strongest.get("confidence") if strongest else str(result.get("highest_confidence") or "Low"),
                "manual_validation_required": _manual_required(owasp_id, result, items, category, coverage_status),
                "recommendation_summary": recommendation_summary,
                "confirmed_count": sum(1 for item in items if item.get("evidence_strength") == "confirmed_finding") or int(result.get("confirmed_count", 0) or 0),
                "strong_indicator_count": sum(1 for item in items if item.get("evidence_strength") == "strong_indicator") or int(result.get("strong_indicator_count", 0) or 0),
                "weak_indicator_count": sum(1 for item in items if item.get("evidence_strength") == "weak_indicator") or int(result.get("weak_indicator_count", 0) or 0),
            }
        )
    return rows


def build_evidence_strength_summary(evidence_items: list[dict[str, Any]]) -> dict[str, Any]:
    strengths = Counter(str(item.get("evidence_strength") or "informational") for item in evidence_items)
    by_category: dict[str, Counter[str]] = defaultdict(Counter)
    by_source: dict[str, Counter[str]] = defaultdict(Counter)
    by_confidence = Counter(str(item.get("confidence") or "Low") for item in evidence_items)
    for item in evidence_items:
        strength = str(item.get("evidence_strength") or "informational")
        by_category[str(item.get("owasp_id") or "unknown")][strength] += 1
        by_source[str(item.get("source") or "unknown")][strength] += 1
    return {
        "confirmed_findings_count": strengths.get("confirmed_finding", 0),
        "strong_indicators_count": strengths.get("strong_indicator", 0),
        "weak_indicators_count": strengths.get("weak_indicator", 0),
        "informational_count": strengths.get("informational", 0),
        "manual_validation_required_count": sum(1 for item in evidence_items if item.get("manual_validation_required")),
        "by_category": {key: dict(value) for key, value in sorted(by_category.items())},
        "by_source": {key: dict(value) for key, value in sorted(by_source.items())},
        "by_confidence": dict(by_confidence),
    }


def build_manual_validation_checklist(coverage_matrix: list[dict[str, Any]], evidence_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    categories = {row["owasp_id"] for row in coverage_matrix if row.get("manual_validation_required") or row.get("coverage_status") in {"manual_review_required", "coverage_gap", "partially_assessed"}}
    categories.update(item.get("owasp_id") for item in evidence_items if item.get("manual_validation_required"))
    categories.update({"A01:2025", "A05:2025", "A06:2025", "A07:2025", "A08:2025", "A09:2025", "A10:2025"})
    rows = []
    for owasp_id in sorted(str(item) for item in categories if item):
        for item, priority, reason, suggested_evidence in MANUAL_CHECKLIST_TEMPLATES.get(owasp_id, []):
            rows.append({"category": owasp_id, "item": item, "priority": priority, "reason": reason, "suggested_evidence": suggested_evidence, "status": "pending"})
    return rows


def build_coverage_gaps(coverage_matrix: list[dict[str, Any]], scan_result: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    scan_result = scan_result or {}
    gaps: list[dict[str, Any]] = []
    for row in coverage_matrix:
        if row.get("coverage_status") in {"not_assessed", "manual_review_required", "coverage_gap"}:
            gaps.append(
                {
                    "category": row.get("owasp_id"),
                    "gap_title": f"{row.get('owasp_id')} {row.get('name')} requires additional evidence",
                    "why_it_matters": "This category cannot be fully assessed from available automated evidence.",
                    "recommended_next_step": "Plan manual validation and attach redacted evidence notes.",
                    "severity_context": "Coverage gap; not a security severity rating.",
                }
            )
    extra = [
        ("A01:2025", "No authenticated testing performed", "Role and object ownership impact usually requires authorised authenticated validation."),
        ("A01:2025", "No role-based access-control validation performed", "Role boundaries cannot be confirmed from passive evidence alone."),
        ("A06:2025", "No business logic review performed", "Business logic and design risks require workflow context and manual review."),
        ("A09:2025", "No logging/alerting evidence available", "Detection and alerting coverage usually requires operational access."),
        ("A03:2025", "No SBOM supplied", "Component and dependency evidence is stronger when a current SBOM is available."),
        ("A06:2025", "No source code review performed", "Some design and trust-boundary issues require code or architecture review."),
    ]
    if not scan_result.get("a04_tls_metadata"):
        extra.append(("A04:2025", "No live TLS metadata available", "TLS configuration confidence is limited without certificate and protocol metadata."))
    for category, title, why in extra:
        if title not in {gap.get("gap_title") for gap in gaps}:
            gaps.append({"category": category, "gap_title": title, "why_it_matters": why, "recommended_next_step": "Collect authorised manual evidence or enable the relevant safe evidence source.", "severity_context": "Coverage gap; not a security severity rating."})
    return gaps


def _merge_coverage_gaps(existing: list[dict[str, Any]], generated: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for gap in [*existing, *generated]:
        category = str(gap.get("category") or gap.get("owasp_id") or "")
        title = str(gap.get("gap_title") or gap.get("explanation") or "Coverage gap")
        key = (category, title)
        if key in seen:
            continue
        seen.add(key)
        merged.append(
            {
                "category": category,
                "gap_title": title,
                "why_it_matters": gap.get("why_it_matters") or gap.get("explanation") or "Available evidence does not fully cover this OWASP category.",
                "recommended_next_step": gap.get("recommended_next_step") or "Collect authorised manual evidence or enable the relevant safe evidence source.",
                "severity_context": gap.get("severity_context") or "Coverage gap; not a security severity rating.",
                "coverage_status": gap.get("coverage_status", "coverage_gap"),
            }
        )
    return merged


def build_developer_recommendations() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for category, items in DEVELOPER_GUIDANCE.items():
        for item in items:
            rows.append({"category": category, **item})
    return rows


def build_assessment_quality_score(
    coverage_matrix: list[dict[str, Any]],
    evidence_summary: dict[str, Any],
    manual_checklist: list[dict[str, Any]],
    coverage_gaps: list[dict[str, Any]],
) -> dict[str, Any]:
    assessed = sum(1 for row in coverage_matrix if row.get("coverage_status") == "assessed")
    partial = sum(1 for row in coverage_matrix if row.get("coverage_status") == "partially_assessed")
    sources = len(evidence_summary.get("by_source") or {})
    score = assessed * 8 + partial * 5 + min(int(evidence_summary.get("strong_indicators_count", 0)) * 4, 20) + min(int(evidence_summary.get("confirmed_findings_count", 0)) * 6, 18) + min(sources * 3, 12)
    score -= min(len(coverage_gaps) * 3, 30)
    score -= min(len(manual_checklist), 20) // 4
    score = max(0, min(100, score))
    return {"score": score, "label": _quality_label(score), "limitation": QUALITY_LIMITATION}


def build_executive_summary(
    target: str,
    coverage_matrix: list[dict[str, Any]],
    evidence_summary: dict[str, Any],
    coverage_gaps: list[dict[str, Any]],
    summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    summary = summary or {}
    categories_with_indicators = [row for row in coverage_matrix if int(row.get("evidence_count", 0) or 0) > 0]
    highest_signal = sorted(categories_with_indicators, key=lambda row: (int(row.get("confirmed_count", 0)), int(row.get("strong_indicator_count", 0)), CONFIDENCE_ORDER.get(str(row.get("highest_confidence")), 0)), reverse=True)[:3]
    text = (
        f"VulScan identified indicators across {len(categories_with_indicators)} OWASP categories for {target or 'the assessed target'}. "
        "Several findings may require manual validation because automated evidence alone cannot confirm business logic, access-control, authentication, integrity, or logging impact."
    )
    return {
        "target": target,
        "summary_text": text,
        "assessed_categories_count": sum(1 for row in coverage_matrix if row.get("coverage_status") in {"assessed", "partially_assessed"}),
        "categories_with_indicators_count": len(categories_with_indicators),
        "strong_indicators_count": evidence_summary.get("strong_indicators_count", 0),
        "weak_indicators_count": evidence_summary.get("weak_indicators_count", 0),
        "confirmed_findings_count": evidence_summary.get("confirmed_findings_count", 0),
        "manual_validation_required_count": evidence_summary.get("manual_validation_required_count", 0),
        "coverage_gaps_count": len(coverage_gaps),
        "highest_signal_categories": [{"category": row.get("owasp_id"), "name": row.get("name"), "evidence_count": row.get("evidence_count"), "highest_confidence": row.get("highest_confidence")} for row in highest_signal],
        "key_limitations": (summary.get("limitations") or REPORT_LIMITATIONS)[:3],
        "recommended_next_steps": ["Complete manual validation for A01, A05, A06, A07, A08, A09, and A10 where applicable.", "Address high-confidence configuration and transport indicators.", "Attach redacted manual evidence to close coverage gaps."],
    }


def save_markdown_report(report: dict[str, Any], reports_dir: Path | str = OWASP_REPORTS_DIR) -> Path:
    root = Path(reports_dir)
    root.mkdir(parents=True, exist_ok=True)
    report_id = str(report.get("report_id") or _report_id(str(report.get("target") or ""), str(report.get("generated_at") or "")))
    path = root / f"{report_id}.md"
    path.write_text(render_markdown_report(report), encoding="utf-8")
    return path


def render_markdown_report(report: dict[str, Any]) -> str:
    report = redact_nested(report)
    lines = ["# VulScan OWASP Assessment Report", ""]
    lines.extend(["## 1. Assessment Scope", f"- Target: {report.get('target') or 'Not specified'}", f"- OWASP version: {report.get('owasp_version', '2025')}", f"- Generated at: {report.get('generated_at')}", f"- Safe testing statement: {report.get('safe_testing_statement')}", ""])
    executive = report.get("executive_summary", {})
    lines.extend(["## 2. Executive Summary", str(executive.get("summary_text") or ""), f"- Categories with indicators: {executive.get('categories_with_indicators_count', 0)}", f"- Strong indicators: {executive.get('strong_indicators_count', 0)}", f"- Weak indicators: {executive.get('weak_indicators_count', 0)}", f"- Manual validation required: {executive.get('manual_validation_required_count', 0)}", ""])
    lines.extend(["## 3. OWASP Coverage Matrix", "| Category | Coverage status | Assessment status | Evidence | Confidence | Manual validation | Recommendation |", "| --- | --- | --- | ---: | --- | --- | --- |"])
    for row in report.get("category_results", []):
        lines.append(f"| {row.get('owasp_id')} {row.get('name')} | {row.get('coverage_status')} | {row.get('assessment_status')} | {row.get('evidence_count', 0)} | {row.get('highest_confidence')} | {'Required' if row.get('manual_validation_required') else 'No'} | {_md(row.get('recommendation_summary'))} |")
    lines.append("")
    lines.extend(["## 4. Key Indicators"])
    for item in report.get("top_risks", []):
        lines.append(f"- {item.get('category')} {item.get('name')}: {item.get('reason')}")
    lines.append("")
    lines.extend(["## 5. Category Findings"])
    for row in report.get("category_results", []):
        lines.append(f"### {row.get('owasp_id')} {row.get('name')}")
        lines.append(f"Coverage status: {row.get('coverage_status')}. Assessment status: {row.get('assessment_status')}. Evidence count: {row.get('evidence_count', 0)}. Strongest evidence: {row.get('strongest_evidence') or 'None observed'}.")
        lines.append("")
    lines.extend(["## 6. Manual Validation Checklist"])
    for item in report.get("manual_validation_summary", {}).get("checklist", []):
        lines.append(f"- [{item.get('status', 'pending')}] {item.get('category')}: {item.get('item')} ({item.get('priority')}) - {item.get('reason')}")
    lines.append("")
    lines.extend(["## 7. Developer Recommendations"])
    for item in report.get("developer_recommendations", []):
        lines.append(f"- {item.get('category')} {item.get('issue_theme')}: {item.get('recommendation')} Validation: {item.get('validation_hint')} Reference: {item.get('references_label')}.")
    lines.append("")
    lines.extend(["## 8. Coverage Gaps"])
    for gap in report.get("coverage_gaps", []):
        lines.append(f"- {gap.get('category')}: {gap.get('gap_title')} - {gap.get('recommended_next_step')}")
    lines.append("")
    lines.extend(["## 9. Limitations"])
    for limitation in report.get("report_limitations", []):
        lines.append(f"- {limitation}")
    lines.extend(["", "## 10. Safe Testing Statement", str(report.get("safe_testing_statement") or SAFE_TESTING_STATEMENT), ""])
    return "\n".join(lines)


def list_owasp_markdown_reports(reports_dir: Path | str = OWASP_REPORTS_DIR) -> list[dict[str, Any]]:
    root = Path(reports_dir)
    if not root.exists():
        return []
    reports = []
    for path in root.glob("owasp_assessment_*.md"):
        stat = path.stat()
        reports.append({"report_id": path.stem, "filename": path.name, "type": "markdown", "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(timespec="seconds"), "size_bytes": stat.st_size, "download_url": f"/owasp/report/{path.stem}/download"})
    return sorted(reports, key=lambda item: str(item.get("created_at")), reverse=True)


def resolve_owasp_markdown_report(report_id: str, reports_dir: Path | str = OWASP_REPORTS_DIR) -> Path | None:
    if not re.fullmatch(r"owasp_assessment_[A-Za-z0-9_.-]+", report_id or ""):
        return None
    path = (Path(reports_dir) / f"{report_id}.md").resolve()
    root = Path(reports_dir).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return None
    return path if path.is_file() and path.suffix.lower() == ".md" else None


def _coverage_status(owasp_id: str, result: dict[str, Any], items: list[dict[str, Any]], category: dict[str, Any]) -> str:
    if owasp_id in {"A06:2025", "A09:2025"} and not items:
        return "coverage_gap"
    if items and category.get("manual_validation_required") and owasp_id in {"A01:2025", "A05:2025"}:
        return "partially_assessed"
    if items:
        return "partially_assessed" if any(item.get("manual_validation_required") for item in items) else "assessed"
    existing = str(result.get("coverage_status") or "")
    if existing in {"assessed", "partially_assessed", "manual_review_required", "not_assessed", "coverage_gap"}:
        return existing
    if category.get("manual_validation_required"):
        return "manual_review_required"
    return "not_assessed"


def _assessment_status(result: dict[str, Any], items: list[dict[str, Any]], coverage_status: str) -> str:
    strengths = Counter(str(item.get("evidence_strength") or "") for item in items)
    if strengths.get("confirmed_finding"):
        return "confirmed_findings"
    if strengths.get("strong_indicator"):
        return "strong_indicators"
    if strengths.get("weak_indicator"):
        return "weak_indicators"
    if strengths.get("informational"):
        return "informational_only"
    if coverage_status in {"not_assessed", "coverage_gap", "manual_review_required"}:
        return "not_assessed"
    existing = str(result.get("assessment_status") or "")
    if existing == "confirmed":
        return "confirmed_findings"
    if existing in {"detected_indicator", "needs_manual_validation"}:
        return "weak_indicators"
    return "no_indicators_observed"


def _manual_required(owasp_id: str, result: dict[str, Any], items: list[dict[str, Any]], category: dict[str, Any], coverage_status: str) -> bool:
    return bool(any(item.get("manual_validation_required") for item in items) or category.get("manual_validation_required") or result.get("manual_validation_required_count") or coverage_status in {"manual_review_required", "coverage_gap"})


def _assessment_scope(scan_result: dict[str, Any]) -> dict[str, Any]:
    return {
        "scan_mode": scan_result.get("scan_mode", ""),
        "web_dast_enabled": bool(scan_result.get("web_dast_summary", {}).get("enabled") or scan_result.get("web_scan_summary", {}).get("enabled")),
        "authenticated_testing": False,
        "source_code_review": False,
        "manual_evidence_linked": bool(scan_result.get("evidence_records")),
    }


def _overall_coverage_status(matrix: list[dict[str, Any]]) -> str:
    if all(row.get("coverage_status") == "assessed" for row in matrix):
        return "assessed"
    if any(row.get("coverage_status") in {"assessed", "partially_assessed"} for row in matrix):
        return "partially_assessed"
    return "coverage_gap"


def _quality_label(score: int) -> str:
    if score >= 80:
        return "Strong OWASP Coverage"
    if score >= 55:
        return "Good OWASP Coverage"
    if score >= 25:
        return "Developing Coverage"
    return "Limited Assessment"


def _top_risks(matrix: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked = sorted([row for row in matrix if int(row.get("evidence_count", 0) or 0) > 0], key=lambda row: (int(row.get("confirmed_count", 0)), int(row.get("strong_indicator_count", 0)), int(row.get("weak_indicator_count", 0)), STRENGTH_ORDER.get(str(row.get("assessment_status")), 0)), reverse=True)
    return [{"category": row.get("owasp_id"), "name": row.get("name"), "reason": f"{row.get('evidence_count')} evidence item(s), confidence {row.get('highest_confidence')}, status {row.get('assessment_status')}."} for row in ranked[:5]]


def _report_id(target: str, generated_at: str) -> str:
    seed = f"{target}_{generated_at}".replace(":", "").replace("+", "_").replace("-", "")
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", seed).strip("_").lower()
    return f"owasp_assessment_{safe or datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"


def _first(values: Any) -> Any:
    if isinstance(values, list) and values:
        return values[0]
    return {}


def _md(value: Any) -> str:
    return str(value or "").replace("|", "/").replace("\n", " ")
