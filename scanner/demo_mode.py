"""Safe Portfolio Demo Mode dataset for VulScan."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


DEMO_DATE = "2026-06-12T09:00:00+00:00"
DEMO_TARGET = "https://demo.local"
SAFE_TESTING_STATEMENT = "Portfolio Demo Mode uses simulated redacted data only. No real target was scanned and no live requests were sent."


def build_demo_dataset() -> dict[str, Any]:
    findings = _demo_findings()
    evidence = _demo_evidence()
    return {
        "demo_mode": True,
        "dataset_name": "Safe Demo Dataset",
        "generated_at": DEMO_DATE,
        "target": DEMO_TARGET,
        "safe_testing_statement": SAFE_TESTING_STATEMENT,
        "dashboard_summary": {
            "assets_assessed": 3,
            "findings": len(findings),
            "owasp_categories_covered": 10,
            "evidence_items": len(evidence),
            "reports_generated": 1,
            "manual_plans": 4,
            "badge": "Portfolio Demo Mode — simulated redacted data.",
        },
        "owasp_assessment": _demo_owasp_assessment(),
        "evidence_vault": {"evidence_vault_items": evidence, "summary": {"total_evidence": len(evidence), "passed_redaction": len(evidence), "blocked_from_export": 0}},
        "findings": findings,
        "authenticated_assessment": _demo_authenticated_assessment(),
        "role_mapping": _demo_role_mapping(),
        "access_tests": _demo_access_tests(),
        "replay_plans": _demo_replay_plans(),
        "business_logic": _demo_business_logic(),
        "report_composer": _demo_report_composer(findings),
        "feature_tour": _demo_feature_tour(),
        "walkthrough": _demo_walkthrough(),
    }


def safe_demo_dataset() -> dict[str, Any]:
    return deepcopy(build_demo_dataset())


def _demo_findings() -> list[dict[str, Any]]:
    base = {
        "status": "draft",
        "confidence": "Low",
        "validation_status": "manual_validation_required",
        "safe_testing_statement": SAFE_TESTING_STATEMENT,
        "source_modules": ["portfolio_demo_mode"],
        "tags": ["simulated", "portfolio-demo"],
        "limitations": ["Simulated demo finding. Manual validation would be required in a real authorised assessment."],
    }
    rows = [
        ("demo-finding-001", "Simulated Missing Content-Security-Policy Header", "Low", ["A02:2025"], "Content-Security-Policy header was not observed in simulated response-header evidence.", "Harden browser security headers and validate policy compatibility."),
        ("demo-finding-002", "Simulated Session Cookie Missing HttpOnly Attribute", "Medium", ["A07:2025"], "A simulated session cookie attribute review identified a missing HttpOnly flag.", "Harden session cookie attributes after application testing."),
        ("demo-finding-003", "Simulated IDOR Candidate Requiring Manual Validation", "Medium", ["A01:2025"], "A role and object ownership review candidate requires manual validation. The demo evidence does not confirm exploitability.", "Enforce server-side authorization and object ownership checks."),
        ("demo-finding-004", "Simulated External Script Without SRI", "Low", ["A08:2025"], "A simulated third-party script reference did not include Subresource Integrity metadata.", "Add SRI where appropriate and review CSP coverage."),
        ("demo-finding-005", "Simulated Verbose Error Page Indicator", "Low", ["A10:2025"], "A simulated error response exposed framework-style diagnostic wording.", "Return generic user-facing errors and keep details in server-side logs."),
        ("demo-finding-006", "Simulated Checkout Business Logic Review Plan", "Informational", ["A06:2025"], "A simulated checkout workflow was selected for manual business rule review.", "Validate workflow state transitions and server-side business rule enforcement."),
    ]
    findings = []
    for index, (finding_id, title, severity, categories, summary, remediation) in enumerate(rows, start=1):
        item = dict(base)
        item.update(
            {
                "finding_id": finding_id,
                "title": title,
                "finding_type": "business_logic_issue" if "Business Logic" in title else "owasp_indicator",
                "owasp_categories": categories,
                "affected_targets": [DEMO_TARGET],
                "affected_urls": [f"{DEMO_TARGET}/demo/{index}"],
                "severity": severity,
                "risk_score": {"Informational": 8, "Low": 22, "Medium": 48}.get(severity, 20),
                "evidence_strength": "weak_indicator",
                "executive_summary": f"Simulated demo finding: {title}.",
                "technical_summary": f"VulScan identified a candidate requiring manual validation. This indicator suggests a possible area for review. The evidence does not confirm exploitability. {summary}",
                "business_impact": "Simulated business impact for interview walkthrough only.",
                "technical_impact": "Simulated technical impact based on redacted demo evidence only.",
                "evidence_references": [f"demo-evidence-{index:03d}"],
                "evidence_quality_summary": {"score": 82, "label": "Demo redacted evidence"},
                "remediation": remediation,
                "developer_guidance": remediation,
                "validation_guidance": "Validate manually in an authorised local lab before using stronger wording.",
                "retest_status": "not_retested" if index < 5 else "not_applicable",
                "created_at": DEMO_DATE,
                "updated_at": DEMO_DATE,
            }
        )
        findings.append(item)
    return findings


def _demo_evidence() -> list[dict[str, Any]]:
    titles = ["CSP header review", "Cookie attribute review", "Role ownership review", "External script review", "Error response review", "Checkout workflow review"]
    return [
        {
            "evidence_id": f"demo-evidence-{index:03d}",
            "title": f"Redacted Demo Evidence: {title}",
            "evidence_type": "manual_observation",
            "source_module": "portfolio_demo_mode",
            "related_target": DEMO_TARGET,
            "related_url": f"{DEMO_TARGET}/demo/{index}",
            "related_owasp_categories": [["A02:2025"], ["A07:2025"], ["A01:2025"], ["A08:2025"], ["A10:2025"], ["A06:2025"]][index - 1],
            "confidence": "medium",
            "evidence_strength": "weak_indicator",
            "redaction_status": "redacted",
            "secret_detection_status": "passed",
            "evidence_quality_score": 82,
            "evidence_quality_label": "Demo redacted evidence",
            "safe_summary": f"Simulated safe observation for {title}.",
            "redacted_request_summary": "GET /demo/path with authorised local demo context. Authorization: Bearer [REDACTED-BEARER]",
            "redacted_response_summary": "Simulated response summary only. Full body not stored.",
            "safe_observed_value": "simulated_indicator",
            "timeline_events": [{"event_id": f"demo-timeline-{index}", "event_type": "created", "timestamp": DEMO_DATE, "description": "Redacted Demo Evidence created for Portfolio Demo Mode."}],
            "created_at": DEMO_DATE,
            "updated_at": DEMO_DATE,
            "limitations": ["Simulated Redacted Demo Evidence only."],
        }
        for index, title in enumerate(titles, start=1)
    ]


def _demo_owasp_assessment() -> dict[str, Any]:
    statuses = {
        "A01": "High-interest access-control candidates, manual validation required",
        "A02": "Missing CSP, missing HSTS, and permissive CORS indicators",
        "A03": "jQuery and Bootstrap version hints with SBOM demo component",
        "A04": "Cookie Secure/HttpOnly demo indicators",
        "A05": "Safe marker reflection candidate",
        "A06": "Business logic manual review plans",
        "A07": "Session cookie and auth endpoint indicators",
        "A08": "Upload, webhook, and SRI indicators",
        "A09": "Logging and alerting manual review gap",
        "A10": "Verbose error indicator",
    }
    return {
        "summary": {"categories_assessed": 10, "manual_validation_required": 10, "simulated": True},
        "coverage_matrix": [{"category": key, "status": value, "evidence_count": 1, "manual_validation_required": True, "simulated": True} for key, value in statuses.items()],
    }


def _demo_authenticated_assessment() -> dict[str, Any]:
    return {"authenticated_crawl_summary": {"enabled": True, "simulated": True, "pages_observed": 12, "boundary_events": 2, "session_expiry_indicators": 1}, "safe_note": "Redacted demo session profile only. No raw cookies or bearer tokens."}


def _demo_role_mapping() -> dict[str, Any]:
    return {"roles": ["anonymous", "standard_user", "support_user", "admin_reviewer"], "matrix": [{"endpoint": "/account/demo", "standard_user": "allowed", "support_user": "denied", "admin_reviewer": "allowed"}], "simulated": True}


def _demo_access_tests() -> dict[str, Any]:
    return {"plans": [{"test_plan_id": "demo-access-plan-001", "role": "standard_user", "endpoint": "/admin/demo/users", "expected": "denied", "status": "manual_validation_required", "simulated": True}]}


def _demo_replay_plans() -> dict[str, Any]:
    return {"plans": [{"replay_plan_id": "demo-replay-plan-001", "endpoint": "/account/demo?user_id=1001", "parameter": "user_id", "intent": "object_ownership_review", "status": "planning_only", "simulated": True}]}


def _demo_business_logic() -> dict[str, Any]:
    return {"plans": [{"review_plan_id": "demo-business-plan-001", "workflow": "checkout", "objective": "Review state transition and business rule enforcement.", "status": "manual_validation_required", "simulated": True}]}


def _demo_report_composer(findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {"draft_title": "VulScan Portfolio Demo Report", "findings_count": len(findings), "export_formats": ["markdown", "html", "json"], "safe_testing_statement": SAFE_TESTING_STATEMENT, "simulated": True}


def _demo_feature_tour() -> list[dict[str, str]]:
    return [
        {"title": "Dashboard Overview", "module": "Dashboard Home", "explanation": "Review portfolio summary metrics and module readiness.", "safe_note": "Uses simulated redacted data."},
        {"title": "Run safe local scan", "module": "Scanning", "explanation": "Show where passive local scans are started.", "safe_note": "Demo mode does not run scans."},
        {"title": "Review OWASP matrix", "module": "OWASP Report", "explanation": "Inspect A01-A10 simulated coverage.", "safe_note": "Indicators require manual validation."},
        {"title": "Add authenticated context safely", "module": "Authenticated Assessment", "explanation": "Explain redacted session profile boundaries.", "safe_note": "No raw cookies or tokens."},
        {"title": "Plan A01 manual validation", "module": "A01 Manual Test Planner", "explanation": "Review expected behaviour and manual plan records.", "safe_note": "Planning only."},
        {"title": "Use Evidence Vault", "module": "Evidence Vault", "explanation": "Show Redacted Demo Evidence and quality status.", "safe_note": "No raw evidence export."},
        {"title": "Build professional findings", "module": "Finding Builder", "explanation": "Turn indicators into carefully worded Technical Findings.", "safe_note": "No confirmed wording without validation."},
        {"title": "Compose report", "module": "Report Composer", "explanation": "Generate a Demo Report in Markdown, HTML, and JSON.", "safe_note": "Export safety checks apply."},
    ]


def _demo_walkthrough() -> list[str]:
    return [
        "Dashboard Home, 30 seconds: introduce VulScan as an OWASP-focused assessment and reporting platform.",
        "OWASP Report Matrix, 1 minute: show simulated A01-A10 coverage and manual validation status.",
        "Authenticated Assessment Safety, 45 seconds: explain redacted context and session boundary controls.",
        "Evidence Vault, 1 minute: show Redacted Demo Evidence, quality score, and safety checks.",
        "Finding Builder and Report Composer, 1 minute: compose careful Technical Findings and a Demo Report.",
        "Closing, 45 seconds: summarize local-first safety, portfolio value, and roadmap.",
    ]


def demo_dataset_contains_unsafe_values(dataset: dict[str, Any]) -> bool:
    text = str(dataset).lower()
    unsafe = ["secret-demo-token", "set-cookie:", "password=", "bearer ey", "private key", "real customer"]
    return any(marker in text for marker in unsafe)

