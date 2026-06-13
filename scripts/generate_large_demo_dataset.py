"""Generate a safe simulated Large Demo Dataset for Performance Review."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.demo_mode import demo_dataset_contains_unsafe_values
from scanner.large_dataset_loader import (
    LARGE_DEMO_DIR,
    LARGE_EVIDENCE_FILE,
    LARGE_FINDINGS_FILE,
    LARGE_REPORTS_FILE,
    LARGE_SUMMARY_FILE,
    clear_large_demo_cache,
)


SEVERITIES = ("Informational", "Low", "Medium", "High")
OWASP_CATEGORIES = ("A01:2025", "A02:2025", "A03:2025", "A04:2025", "A05:2025", "A06:2025", "A07:2025", "A08:2025", "A09:2025", "A10:2025")
SOURCE_MODULES = ("owasp_assessment", "evidence_vault", "authenticated_crawler", "access_control_test_planner", "business_logic_review")
SAFE_TARGET = "https://demo.local"
GENERATED_AT = "2026-06-13T00:00:00+00:00"


def build_large_demo_dataset(findings: int, evidence: int, reports: int) -> dict[str, Any]:
    finding_rows = [_finding(index) for index in range(1, findings + 1)]
    evidence_rows = [_evidence(index) for index in range(1, evidence + 1)]
    report_rows = [_report(index, findings) for index in range(1, reports + 1)]
    category_counts = Counter(category for item in finding_rows for category in item["owasp_categories"])
    severity_counts = Counter(item["severity"] for item in finding_rows)
    summary = {
        "dataset_name": "Large Demo Dataset",
        "generated_at": GENERATED_AT,
        "simulated": True,
        "target": SAFE_TARGET,
        "safe_testing_statement": "Large Demo Dataset uses simulated redacted records only. No live requests were sent.",
        "findings": len(finding_rows),
        "evidence": len(evidence_rows),
        "reports": len(report_rows),
        "manual_plans": max(10, findings // 20),
        "severity_totals": dict(severity_counts),
        "owasp_category_totals": dict(category_counts),
    }
    return {"findings": finding_rows, "evidence": evidence_rows, "reports": report_rows, "summary": summary}


def write_large_demo_dataset(dataset: dict[str, Any]) -> dict[str, str]:
    LARGE_DEMO_DIR.mkdir(parents=True, exist_ok=True)
    if demo_dataset_contains_unsafe_values(dataset):
        raise ValueError("Large Demo Dataset contains unsafe values.")
    files = {
        LARGE_FINDINGS_FILE: dataset["findings"],
        LARGE_EVIDENCE_FILE: dataset["evidence"],
        LARGE_REPORTS_FILE: dataset["reports"],
        LARGE_SUMMARY_FILE: dataset["summary"],
    }
    paths: dict[str, str] = {}
    for path, payload in files.items():
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        paths[path.stem] = str(path)
    clear_large_demo_cache()
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate safe simulated Large Demo Dataset files.")
    parser.add_argument("--findings", type=int, default=500)
    parser.add_argument("--evidence", type=int, default=1000)
    parser.add_argument("--reports", type=int, default=50)
    args = parser.parse_args()
    dataset = build_large_demo_dataset(max(0, args.findings), max(0, args.evidence), max(0, args.reports))
    paths = write_large_demo_dataset(dataset)
    print("Large Demo Dataset generated")
    print(f"- findings: {len(dataset['findings'])}")
    print(f"- evidence: {len(dataset['evidence'])}")
    print(f"- reports: {len(dataset['reports'])}")
    print(f"- output: {LARGE_DEMO_DIR}")
    return 0


def _finding(index: int) -> dict[str, Any]:
    severity = SEVERITIES[index % len(SEVERITIES)]
    category = OWASP_CATEGORIES[index % len(OWASP_CATEGORIES)]
    source = SOURCE_MODULES[index % len(SOURCE_MODULES)]
    return {
        "finding_id": f"large-demo-finding-{index:04d}",
        "title": f"Simulated Performance Review Finding {index:04d}",
        "severity": severity,
        "status": "draft",
        "validation_status": "manual_validation_required",
        "owasp_categories": [category],
        "source_modules": [source],
        "evidence_strength": "weak_indicator",
        "risk_score": {"Informational": 8, "Low": 22, "Medium": 48, "High": 72}[severity],
        "affected_targets": [SAFE_TARGET],
        "affected_urls": [f"{SAFE_TARGET}/large-demo/{index:04d}"],
        "technical_summary": "Simulated redacted record for Pagination and Dashboard Rendering Optimisation review.",
        "evidence_references": [f"large-demo-evidence-{((index - 1) % max(1, index)) + 1:04d}"],
        "simulated": True,
        "created_at": GENERATED_AT,
        "updated_at": GENERATED_AT,
    }


def _evidence(index: int) -> dict[str, Any]:
    category = OWASP_CATEGORIES[index % len(OWASP_CATEGORIES)]
    source = SOURCE_MODULES[index % len(SOURCE_MODULES)]
    return {
        "evidence_id": f"large-demo-evidence-{index:04d}",
        "title": f"Redacted Large Demo Evidence {index:04d}",
        "evidence_type": "manual_observation",
        "source_module": source,
        "related_target": SAFE_TARGET,
        "related_url": f"{SAFE_TARGET}/large-demo/evidence/{index:04d}",
        "related_owasp_categories": [category],
        "confidence": "medium",
        "evidence_strength": "weak_indicator",
        "redaction_status": "redacted",
        "secret_detection_status": "passed",
        "evidence_quality_score": 82,
        "evidence_quality_label": "Simulated redacted evidence",
        "safe_summary": "Simulated safe observation for Large Dataset Handling review.",
        "redacted_request_summary": "GET /large-demo/path with authorised local demo context. Authorization: Bearer [REDACTED-BEARER]",
        "redacted_response_summary": "Simulated response summary only. Full body not stored.",
        "simulated": True,
        "created_at": GENERATED_AT,
        "updated_at": GENERATED_AT,
    }


def _report(index: int, findings_count: int) -> dict[str, Any]:
    return {
        "report_id": f"large-demo-report-{index:04d}",
        "title": f"VulScan Large Demo Report {index:04d}",
        "target": SAFE_TARGET,
        "status": "draft",
        "finding_count": min(25, findings_count),
        "formats": ["json", "html", "markdown"],
        "simulated": True,
        "created_at": GENERATED_AT,
    }


if __name__ == "__main__":
    raise SystemExit(main())
