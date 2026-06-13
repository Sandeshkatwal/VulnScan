"""API helpers for Portfolio Demo Mode."""

from __future__ import annotations

from typing import Any

from scanner.demo_data_loader import load_demo_dataset, save_demo_dataset
from scanner.demo_mode import SAFE_TESTING_STATEMENT, demo_dataset_contains_unsafe_values
from scanner.demo_report_builder import build_demo_report
from scanner.large_dataset_loader import large_demo_summary, load_large_demo_dataset
from scanner.pagination import build_paginated_response


def api_demo_status() -> dict[str, Any]:
    return {
        "available": True,
        "mode": "Portfolio Demo Mode",
        "dataset": "Safe Demo Dataset",
        "local_demo_only": True,
        "safe_testing_statement": SAFE_TESTING_STATEMENT,
    }


def api_demo_dashboard(*, large: bool = False, page: int = 1, page_size: int = 25) -> dict[str, Any]:
    if large:
        dataset = load_large_demo_dataset()
        summary = large_demo_summary()
        findings_page = build_paginated_response(dataset.get("findings") or [], page=page, page_size=page_size, sort_by="created_at", sort_direction="desc")
        evidence_page = build_paginated_response(dataset.get("evidence") or [], page=page, page_size=page_size, sort_by="created_at", sort_direction="desc")
        reports_page = build_paginated_response(dataset.get("reports") or [], page=page, page_size=page_size, sort_by="created_at", sort_direction="desc")
        return {
            "demo_dataset": {
                "demo_mode": True,
                "dataset_name": "Large Demo Dataset",
                "summary": summary,
                "findings": findings_page["items"],
                "evidence": evidence_page["items"],
                "reports": reports_page["items"],
                "pagination": {
                    "findings": findings_page,
                    "evidence": evidence_page,
                    "reports": reports_page,
                },
            },
            "simulated": True,
            "summary_only": True,
        }
    dataset = load_demo_dataset()
    if demo_dataset_contains_unsafe_values(dataset):
        raise ValueError("Demo dataset contains unsafe values.")
    return {"demo_dataset": dataset, "simulated": True}


def api_demo_generate() -> dict[str, Any]:
    paths = save_demo_dataset()
    return {"generated": True, "simulated": True, "paths": paths, "safe_testing_statement": SAFE_TESTING_STATEMENT}


def api_demo_report_build(markdown: bool = True, html: bool = True, json_export: bool = True) -> dict[str, Any]:
    return build_demo_report(markdown=markdown, html=html, json_export=json_export)
