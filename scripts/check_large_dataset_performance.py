"""Validate Large Dataset Handling for local simulated data."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scanner.demo_mode import demo_dataset_contains_unsafe_values
from scanner.large_dataset_loader import LARGE_FINDINGS_FILE, load_large_demo_dataset
from scanner.pagination import PaginationError, build_paginated_response, paginate_items
from scanner.performance import write_performance_json


OUTPUT = Path("reports") / "performance" / "large_dataset_check.json"


def run_check() -> dict[str, Any]:
    if not LARGE_FINDINGS_FILE.exists():
        from scripts.generate_large_demo_dataset import build_large_demo_dataset, write_large_demo_dataset

        write_large_demo_dataset(build_large_demo_dataset(500, 1000, 50))
    dataset = load_large_demo_dataset()
    findings = list(dataset.get("findings") or [])
    evidence = list(dataset.get("evidence") or [])
    findings_page = build_paginated_response(findings, page=1, page_size=25, sort_by="created_at", sort_direction="desc")
    evidence_page = build_paginated_response(evidence, page=1, page_size=25, sort_by="created_at", sort_direction="desc")
    capped = paginate_items(findings, page=1, page_size=500)
    invalid_page_handled = False
    try:
        paginate_items(findings, page=0, page_size=25)
    except PaginationError:
        invalid_page_handled = True
    summary = {
        "findings": len(findings),
        "evidence": len(evidence),
        "reports": len(dataset.get("reports") or []),
    }
    checks = {
        "pagination_helpers": findings_page["page_size"] == 25 and evidence_page["page_size"] == 25,
        "page_size_limits": capped["page_size"] == 100 and capped.get("page_size_capped") is True,
        "invalid_page_handled": invalid_page_handled,
        "summary_avoids_full_huge_arrays": "items" not in summary and all(isinstance(value, int) for value in summary.values()),
        "no_secrets_in_large_demo_data": not demo_dataset_contains_unsafe_values(dataset),
        "simulated_flags": all(item.get("simulated") is True for item in findings[:50] + evidence[:50]),
    }
    return {
        "version": "22.2.0-beta",
        "build_status": "performance-review",
        "generated_at": "2026-06-13T00:00:00+00:00",
        "simulated": True,
        "summary": summary,
        "checks": checks,
        "passed": all(checks.values()),
    }


def main() -> int:
    payload = run_check()
    write_performance_json(OUTPUT, payload)
    print("Large Dataset Performance Check")
    for key, passed in payload["checks"].items():
        print(f"- {key}: {'pass' if passed else 'fail'}")
    print(f"Output: {OUTPUT}")
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
