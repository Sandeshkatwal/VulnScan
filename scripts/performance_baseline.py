"""Collect a local Performance Baseline for Version 22.2."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

from scanner.large_dataset_loader import LARGE_FINDINGS_FILE, load_large_demo_dataset
from scanner.pagination import build_paginated_response
from scanner.performance import write_performance_json
from scanner.report_composer import compose_report
from scanner.report_exporter import export_composed_report_html, export_composed_report_json


OUTPUT = Path("reports") / "performance" / "performance_baseline.json"


def measure() -> dict[str, Any]:
    started = time.perf_counter()
    steps: list[dict[str, Any]] = []
    dataset, load_ms = _time_call(load_large_demo_dataset)
    findings = list(dataset.get("findings") or [])
    evidence = list(dataset.get("evidence") or [])
    steps.append({"name": "demo_dataset_load_time", "duration_ms": load_ms, "records": len(findings) + len(evidence)})
    _, findings_page_ms = _time_call(lambda: build_paginated_response(findings, page=1, page_size=25, sort_by="created_at", sort_direction="desc"))
    steps.append({"name": "large_findings_pagination_time", "duration_ms": findings_page_ms, "records": len(findings)})
    _, evidence_page_ms = _time_call(lambda: build_paginated_response(evidence, page=1, page_size=25, sort_by="created_at", sort_direction="desc"))
    steps.append({"name": "large_evidence_pagination_time", "duration_ms": evidence_page_ms, "records": len(evidence)})
    sample_findings = [_exportable_finding(item) for item in findings[: min(50, len(findings))]]
    report, compose_ms = _time_call(lambda: compose_report(title="VulScan Performance Baseline Report", target="https://demo.local", findings=sample_findings))
    steps.append({"name": "report_compose_time", "duration_ms": compose_ms, "records": len(sample_findings)})
    _, json_ms = _time_call(lambda: export_composed_report_json(report))
    steps.append({"name": "json_export_time", "duration_ms": json_ms, "records": len(sample_findings)})
    _, html_ms = _time_call(lambda: export_composed_report_html(report))
    steps.append({"name": "html_export_time", "duration_ms": html_ms, "records": len(sample_findings)})
    memory_estimate_bytes = sum(path.stat().st_size for path in [LARGE_FINDINGS_FILE] if path.exists())
    return {
        "version": "22.2.0-beta",
        "build_status": "performance-review",
        "generated_at": "2026-06-13T00:00:00+00:00",
        "simulated": True,
        "dataset_counts": {
            "findings": len(findings),
            "evidence": len(evidence),
            "reports": len(dataset.get("reports") or []),
        },
        "steps": steps,
        "memory_estimate_bytes": memory_estimate_bytes,
        "total_duration_ms": round((time.perf_counter() - started) * 1000, 3),
    }


def main() -> int:
    if not LARGE_FINDINGS_FILE.exists():
        from scripts.generate_large_demo_dataset import build_large_demo_dataset, write_large_demo_dataset

        write_large_demo_dataset(build_large_demo_dataset(500, 1000, 50))
    payload = measure()
    write_performance_json(OUTPUT, payload)
    print("Performance Baseline")
    for step in payload["steps"]:
        print(f"- {step['name']}: {step['duration_ms']} ms")
    print(f"Output: {OUTPUT}")
    return 0


def _time_call(callback):
    start = time.perf_counter()
    result = callback()
    return result, round((time.perf_counter() - start) * 1000, 3)


def _exportable_finding(finding: dict[str, Any]) -> dict[str, Any]:
    safe = dict(finding)
    safe["evidence_references"] = []
    return safe


if __name__ == "__main__":
    raise SystemExit(main())
