"""API helpers for Portfolio Demo Mode."""

from __future__ import annotations

from typing import Any

from scanner.demo_data_loader import load_demo_dataset, save_demo_dataset
from scanner.demo_mode import SAFE_TESTING_STATEMENT, demo_dataset_contains_unsafe_values
from scanner.demo_report_builder import build_demo_report


def api_demo_status() -> dict[str, Any]:
    return {
        "available": True,
        "mode": "Portfolio Demo Mode",
        "dataset": "Safe Demo Dataset",
        "local_demo_only": True,
        "safe_testing_statement": SAFE_TESTING_STATEMENT,
    }


def api_demo_dashboard() -> dict[str, Any]:
    dataset = load_demo_dataset()
    if demo_dataset_contains_unsafe_values(dataset):
        raise ValueError("Demo dataset contains unsafe values.")
    return {"demo_dataset": dataset, "simulated": True}


def api_demo_generate() -> dict[str, Any]:
    paths = save_demo_dataset()
    return {"generated": True, "simulated": True, "paths": paths, "safe_testing_statement": SAFE_TESTING_STATEMENT}


def api_demo_report_build(markdown: bool = True, html: bool = True, json_export: bool = True) -> dict[str, Any]:
    return build_demo_report(markdown=markdown, html=html, json_export=json_export)

