"""Load safe simulated large demo datasets."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from scanner.demo_mode import demo_dataset_contains_unsafe_values


LARGE_DEMO_DIR = Path("data") / "demo" / "large"
LARGE_FINDINGS_FILE = LARGE_DEMO_DIR / "demo_large_findings.json"
LARGE_EVIDENCE_FILE = LARGE_DEMO_DIR / "demo_large_evidence.json"
LARGE_REPORTS_FILE = LARGE_DEMO_DIR / "demo_large_reports.json"
LARGE_SUMMARY_FILE = LARGE_DEMO_DIR / "demo_large_summary.json"


def ensure_large_demo_dir() -> None:
    LARGE_DEMO_DIR.mkdir(parents=True, exist_ok=True)


def clear_large_demo_cache() -> None:
    load_large_demo_dataset.cache_clear()


@lru_cache(maxsize=1)
def load_large_demo_dataset() -> dict[str, Any]:
    """Load generated large demo files with simple safe caching."""
    ensure_large_demo_dir()
    dataset = {
        "findings": _load_json(LARGE_FINDINGS_FILE, []),
        "evidence": _load_json(LARGE_EVIDENCE_FILE, []),
        "reports": _load_json(LARGE_REPORTS_FILE, []),
        "summary": _load_json(LARGE_SUMMARY_FILE, {}),
    }
    if demo_dataset_contains_unsafe_values(dataset):
        raise ValueError("Large Demo Dataset contains unsafe values.")
    return dataset


def large_demo_summary() -> dict[str, Any]:
    dataset = load_large_demo_dataset()
    summary = dict(dataset.get("summary") or {})
    summary.update(
        {
            "findings": len(dataset.get("findings") or []),
            "evidence": len(dataset.get("evidence") or []),
            "reports": len(dataset.get("reports") or []),
            "simulated": True,
        }
    )
    return summary


def _load_json(path: Path, fallback: Any) -> Any:
    if not path.exists():
        return fallback
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Large Demo Dataset file is not valid JSON: {path}") from exc
