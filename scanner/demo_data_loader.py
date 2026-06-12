"""Load and save the Safe Demo Dataset."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scanner.demo_mode import build_demo_dataset, demo_dataset_contains_unsafe_values


DEMO_DATA_DIR = Path("data") / "demo"
DEMO_REPORT_DIR = Path("reports") / "demo"
SCREENSHOT_NOTES_DIR = DEMO_REPORT_DIR / "screenshots_notes"


DEMO_FILES = {
    "dashboard_summary": "demo_dashboard_summary.json",
    "owasp_assessment": "demo_owasp_assessment.json",
    "evidence_vault": "demo_evidence_vault.json",
    "findings": "demo_findings.json",
    "authenticated_assessment": "demo_authenticated_assessment.json",
    "role_mapping": "demo_role_mapping.json",
    "access_tests": "demo_access_tests.json",
    "replay_plans": "demo_replay_plans.json",
    "business_logic": "demo_business_logic.json",
    "report_composer": "demo_report_composer.json",
}


def ensure_demo_dirs() -> None:
    for path in (DEMO_DATA_DIR, DEMO_REPORT_DIR, SCREENSHOT_NOTES_DIR):
        path.mkdir(parents=True, exist_ok=True)


def load_demo_dataset() -> dict[str, Any]:
    summary_path = DEMO_DATA_DIR / DEMO_FILES["dashboard_summary"]
    if not summary_path.exists():
        return build_demo_dataset()
    dataset = build_demo_dataset()
    for key, filename in DEMO_FILES.items():
        path = DEMO_DATA_DIR / filename
        if not path.exists():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        dataset[key] = payload
    return dataset


def save_demo_dataset(dataset: dict[str, Any] | None = None) -> dict[str, str]:
    ensure_demo_dirs()
    payload = dataset or build_demo_dataset()
    if demo_dataset_contains_unsafe_values(payload):
        raise ValueError("Demo dataset contains unsafe values.")
    paths: dict[str, str] = {}
    for key, filename in DEMO_FILES.items():
        path = DEMO_DATA_DIR / filename
        path.write_text(json.dumps(payload.get(key), indent=2), encoding="utf-8")
        paths[key] = str(path)
    readme = DEMO_DATA_DIR / "README.md"
    readme.write_text("# Safe Demo Dataset\n\nPortfolio Demo Mode uses simulated redacted data only. No real target is scanned.\n", encoding="utf-8")
    paths["readme"] = str(readme)
    return paths

