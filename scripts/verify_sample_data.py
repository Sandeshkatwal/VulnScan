"""Verify VulScan sample data required for safe regression testing."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_JSON = [
    "data/findings/sample_finding.json",
    "data/demo/demo_dashboard_summary.json",
    "data/demo/demo_findings.json",
    "data/demo/demo_evidence_vault.json",
    "data/auth_profiles/sample_session_profile.redacted.json",
    "data/sbom/sample_cyclonedx_sbom.json",
    "data/report_templates/sample_report_template.json",
]
REQUIRED_TEXT = [
    "data/endpoints/sample_urls.txt",
    "data/recon/sample_targets.txt",
    "data/validation/sample_validation_targets.json",
]


def verify_sample_data() -> dict[str, object]:
    missing: list[str] = []
    invalid_json: list[str] = []
    for item in REQUIRED_JSON + [path for path in REQUIRED_TEXT if path.endswith(".json")]:
        path = ROOT / item
        if not path.is_file():
            missing.append(item)
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            invalid_json.append(item)
    for item in [path for path in REQUIRED_TEXT if not path.endswith(".json")]:
        if not (ROOT / item).is_file():
            missing.append(item)
    return {
        "status": "pass" if not missing and not invalid_json else "fail",
        "missing": missing,
        "invalid_json": invalid_json,
        "checked_count": len(REQUIRED_JSON) + len(REQUIRED_TEXT),
    }


def main() -> int:
    result = verify_sample_data()
    print(f"Sample data verification: {result['status'].upper()}")
    for item in result["missing"]:
        print(f"MISSING: {item}")
    for item in result["invalid_json"]:
        print(f"INVALID JSON: {item}")
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
