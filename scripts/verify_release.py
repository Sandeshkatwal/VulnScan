"""Verify VulScan portfolio release readiness using local static checks."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = [
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "requirements.txt",
    "dashboard/package.json",
    "docs/README.md",
    "docs/SAFETY.md",
    "docs/COMMAND_REFERENCE.md",
    "docs/ARCHITECTURE.md",
    "docs/PORTFOLIO_DEMO.md",
    "docs/DASHBOARD_GUIDE.md",
    "docs/DEMO_WALKTHROUGH.md",
    "docs/PROFESSIONAL_REPORT_COMPOSER.md",
    "docs/diagrams/ARCHITECTURE.md",
    "docs/release/RELEASE_CHECKLIST.md",
    "docs/release/RELEASE_NOTES_TEMPLATE.md",
    "docs/interview/TALKING_POINTS.md",
    "docs/interview/FAQ.md",
    "data/demo/demo_dashboard_summary.json",
    "data/demo/demo_findings.json",
    ".github/workflows/backend-tests.yml",
    ".github/workflows/dashboard-build.yml",
    ".github/workflows/demo-safety-check.yml",
    ".github/workflows/docs-check.yml",
]
REQUIRED_DIRS = ["tests", "scanner", "dashboard/src", "docs/screenshots", "docs/assets", "docs/diagrams", "docs/release", "docs/interview"]


def main() -> int:
    missing: list[str] = []
    for item in REQUIRED_FILES:
        if not (ROOT / item).is_file():
            missing.append(item)
    for item in REQUIRED_DIRS:
        if not (ROOT / item).is_dir():
            missing.append(item)
    if missing:
        print("FAIL: release readiness checks failed")
        for item in missing:
            print(f"- missing {item}")
        return 1
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    required_phrases = ["Authorised Testing Only", "Portfolio Demo Mode", "not an exploitation framework", "Manual Validation"]
    phrase_failures = [phrase for phrase in required_phrases if phrase.lower() not in readme.lower()]
    if phrase_failures:
        print("FAIL: README is missing release messaging")
        for phrase in phrase_failures:
            print(f"- missing phrase: {phrase}")
        return 1
    print("PASS: release readiness static checks passed.")
    print(f"Checked {len(REQUIRED_FILES)} files and {len(REQUIRED_DIRS)} directories.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

