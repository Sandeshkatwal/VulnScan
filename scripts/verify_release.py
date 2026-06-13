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
    "docs/beta/PUBLIC_BETA_NOTES.md",
    "docs/beta/KNOWN_LIMITATIONS.md",
    "docs/beta/VERIFICATION_MATRIX.md",
    "docs/beta/BETA_TESTING_GUIDE.md",
    "docs/issues/ISSUE_TRIAGE_GUIDE.md",
    "docs/beta/resolved/RESOLVED_ISSUES_22_1.md",
    "docs/regression/REGRESSION_TESTING.md",
    "docs/regression/CLI_EDGE_CASES.md",
    "docs/regression/API_ERROR_HANDLING.md",
    "docs/regression/DASHBOARD_STABILITY.md",
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
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    ".github/ISSUE_TEMPLATE/documentation_issue.yml",
    ".github/PULL_REQUEST_TEMPLATE.md",
    "scripts/run_regression_suite.py",
    "scripts/collect_beta_issues.py",
    "scripts/verify_sample_data.py",
    "scripts/check_report_exports.py",
    "reports/regression/regression_summary.json",
]
REQUIRED_DIRS = ["tests", "tests/regression", "scanner", "dashboard/src", "docs/screenshots", "docs/assets", "docs/diagrams", "docs/release", "docs/interview", "docs/beta", "docs/beta/resolved", "docs/issues", "docs/regression", "reports/diagnostics", "reports/regression", "reports/beta_issues"]


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
    required_phrases = ["Authorised Testing Only", "Public Beta", "Known Limitations", "Portfolio Demo Mode", "not an exploitation framework", "Manual Validation"]
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
