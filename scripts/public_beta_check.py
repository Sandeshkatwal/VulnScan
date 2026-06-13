"""Public Beta readiness checks for VulScan."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from scanner.version import VERSION, version_metadata
from scripts.check_dependencies import run_dependency_review
from scripts.check_no_secrets import scan_paths


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = [
    "README.md",
    "LICENSE",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "scanner/version.py",
    "scanner/health_check.py",
    "scanner/diagnostics.py",
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
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    ".github/ISSUE_TEMPLATE/documentation_issue.yml",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/workflows/backend-tests.yml",
    ".github/workflows/dashboard-build.yml",
    ".github/workflows/demo-safety-check.yml",
    ".github/workflows/docs-check.yml",
    "scripts/run_regression_suite.py",
    "scripts/collect_beta_issues.py",
    "scripts/verify_sample_data.py",
    "scripts/check_report_exports.py",
    "reports/regression/regression_summary.json",
]


def run_public_beta_check() -> dict[str, Any]:
    passed: list[str] = []
    warnings: list[str] = []
    blocking: list[str] = []
    for item in REQUIRED_FILES:
        if (ROOT / item).is_file():
            passed.append(f"required file present: {item}")
        else:
            blocking.append(f"missing required file: {item}")
    metadata = version_metadata()
    if metadata["version"] == VERSION and metadata["release_channel"] == "public-beta":
        passed.append("version metadata is public beta")
    else:
        blocking.append("version metadata is not public beta")
    readme = (ROOT / "README.md").read_text(encoding="utf-8") if (ROOT / "README.md").exists() else ""
    for phrase in ("Public Beta", "authorised testing only", "Known Limitations"):
        if phrase.lower() in readme.lower():
            passed.append(f"README mentions {phrase}")
        else:
            blocking.append(f"README missing {phrase}")
    secret_findings = scan_paths()
    if secret_findings:
        blocking.append(f"{len(secret_findings)} unredacted secret-like values detected")
    else:
        passed.append("secret safety check passed")
    dependency_result = run_dependency_review()
    warnings.extend(dependency_result["warnings"])
    blocking.extend(dependency_result["blocking"])
    score = max(0, round((len(passed) / max(1, len(passed) + len(blocking))) * 100))
    if blocking:
        label = "Blocked"
    elif score >= 95 and not warnings:
        label = "Ready for Public Beta"
    elif score >= 85:
        label = "Almost Ready"
    else:
        label = "Needs Work"
    return {
        "public_beta_readiness_score": score,
        "label": label,
        "passed_checks": passed,
        "warnings": warnings,
        "blocking_issues": blocking,
        "next_actions": blocking[:5] or warnings[:5] or ["Run regression testing and prepare release notes."],
    }


def main() -> int:
    result = run_public_beta_check()
    print(f"Public Beta Readiness Score: {result['public_beta_readiness_score']}%")
    print(f"Status: {result['label']}")
    if result["blocking_issues"]:
        print("Blocking issues:")
        for item in result["blocking_issues"]:
            print(f"- {item}")
    if result["warnings"]:
        print("Warnings:")
        for item in result["warnings"]:
            print(f"- {item}")
    print("Next actions:")
    for item in result["next_actions"]:
        print(f"- {item}")
    return 0 if result["label"] != "Blocked" else 1


if __name__ == "__main__":
    sys.exit(main())
