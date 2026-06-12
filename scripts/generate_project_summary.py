"""Print a concise VulScan portfolio project summary."""

from __future__ import annotations


FEATURES = [
    "Discovery Engine",
    "Passive Web DAST",
    "OWASP Assessment Engine",
    "Authenticated Assessment Foundation",
    "Role and Permission Mapping",
    "Access Control Manual Test Planner",
    "Safe Parameter Replay Planner",
    "Business Logic Review Assistant",
    "Evidence Vault",
    "Professional Finding Builder",
    "Report Composer",
    "Portfolio Demo Mode",
]


def main() -> int:
    print("VulScan — OWASP-focused vulnerability assessment, evidence management, and professional reporting platform.")
    print("Purpose: Authorised Security Assessment, Defensive Security, Safe Local Testing, Manual Validation Workflow.")
    print("Stack: Python 3.11, FastAPI, SQLite/local files, React, Vite, TypeScript.")
    print("Modules:")
    for feature in FEATURES:
        print(f"- {feature}")
    print("Safety: not an exploitation framework; no exploit automation; demo data is simulated and redacted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

