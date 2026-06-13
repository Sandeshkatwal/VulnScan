"""Check safe report export paths and sample report export safety."""

from __future__ import annotations

import sys
from pathlib import Path

from scanner.finding_builder import load_findings_file
from scanner.report_composer import compose_report
from scanner.report_exporter import export_safety_check


ROOT = Path(__file__).resolve().parents[1]


def check_report_exports() -> dict[str, object]:
    findings_file = ROOT / "data" / "findings" / "sample_finding.json"
    blocking: list[str] = []
    if not findings_file.is_file():
        blocking.append("Missing sample finding file.")
        return {"status": "fail", "blocking": blocking}
    try:
        findings = load_findings_file(findings_file)
        report = compose_report(
            title="VulScan Regression Report",
            target="http://127.0.0.1:8000",
            findings=findings,
        )
        safety = export_safety_check(report)
    except Exception as exc:  # pragma: no cover - defensive script path
        blocking.append(f"Report export safety check failed: {exc.__class__.__name__}")
        return {"status": "fail", "blocking": blocking}
    if not safety.get("export_allowed"):
        blocking.append("Sample report export was blocked by safety checks.")
    return {"status": "pass" if not blocking else "fail", "blocking": blocking, "safety": safety}


def main() -> int:
    result = check_report_exports()
    print(f"Report export check: {result['status'].upper()}")
    for item in result["blocking"]:
        print(f"BLOCKING: {item}")
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
