"""Check Portfolio Demo Mode data for safe simulated content."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = ROOT / "data" / "demo"
SECRET_PATTERNS = [
    re.compile(r"bearer\s+(?!\[REDACTED-BEARER\])[A-Za-z0-9._~+/=-]{8,}", re.I),
    re.compile(r"password\s*[:=]\s*[^,\s\]}]+", re.I),
    re.compile(r"set-cookie\s*:", re.I),
    re.compile(r"api[_-]?key\s*[:=]\s*[^,\s\]}]+", re.I),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I),
    re.compile(r"secret-demo-token", re.I),
]


def load_demo_json() -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for path in sorted(DEMO_DIR.glob("*.json")):
        payload[path.name] = json.loads(path.read_text(encoding="utf-8"))
    return payload


def main() -> int:
    if not DEMO_DIR.exists():
        print(f"FAIL: missing demo directory: {DEMO_DIR}")
        return 1
    payload = load_demo_json()
    if not payload:
        print("FAIL: no demo JSON files found.")
        return 1
    text = json.dumps(payload, sort_keys=True)
    failures: list[str] = []
    for pattern in SECRET_PATTERNS:
        if pattern.search(text):
            failures.append(f"secret-like pattern detected: {pattern.pattern}")
    findings = payload.get("demo_findings.json") or []
    if not isinstance(findings, list) or not findings:
        failures.append("demo findings are missing or not a list")
    else:
        for finding in findings:
            tags = finding.get("tags") or []
            title = str(finding.get("title") or "").lower()
            if "simulated" not in tags and "simulated" not in title:
                failures.append(f"finding is not marked simulated: {finding.get('finding_id')}")
    evidence = (payload.get("demo_evidence_vault.json") or {}).get("evidence_vault_items") or []
    for item in evidence:
        if item.get("redaction_status") != "redacted" or item.get("secret_detection_status") != "passed":
            failures.append(f"demo evidence is not redaction-safe: {item.get('evidence_id')}")
    if failures:
        print("FAIL: demo safety check failed")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(f"PASS: checked {len(payload)} demo JSON files; Safe Demo Dataset contains simulated redacted data only.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

