"""Run VulScan 22.1 regression tests and write a local summary."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SUMMARY_PATH = ROOT / "reports" / "regression" / "regression_summary.json"


def run_regression_suite() -> dict[str, object]:
    SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, "-m", "pytest", "tests/regression"]
    completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=180)
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "release": "22.1.0-beta",
        "focus": "Bug Fix Sprint and Regression Test Hardening",
        "command": command,
        "returncode": completed.returncode,
        "status": "passed" if completed.returncode == 0 else "failed",
        "stdout_tail": completed.stdout.splitlines()[-40:],
        "stderr_tail": completed.stderr.splitlines()[-20:],
    }
    SUMMARY_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    summary = run_regression_suite()
    print(f"Regression suite: {summary['status']}")
    print(f"Wrote {SUMMARY_PATH.relative_to(ROOT)}")
    return int(summary["returncode"])


if __name__ == "__main__":
    sys.exit(main())
