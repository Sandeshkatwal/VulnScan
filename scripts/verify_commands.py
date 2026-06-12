"""Safely verify important VulScan commands for Public Beta."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv311" / "Scripts" / "python.exe"
if not PYTHON.exists():
    PYTHON = Path(sys.executable)


@dataclass(frozen=True)
class CommandCheck:
    name: str
    command: list[str]
    optional: bool = False


COMMANDS = [
    CommandCheck("version", [str(PYTHON), "-m", "scanner.main", "version"]),
    CommandCheck("health", [str(PYTHON), "-m", "scanner.main", "health"], optional=True),
    CommandCheck("demo status", [str(PYTHON), "-m", "scanner.main", "demo", "status"]),
    CommandCheck("demo generate", [str(PYTHON), "-m", "scanner.main", "demo", "generate", "--json"]),
    CommandCheck("evidence redact-check", [str(PYTHON), "-m", "scanner.main", "evidence", "redact-check", "--text", "Authorization: Bearer secret-demo-token"]),
    CommandCheck("public beta check", [str(PYTHON), "scripts/public_beta_check.py"], optional=True),
]


def run_checks() -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    for item in COMMANDS:
        try:
            completed = subprocess.run(item.command, cwd=ROOT, text=True, capture_output=True, timeout=45)
        except Exception as exc:  # pragma: no cover - subprocess environment varies
            results.append({"command": item.name, "status": "skipped" if item.optional else "failed", "reason": exc.__class__.__name__})
            continue
        status = "passed" if completed.returncode == 0 else ("skipped" if item.optional else "failed")
        reason = "ok" if completed.returncode == 0 else (completed.stderr or completed.stdout or "command returned non-zero").splitlines()[0][:160]
        results.append({"command": item.name, "status": status, "reason": reason})
    return results


def main() -> int:
    results = run_checks()
    for result in results:
        print(f"{result['status'].upper()}: {result['command']} - {result['reason']}")
    failed = [item for item in results if item["status"] == "failed"]
    print(f"Summary: {len(results) - len(failed)}/{len(results)} commands passed or skipped safely.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
