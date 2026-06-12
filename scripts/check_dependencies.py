"""Static dependency review for VulScan public beta."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def run_dependency_review() -> dict[str, Any]:
    warnings: list[str] = []
    blocking: list[str] = []
    requirements = ROOT / "requirements.txt"
    package_json = ROOT / "dashboard" / "package.json"
    package_lock = ROOT / "dashboard" / "package-lock.json"
    if not requirements.exists():
        blocking.append("requirements.txt is missing.")
    else:
        lines = [line.strip() for line in requirements.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
        unpinned = [line for line in lines if not any(op in line for op in ("==", ">=", "~=", "<"))]
        if unpinned:
            warnings.append(f"{len(unpinned)} Python dependencies do not include a version constraint.")
    if not package_json.exists():
        blocking.append("dashboard/package.json is missing.")
    else:
        payload = json.loads(package_json.read_text(encoding="utf-8"))
        if not payload.get("scripts", {}).get("build"):
            blocking.append("dashboard/package.json does not define npm run build.")
    if package_json.exists() and not package_lock.exists():
        warnings.append("dashboard/package-lock.json is missing; npm ci in CI expects it.")
    if (ROOT / "node_modules").exists() or (ROOT / "dashboard" / "node_modules").exists():
        warnings.append("node_modules exists locally; ensure it is not committed.")
    if (ROOT / ".venv").exists() or (ROOT / ".venv311").exists():
        warnings.append("Python virtual environment exists locally; ensure it is not committed.")
    readme = (ROOT / "README.md").read_text(encoding="utf-8") if (ROOT / "README.md").exists() else ""
    if "Python 3.11" not in readme:
        warnings.append("README should mention Python 3.11.")
    return {
        "status": "pass" if not blocking else "fail",
        "blocking": blocking,
        "warnings": warnings,
        "checked": ["requirements.txt", "dashboard/package.json", "dashboard/package-lock.json", ".gitignore", "README.md"],
    }


def main() -> int:
    result = run_dependency_review()
    print(f"Dependency review: {result['status'].upper()}")
    for item in result["blocking"]:
        print(f"BLOCKING: {item}")
    for item in result["warnings"]:
        print(f"WARNING: {item}")
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
