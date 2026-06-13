"""Profile composed report loading on safe local report files."""

from __future__ import annotations

import json
import time
from pathlib import Path


def main() -> int:
    reports_dir = Path("reports")
    started = time.perf_counter()
    files = [path for path in reports_dir.rglob("*.json") if path.is_file()] if reports_dir.exists() else []
    loaded = 0
    for path in files[:100]:
        try:
            json.loads(path.read_text(encoding="utf-8"))
            loaded += 1
        except (OSError, json.JSONDecodeError):
            continue
    duration_ms = round((time.perf_counter() - started) * 1000, 3)
    print("Report Loading Profile")
    print(f"- json_reports_seen: {len(files)}")
    print(f"- json_reports_loaded: {loaded}")
    print(f"- duration_ms: {duration_ms}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
