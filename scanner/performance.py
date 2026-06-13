"""Performance measurement helpers used by local scripts and diagnostics."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable


REPORTS_PERFORMANCE_DIR = Path("reports") / "performance"


def ensure_performance_dirs() -> None:
    REPORTS_PERFORMANCE_DIR.mkdir(parents=True, exist_ok=True)


def timed_step(name: str, callback: Callable[[], Any]) -> dict[str, Any]:
    start = time.perf_counter()
    result = callback()
    duration_ms = round((time.perf_counter() - start) * 1000, 3)
    size_hint = len(result) if isinstance(result, list) else len(result.keys()) if isinstance(result, dict) else None
    return {"name": name, "duration_ms": duration_ms, "size_hint": size_hint, "result": result}


def write_performance_json(path: Path, payload: dict[str, Any]) -> Path:
    ensure_performance_dirs()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path
