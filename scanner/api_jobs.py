"""Background API job execution helpers."""

from __future__ import annotations

from time import perf_counter
from typing import Any, Callable

from scanner import __version__
from scanner.api_job_store import ApiJobStore
from scanner.port_scan import PortScanError


ScanExecutor = Callable[..., dict[str, Any]]


def run_scan_job(
    *,
    job_id: str,
    request: dict[str, Any],
    store: ApiJobStore,
    executor: ScanExecutor,
) -> None:
    """Execute a safe scan job and persist its final state."""
    started = perf_counter()
    store.update_job(job_id, status="running", started_at=_job_time())
    try:
        result = executor(
            target=request["target"],
            scan_mode=request.get("scan_mode", "safe"),
            json_report=bool(request.get("json_report", False)),
            html_report=bool(request.get("html_report", False)),
            save_db=bool(request.get("save_db", True)),
            vuln_intel=bool(request.get("vuln_intel", False)),
            prioritise=bool(request.get("prioritise", False)),
            fix_first_dashboard=bool(request.get("fix_first_dashboard", False)),
            scanner_name="VulScan",
            scanner_version=__version__,
        )
    except ValueError as exc:
        store.mark_job_failed(job_id, "API_JOB_INVALID_REQUEST", str(exc))
        return
    except PortScanError as exc:
        store.mark_job_failed(job_id, "API_JOB_SCAN_REJECTED", str(exc))
        return
    except Exception:
        store.mark_job_failed(job_id, "API_JOB_FAILED", "Scan failed. Review the target and local scanner configuration.")
        return

    duration = round(perf_counter() - started, 3)
    store.save_job_result(
        job_id=job_id,
        scan_id=str(result.get("scan_id") or ""),
        result_summary=dict(result.get("summary") or {}),
        result_path=result.get("result_path"),
        html_report_path=result.get("html_report_path"),
        duration_seconds=duration,
    )


def _job_time() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")
