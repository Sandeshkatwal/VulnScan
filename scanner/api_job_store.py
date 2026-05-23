"""Persistent SQLite storage for VulScan API jobs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.database import DB_PATH, get_connection, init_api_jobs_table
from scanner.evidence import redact_nested


ALLOWED_JOB_STATUSES = {"queued", "running", "completed", "failed", "cancelled"}
INTERRUPTED_ERROR_CODE = "API_JOB_INTERRUPTED"
INTERRUPTED_ERROR_MESSAGE = "Job was interrupted because the API process stopped before completion."
UNAVAILABLE_RESULT_MESSAGE = "Job completed but result payload is no longer available."
UNAVAILABLE_FINDINGS_MESSAGE = "Job completed but findings are no longer available."
UNSAFE_REQUEST_KEYS = {
    "password",
    "token",
    "secret",
    "private_key",
    "ssh_password",
    "windows_password",
    "api_key",
    "bearer",
    "authorization",
}


class ApiJobStore:
    """SQLite-backed API job metadata store."""

    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = db_path
        self.ensure_schema()

    def ensure_schema(self) -> None:
        init_api_jobs_table(db_path=self.db_path)

    def mark_interrupted_jobs(self) -> int:
        now = _now()
        with get_connection(self.db_path) as connection:
            cursor = connection.execute(
                """
                UPDATE api_jobs
                SET status = ?, completed_at = ?, error_message = ?, safe_error_code = ?, updated_at = ?
                WHERE status IN ('queued', 'running')
                """,
                ("failed", now, INTERRUPTED_ERROR_MESSAGE, INTERRUPTED_ERROR_CODE, now),
            )
            return int(cursor.rowcount or 0)

    def create_job(self, job: dict[str, Any]) -> dict[str, Any]:
        request_payload = sanitize_request_payload(job.get("request") or {})
        now = str(job.get("created_at") or _now())
        row = {
            "job_id": str(job["job_id"]),
            "scan_id": str(job.get("scan_id") or ""),
            "target": str(job.get("target") or request_payload.get("target") or ""),
            "status": _validate_status(str(job.get("status") or "queued")),
            "created_at": now,
            "started_at": str(job.get("started_at") or ""),
            "completed_at": str(job.get("completed_at") or ""),
            "duration_seconds": job.get("duration_seconds"),
            "request_json": json.dumps(request_payload, sort_keys=True),
            "result_summary_json": json.dumps(redact_nested(job.get("result_summary") or {}), sort_keys=True),
            "result_path": str(job.get("result_path") or ""),
            "html_report_path": str(job.get("html_report_path") or ""),
            "error_message": str(job.get("error_message") or ""),
            "safe_error_code": str(job.get("safe_error_code") or ""),
            "updated_at": now,
        }
        with get_connection(self.db_path) as connection:
            connection.execute(
                """
                INSERT INTO api_jobs (
                    job_id, scan_id, target, status, created_at, started_at, completed_at,
                    duration_seconds, request_json, result_summary_json, result_path,
                    html_report_path, error_message, safe_error_code, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["job_id"],
                    row["scan_id"],
                    row["target"],
                    row["status"],
                    row["created_at"],
                    row["started_at"],
                    row["completed_at"],
                    row["duration_seconds"],
                    row["request_json"],
                    row["result_summary_json"],
                    row["result_path"],
                    row["html_report_path"],
                    row["error_message"],
                    row["safe_error_code"],
                    row["updated_at"],
                ),
            )
        return self.get_job(row["job_id"]) or row

    def update_job(self, job_id: str, **fields: Any) -> dict[str, Any] | None:
        if not fields:
            return self.get_job(job_id)
        allowed = {
            "scan_id",
            "target",
            "status",
            "started_at",
            "completed_at",
            "duration_seconds",
            "request_json",
            "result_summary_json",
            "result_path",
            "html_report_path",
            "error_message",
            "safe_error_code",
            "updated_at",
        }
        updates: dict[str, Any] = {}
        for key, value in fields.items():
            if key not in allowed:
                continue
            if key == "status":
                value = _validate_status(str(value))
            elif key in {"request_json", "result_summary_json"} and not isinstance(value, str):
                value = json.dumps(redact_nested(value), sort_keys=True)
            elif value is None:
                value = ""
            updates[key] = value
        updates["updated_at"] = _now()
        assignments = ", ".join(f"{key} = ?" for key in updates)
        parameters = tuple(updates.values()) + (job_id,)
        with get_connection(self.db_path) as connection:
            connection.execute(
                f"UPDATE api_jobs SET {assignments} WHERE job_id = ?",
                parameters,
            )
        return self.get_job(job_id)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with get_connection(self.db_path) as connection:
            row = connection.execute(
                "SELECT * FROM api_jobs WHERE job_id = ? LIMIT 1",
                (job_id,),
            ).fetchone()
        return _row_to_job(row) if row else None

    def list_jobs(
        self,
        *,
        limit: int = 20,
        status: str | None = None,
        target: str | None = None,
    ) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit or 20), 100))
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(_validate_status(status))
        if target:
            clauses.append("target = ?")
            params.append(target)
        where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(safe_limit)
        with get_connection(self.db_path) as connection:
            rows = connection.execute(
                f"""
                SELECT * FROM api_jobs
                {where_clause}
                ORDER BY created_at DESC, updated_at DESC
                LIMIT ?
                """,
                tuple(params),
            ).fetchall()
        return [_row_to_job(row) for row in rows]

    def save_job_result(
        self,
        job_id: str,
        scan_id: str,
        result_summary: dict[str, Any],
        result_path: str | None,
        html_report_path: str | None,
        duration_seconds: float | None = None,
    ) -> dict[str, Any] | None:
        return self.update_job(
            job_id,
            scan_id=scan_id,
            status="completed",
            completed_at=_now(),
            duration_seconds=duration_seconds,
            result_summary_json=json.dumps(redact_nested(result_summary), sort_keys=True),
            result_path=result_path or "",
            html_report_path=html_report_path or "",
            error_message="",
            safe_error_code="",
        )

    def mark_job_failed(self, job_id: str, safe_error_code: str, error_message: str) -> dict[str, Any] | None:
        return self.update_job(
            job_id,
            status="failed",
            completed_at=_now(),
            safe_error_code=safe_error_code,
            error_message=error_message,
        )

    def cleanup_old_jobs(self, max_jobs: int = 500) -> int:
        safe_max = max(1, int(max_jobs or 500))
        with get_connection(self.db_path) as connection:
            cursor = connection.execute(
                """
                DELETE FROM api_jobs
                WHERE job_id NOT IN (
                    SELECT job_id FROM api_jobs
                    ORDER BY created_at DESC, updated_at DESC
                    LIMIT ?
                )
                """,
                (safe_max,),
            )
            return int(cursor.rowcount or 0)


def sanitize_request_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a redacted request payload safe to persist."""
    sanitized: dict[str, Any] = {}
    for key, value in dict(payload or {}).items():
        lowered = str(key).lower()
        if lowered in UNSAFE_REQUEST_KEYS or any(token in lowered for token in UNSAFE_REQUEST_KEYS):
            raise ValueError("Unsupported or unsafe fields may have been provided.")
        sanitized[str(key)] = redact_nested(value)
    return sanitized


def _row_to_job(row: Any) -> dict[str, Any]:
    raw = dict(row)
    return {
        "job_id": str(raw.get("job_id") or ""),
        "scan_id": str(raw.get("scan_id") or ""),
        "target": str(raw.get("target") or ""),
        "status": str(raw.get("status") or ""),
        "created_at": str(raw.get("created_at") or ""),
        "started_at": str(raw.get("started_at") or ""),
        "completed_at": str(raw.get("completed_at") or ""),
        "duration_seconds": raw.get("duration_seconds"),
        "request": _load_json(raw.get("request_json"), {}),
        "result_summary": _load_json(raw.get("result_summary_json"), {}),
        "result_path": str(raw.get("result_path") or "") or None,
        "html_report_path": str(raw.get("html_report_path") or "") or None,
        "error_message": str(raw.get("error_message") or "") or None,
        "safe_error_code": str(raw.get("safe_error_code") or "") or None,
        "updated_at": str(raw.get("updated_at") or ""),
    }


def _load_json(value: Any, default: Any) -> Any:
    if not value:
        return default
    try:
        loaded = json.loads(str(value))
    except json.JSONDecodeError:
        return default
    return loaded if isinstance(loaded, type(default)) else default


def _validate_status(status: str) -> str:
    normalized = str(status or "").strip().lower()
    if normalized not in ALLOWED_JOB_STATUSES:
        raise ValueError(f"Unsupported API job status: {status}")
    return normalized


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
