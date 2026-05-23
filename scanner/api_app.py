"""Local FastAPI application for the VulScan API foundation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from scanner import __version__
from scanner.api_models import FindingResponse, JobSummaryResponse, ScanRequest, ScanResponse, ScanSummaryResponse
from scanner.api_job_store import ApiJobStore, UNAVAILABLE_FINDINGS_MESSAGE, UNAVAILABLE_RESULT_MESSAGE, sanitize_request_payload
from scanner.api_jobs import run_scan_job
from scanner.api_runner import run_scan_pipeline
from scanner.api_security import require_api_key
from scanner.exporter import export_findings
from scanner.history import get_findings_for_scan_id, get_recent_scans, get_scan_result_by_id


API_VERSION = "15.3"
ScanExecutor = Callable[..., dict[str, Any]]


def create_app(scan_executor: ScanExecutor | None = None, job_store: ApiJobStore | None = None) -> FastAPI:
    """Create the local VulScan FastAPI app."""
    executor = scan_executor or run_scan_pipeline
    store = job_store or ApiJobStore()
    store.mark_interrupted_jobs()
    app = FastAPI(
        title="VulScan Local API",
        version=API_VERSION,
        description="Local development API for authorised VulScan workflows.",
    )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"error": "Invalid request body.", "detail": "Unsupported or unsafe fields may have been provided."},
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={"error": "Request failed.", "detail": "The API could not complete the request."},
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "scanner": "VulScan"}

    @app.get("/version")
    def version() -> dict[str, str]:
        return {"scanner": "VulScan", "version": __version__, "api_version": API_VERSION}

    @app.post("/scans", response_model=ScanResponse, dependencies=[Depends(require_api_key)])
    def start_scan(request: ScanRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
        if request.scan_mode.lower() != "safe":
            raise HTTPException(status_code=400, detail="Version 15.3 API supports only safe scan_mode.")
        try:
            request_payload = sanitize_request_payload(request.model_dump())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        job_id = str(uuid4())
        try:
            job = store.create_job(
                {
                    "job_id": job_id,
                    "target": request.target,
                    "status": "queued",
                    "request": request_payload,
                }
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail="Could not create API scan job.") from exc
        background_tasks.add_task(run_scan_job, job_id=job_id, request=request_payload, store=store, executor=executor)
        return {
            "job_id": job_id,
            "scan_id": str(job.get("scan_id") or ""),
            "status": str(job.get("status") or "queued"),
            "target": str(job.get("target") or request.target),
            "summary": dict(job.get("result_summary") or {}),
            "result_path": job.get("result_path"),
            "html_report_path": job.get("html_report_path"),
            "retrievable": True,
        }

    @app.get("/scans", response_model=ScanSummaryResponse, dependencies=[Depends(require_api_key)])
    def list_scans(
        limit: int = Query(default=10, ge=1, le=100),
        target: str | None = Query(default=None, min_length=1, max_length=255),
    ) -> dict[str, list[dict[str, Any]]]:
        try:
            return {"scans": get_recent_scans(limit=limit, target=target)}
        except Exception as exc:
            raise HTTPException(status_code=500, detail="Could not read local scan history.") from exc

    @app.get("/scans/{scan_id}", dependencies=[Depends(require_api_key)])
    def get_scan(scan_id: str) -> dict[str, Any]:
        result = get_scan_result_by_id(scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Scan ID was not found in local history.")
        return {"scan_id": scan_id, "result": result}

    @app.get("/scans/{scan_id}/findings", response_model=FindingResponse, dependencies=[Depends(require_api_key)])
    def get_scan_findings(scan_id: str) -> dict[str, Any]:
        findings = get_findings_for_scan_id(scan_id)
        if findings is None:
            raise HTTPException(status_code=404, detail="Scan ID was not found in local history.")
        return {"scan_id": scan_id, "findings": findings}

    @app.get("/jobs", response_model=JobSummaryResponse, dependencies=[Depends(require_api_key)])
    def list_jobs(
        limit: int = Query(default=20, ge=1, le=100),
        status: str | None = Query(default=None, pattern="^(queued|running|completed|failed|cancelled)$"),
        target: str | None = Query(default=None, min_length=1, max_length=255),
    ) -> dict[str, list[dict[str, Any]]]:
        return {"jobs": [_public_job(job) for job in store.list_jobs(limit=limit, status=status, target=target)]}

    @app.get("/jobs/{job_id}", dependencies=[Depends(require_api_key)])
    def get_job(job_id: str) -> dict[str, Any]:
        job = store.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job ID was not found in local job history.")
        return _public_job(job)

    @app.get("/jobs/{job_id}/result", dependencies=[Depends(require_api_key)])
    def get_job_result(job_id: str) -> dict[str, Any]:
        job = store.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job ID was not found in local job history.")
        if job["status"] != "completed":
            return {"job": _public_job(job), "result": None}
        result = _load_job_result(job)
        if result is None:
            return {"job_id": job_id, "status": "completed", "message": UNAVAILABLE_RESULT_MESSAGE, "result": None}
        return {"job_id": job_id, "status": "completed", "result": result}

    @app.get("/jobs/{job_id}/findings", dependencies=[Depends(require_api_key)])
    def get_job_findings(job_id: str) -> dict[str, Any]:
        job = store.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job ID was not found in local job history.")
        if job["status"] != "completed":
            return {"job_id": job_id, "status": job["status"], "findings": []}
        result = _load_job_result(job)
        if result is None:
            return {"job_id": job_id, "status": "completed", "message": UNAVAILABLE_FINDINGS_MESSAGE, "findings": []}
        return {"job_id": job_id, "status": "completed", "findings": list(result.get("findings") or [])}

    @app.get("/exports/findings", dependencies=[Depends(require_api_key)])
    def export_saved_findings(
        format: str = Query(default="json", pattern="^(csv|json)$"),
        target: str | None = Query(default=None, min_length=1, max_length=255),
    ) -> dict[str, Any]:
        result = export_findings(format, target=target)
        if result.get("status") == "unsupported_format":
            raise HTTPException(status_code=400, detail="Supported export formats are csv and json.")
        if result.get("status") in {"missing_database", "missing_table"}:
            raise HTTPException(status_code=404, detail=result.get("message") or "No local export data is available.")
        response = dict(result)
        if response.get("path") is not None:
            response["export_path"] = str(response.pop("path"))
        return response

    return app


app = create_app()


def _public_job(job: dict[str, Any]) -> dict[str, Any]:
    return {
        "job_id": job.get("job_id"),
        "scan_id": job.get("scan_id") or "",
        "target": job.get("target") or "",
        "status": job.get("status") or "",
        "created_at": job.get("created_at") or "",
        "started_at": job.get("started_at") or "",
        "completed_at": job.get("completed_at") or "",
        "duration_seconds": job.get("duration_seconds"),
        "result_summary": dict(job.get("result_summary") or {}),
        "result_path": job.get("result_path"),
        "html_report_path": job.get("html_report_path"),
        "error_message": job.get("error_message"),
        "safe_error_code": job.get("safe_error_code"),
    }


def _load_job_result(job: dict[str, Any]) -> dict[str, Any] | None:
    result_path = job.get("result_path")
    if result_path:
        path = Path(str(result_path))
        if path.exists() and path.is_file():
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                payload = None
            if isinstance(payload, dict):
                return payload
    scan_id = str(job.get("scan_id") or "")
    if scan_id:
        return get_scan_result_by_id(scan_id)
    return None
