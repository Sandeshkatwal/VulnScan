"""Local FastAPI application for the VulScan API foundation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from scanner import __version__
from scanner.api_filters import (
    active_filters,
    compact_findings,
    filter_findings,
    paginate_items,
    pagination_metadata,
    sort_findings,
    validate_sort_by,
    validate_sort_order,
)
from scanner.api_bug_bounty import check_scope, get_scope_by_program_id, list_scope_files, resolve_scope_file
from scanner.api_endpoint_discovery import list_endpoint_reports
from scanner.api_bug_bounty_recon import list_recon_reports, load_recon_report
from scanner.bug_bounty_recon import BugBountyReconError, run_bug_bounty_recon
from scanner.bug_bounty_scope import BugBountyScopeError
from scanner.endpoint_discovery import EndpointDiscoveryError, run_endpoint_discovery, save_endpoint_report
from scanner.api_models import ErrorResponse, FindingResponse, JobSummaryResponse, ScanRequest, ScanResponse, ScanSummaryResponse
from scanner.api_models import BugBountyReconRequest, EndpointDiscoveryRequest, RemediationUpdateRequest, ScopeCheckRequest
from scanner.api_reports import decode_report_id, list_report_metadata, load_json_report, report_metadata, report_urls_for_path
from scanner.api_remediation import (
    attach_finding_keys,
    get_remediation_record,
    get_remediation_summary,
    list_remediation_records,
    update_remediation_record,
)
from scanner.api_job_store import ApiJobStore, UNAVAILABLE_FINDINGS_MESSAGE, UNAVAILABLE_RESULT_MESSAGE, sanitize_request_payload
from scanner.api_jobs import run_scan_job
from scanner.api_runner import run_scan_pipeline
from scanner.api_security import require_api_key
from scanner.database import DB_PATH
from scanner.exporter import export_findings
from scanner.history import get_findings_for_scan_id, get_recent_scans_page, get_scan_result_by_id


API_VERSION = "18.2"
LOCAL_DASHBOARD_ORIGINS = ("http://localhost:5173", "http://127.0.0.1:5173")
ScanExecutor = Callable[..., dict[str, Any]]
ERROR_RESPONSES = {
    400: {"model": ErrorResponse, "description": "Invalid request."},
    401: {"model": ErrorResponse, "description": "Invalid or missing API key."},
    404: {"model": ErrorResponse, "description": "Requested local resource was not found."},
    422: {"model": ErrorResponse, "description": "Request validation failed."},
    500: {"model": ErrorResponse, "description": "Safe internal API error."},
}
PROTECTED_PATHS = {
    "/scans",
    "/scans/{scan_id}",
    "/scans/{scan_id}/findings",
    "/jobs",
    "/jobs/{job_id}",
    "/jobs/{job_id}/result",
    "/jobs/{job_id}/findings",
    "/exports/findings",
    "/reports",
    "/reports/{report_id}/metadata",
    "/reports/{report_id}/download",
    "/reports/{report_id}/view",
    "/bug-bounty/scopes",
    "/bug-bounty/scopes/{program_id}",
    "/bug-bounty/scope-check",
    "/bug-bounty/recon",
    "/bug-bounty/recon/results",
    "/bug-bounty/recon/results/{recon_id}",
    "/bug-bounty/endpoints/analyse",
    "/bug-bounty/endpoints/reports",
    "/remediation",
    "/remediation/summary",
    "/remediation/{finding_key}",
}
TAGS_METADATA = [
    {"name": "Health", "description": "Public local API health checks."},
    {"name": "System", "description": "Public scanner and API version metadata."},
    {"name": "Scans", "description": "Safe scan job creation and saved scan history."},
    {"name": "Jobs", "description": "Persistent API job status and result retrieval."},
    {"name": "Findings", "description": "Saved finding retrieval with filtering, sorting, pagination, and compact responses."},
    {"name": "Exports", "description": "Local export metadata for saved findings."},
    {"name": "Reports", "description": "Safe local report listing, metadata, viewing, and download for reports under the reports directory."},
    {"name": "Bug Bounty", "description": "Local bug bounty scope metadata, recon, and endpoint discovery workflows."},
    {"name": "Remediation", "description": "Tracking-only remediation status and notes. Does not execute remediation actions."},
]
SCAN_REQUEST_EXAMPLE = {
    "target": "127.0.0.1",
    "scan_mode": "safe",
    "json_report": True,
    "html_report": False,
    "save_db": True,
    "vuln_intel": False,
    "prioritise": True,
    "fix_first_dashboard": True,
}
SCAN_RESPONSE_EXAMPLE = {
    "job_id": "job_...",
    "status": "queued",
    "target": "127.0.0.1",
    "status_url": "/jobs/job_...",
    "result_url": "/jobs/job_.../result",
}
JOB_STATUS_EXAMPLE = {
    "job_id": "job_...",
    "status": "completed",
    "target": "127.0.0.1",
    "duration_seconds": 1.25,
    "result_summary": {},
}
FINDING_LIST_EXAMPLE = {
    "findings": [],
    "pagination": {
        "limit": 20,
        "offset": 0,
        "returned": 0,
        "total": 0,
        "has_next": False,
        "has_previous": False,
    },
}
ERROR_EXAMPLE = {"detail": "Invalid or missing API key."}


def create_app(
    scan_executor: ScanExecutor | None = None,
    job_store: ApiJobStore | None = None,
    reports_dir: Path | str = Path("reports"),
    remediation_db_path: Path | str | None = None,
) -> FastAPI:
    """Create the local VulScan FastAPI app."""
    executor = scan_executor or run_scan_pipeline
    store = job_store or ApiJobStore()
    safe_reports_dir = Path(reports_dir)
    safe_remediation_db_path = Path(remediation_db_path) if remediation_db_path is not None else DB_PATH
    store.mark_interrupted_jobs()
    app = FastAPI(
        title="VulScan API",
        version=API_VERSION,
        description=(
            "Local API for authorised vulnerability scanning and reporting. "
            "The API binds to localhost by default, does not accept credentials through API requests, "
            "and does not expose credentialed scan workflows."
        ),
        contact={"name": "VulScan local API"},
        license_info={"name": "Authorised local use only"},
        openapi_tags=TAGS_METADATA,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(LOCAL_DASHBOARD_ORIGINS),
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "OPTIONS"],
        allow_headers=["Content-Type", "X-VulScan-API-Key", "Authorization"],
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

    @app.get(
        "/health",
        tags=["Health"],
        summary="API health check",
        description="Public health check for the local VulScan API.",
        responses={500: ERROR_RESPONSES[500]},
    )
    def health() -> dict[str, str]:
        return {"status": "ok", "scanner": "VulScan"}

    @app.get(
        "/version",
        tags=["System"],
        summary="API and scanner version",
        description="Public scanner package version and local API version metadata.",
        responses={500: ERROR_RESPONSES[500]},
    )
    def version() -> dict[str, str]:
        return {"scanner": "VulScan", "version": __version__, "api_version": API_VERSION}

    @app.get(
        "/bug-bounty/scopes",
        dependencies=[Depends(require_api_key)],
        tags=["Bug Bounty"],
        summary="List local bug bounty scope files",
        description="Lists valid local JSON scope files under data/bug_bounty. Does not read arbitrary paths.",
        responses=ERROR_RESPONSES,
    )
    def list_bug_bounty_scopes() -> dict[str, Any]:
        return {"scopes": list_scope_files()}

    @app.get(
        "/bug-bounty/scopes/{program_id}",
        dependencies=[Depends(require_api_key)],
        tags=["Bug Bounty"],
        summary="Get local bug bounty scope",
        description="Returns local scope metadata and rules by program ID from data/bug_bounty.",
        responses=ERROR_RESPONSES,
    )
    def get_bug_bounty_scope(program_id: str) -> dict[str, Any]:
        result = get_scope_by_program_id(program_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Bug bounty scope program was not found.")
        return result

    @app.post(
        "/bug-bounty/scope-check",
        dependencies=[Depends(require_api_key)],
        tags=["Bug Bounty"],
        summary="Check target against local bug bounty scope",
        description="Evaluates a target, URL, domain, or IP against one local JSON scope file under data/bug_bounty.",
        responses=ERROR_RESPONSES,
    )
    def check_bug_bounty_scope(request: ScopeCheckRequest) -> dict[str, Any]:
        try:
            return check_scope(request.target, request.scope_file)
        except BugBountyScopeError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post(
        "/bug-bounty/recon",
        dependencies=[Depends(require_api_key)],
        tags=["Bug Bounty"],
        summary="Run safe bug bounty recon",
        description="Runs synchronous metadata-only recon for provided targets. Does not brute-force or query third-party APIs.",
        responses=ERROR_RESPONSES,
    )
    def start_bug_bounty_recon(request: BugBountyReconRequest) -> dict[str, Any]:
        if not request.targets:
            raise HTTPException(status_code=400, detail="At least one recon target is required.")
        try:
            scope_file = str(resolve_scope_file(request.scope_file)) if request.scope_file else None
            result = run_bug_bounty_recon(
                raw_targets=request.targets,
                scope_file=scope_file,
                enforce_scope=request.enforce_scope,
                request_delay=request.request_delay,
                max_requests_per_minute=request.max_requests_per_minute,
                timeout=request.timeout,
                max_redirects=request.max_redirects,
                input_source="api",
            )
        except (BugBountyScopeError, BugBountyReconError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return result

    @app.get(
        "/bug-bounty/recon/results",
        dependencies=[Depends(require_api_key)],
        tags=["Bug Bounty"],
        summary="List local recon reports",
        description="Lists local JSON recon reports from reports/recon.",
        responses=ERROR_RESPONSES,
    )
    def list_bug_bounty_recon_results() -> dict[str, Any]:
        return {"reports": list_recon_reports()}

    @app.get(
        "/bug-bounty/recon/results/{recon_id}",
        dependencies=[Depends(require_api_key)],
        tags=["Bug Bounty"],
        summary="Get local recon report",
        description="Returns a local JSON recon report by recon ID from reports/recon.",
        responses=ERROR_RESPONSES,
    )
    def get_bug_bounty_recon_result(recon_id: str) -> dict[str, Any]:
        result = load_recon_report(recon_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Recon report was not found.")
        return {"recon_id": recon_id, "result": result}

    @app.post(
        "/bug-bounty/endpoints/analyse",
        dependencies=[Depends(require_api_key)],
        tags=["Bug Bounty"],
        summary="Analyse endpoint and parameter candidates",
        description="Analyses supplied URLs and paths without sending network requests or payloads.",
        responses=ERROR_RESPONSES,
    )
    def analyse_bug_bounty_endpoints(request: EndpointDiscoveryRequest) -> dict[str, Any]:
        if not request.urls:
            raise HTTPException(status_code=400, detail="At least one endpoint URL or path is required.")
        try:
            scope_file = str(resolve_scope_file(request.scope_file)) if request.scope_file else None
            result = run_endpoint_discovery(
                raw_urls=request.urls,
                base_url=request.base_url,
                scope_file=scope_file,
                enforce_scope=request.enforce_scope,
                input_source="api",
            )
            save_endpoint_report(result)
            return result
        except (BugBountyScopeError, EndpointDiscoveryError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get(
        "/bug-bounty/endpoints/reports",
        dependencies=[Depends(require_api_key)],
        tags=["Bug Bounty"],
        summary="List local endpoint discovery reports",
        description="Lists local JSON endpoint discovery reports from reports/endpoints.",
        responses=ERROR_RESPONSES,
    )
    def list_bug_bounty_endpoint_reports() -> dict[str, Any]:
        return {"reports": list_endpoint_reports()}

    @app.post(
        "/scans",
        response_model=ScanResponse,
        dependencies=[Depends(require_api_key)],
        tags=["Scans"],
        summary="Create scan job",
        description="Creates a safe scan job and returns job status URLs. Does not accept credentials.",
        responses={
            200: {"description": "Scan job was created.", "content": {"application/json": {"example": SCAN_RESPONSE_EXAMPLE}}},
            **ERROR_RESPONSES,
        },
        openapi_extra={"requestBody": {"content": {"application/json": {"example": SCAN_REQUEST_EXAMPLE}}}},
    )
    def start_scan(request: ScanRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
        if request.scan_mode.lower() != "safe":
            raise HTTPException(status_code=400, detail="Version 18.1 API supports only safe scan_mode.")
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
            "status_url": f"/jobs/{job_id}",
            "result_url": f"/jobs/{job_id}/result",
        }

    @app.get(
        "/scans",
        response_model=ScanSummaryResponse,
        dependencies=[Depends(require_api_key)],
        tags=["Scans"],
        summary="List saved scans",
        description="Lists saved local SQLite scan history with filtering, pagination, and sorting.",
        responses=ERROR_RESPONSES,
    )
    def list_scans(
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        target: str | None = Query(default=None, min_length=1, max_length=255),
        sort_by: str | None = Query(default=None),
        sort_order: str = Query(default="desc"),
    ) -> dict[str, Any]:
        try:
            sort_by = validate_sort_by(sort_by or "scan_time", {"scan_time", "target", "duration_seconds"})
            sort_order = validate_sort_order(sort_order)
            scans, total = get_recent_scans_page(
                limit=limit,
                offset=offset,
                target=target,
                sort_by=sort_by,
                sort_order=sort_order,
            )
            return {
                "scans": scans,
                "pagination": pagination_metadata(total, len(scans), limit, offset),
                "filters": active_filters(target=target, sort_by=sort_by, sort_order=sort_order),
            }
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail="Could not read local scan history.") from exc

    @app.get(
        "/scans/{scan_id}",
        dependencies=[Depends(require_api_key)],
        tags=["Scans"],
        summary="Get saved scan result",
        description="Returns a saved local scan result snapshot by scan ID.",
        responses=ERROR_RESPONSES,
    )
    def get_scan(scan_id: str) -> dict[str, Any]:
        result = get_scan_result_by_id(scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Scan ID was not found in local history.")
        return {"scan_id": scan_id, "result": result}

    @app.get(
        "/scans/{scan_id}/findings",
        response_model=FindingResponse,
        dependencies=[Depends(require_api_key)],
        tags=["Findings"],
        summary="Get findings for saved scan",
        description="Returns saved findings for a scan ID with filtering, sorting, pagination, and compact response support.",
        responses=ERROR_RESPONSES,
    )
    def get_scan_findings(
        scan_id: str,
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        severity: str | None = Query(default=None),
        source: str | None = Query(default=None),
        category: str | None = Query(default=None),
        priority_label: str | None = Query(default=None),
        min_priority_score: float | None = Query(default=None),
        min_risk_score: float | None = Query(default=None),
        cve: str | None = Query(default=None),
        sort_by: str | None = Query(default=None),
        sort_order: str = Query(default="desc"),
        compact: bool = Query(default=False),
    ) -> dict[str, Any]:
        findings = get_findings_for_scan_id(scan_id)
        if findings is None:
            raise HTTPException(status_code=404, detail="Scan ID was not found in local history.")
        return _filtered_findings_response(
            {"scan_id": scan_id},
            findings,
            limit=limit,
            offset=offset,
            severity=severity,
            source=source,
            category=category,
            priority_label=priority_label,
            min_priority_score=min_priority_score,
            min_risk_score=min_risk_score,
            cve=cve,
            sort_by=sort_by,
            sort_order=sort_order,
            compact=compact,
            target=None,
            remediation_db_path=safe_remediation_db_path,
        )

    @app.get(
        "/jobs",
        response_model=JobSummaryResponse,
        dependencies=[Depends(require_api_key)],
        tags=["Jobs"],
        summary="List scan jobs",
        description="Lists persistent local API scan jobs with filtering, pagination, and sorting.",
        responses=ERROR_RESPONSES,
    )
    def list_jobs(
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        status: str | None = Query(default=None, pattern="^(queued|running|completed|failed|cancelled)$"),
        target: str | None = Query(default=None, min_length=1, max_length=255),
        sort_by: str | None = Query(default=None),
        sort_order: str = Query(default="desc"),
    ) -> dict[str, Any]:
        try:
            sort_by = validate_sort_by(
                sort_by or "created_at",
                {"created_at", "updated_at", "completed_at", "duration_seconds", "status", "target"},
            )
            sort_order = validate_sort_order(sort_order)
            jobs, total = store.list_jobs_page(
                limit=limit,
                offset=offset,
                status=status,
                target=target,
                sort_by=sort_by,
                sort_order=sort_order,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "jobs": [_public_job(job, safe_reports_dir) for job in jobs],
            "pagination": pagination_metadata(total, len(jobs), limit, offset),
            "filters": active_filters(status=status, target=target, sort_by=sort_by, sort_order=sort_order),
        }

    @app.get(
        "/jobs/{job_id}",
        dependencies=[Depends(require_api_key)],
        tags=["Jobs"],
        summary="Get job status",
        description="Returns persistent local job metadata and current status by job ID.",
        responses={
            200: {"description": "Persistent job status.", "content": {"application/json": {"example": JOB_STATUS_EXAMPLE}}},
            **ERROR_RESPONSES,
        },
    )
    def get_job(job_id: str) -> dict[str, Any]:
        job = store.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job ID was not found in local job history.")
        return _public_job(job, safe_reports_dir)

    @app.get(
        "/jobs/{job_id}/result",
        dependencies=[Depends(require_api_key)],
        tags=["Jobs"],
        summary="Get completed job result",
        description="Returns the completed job result from a saved JSON report or local scan history when available.",
        responses=ERROR_RESPONSES,
    )
    def get_job_result(job_id: str) -> dict[str, Any]:
        job = store.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job ID was not found in local job history.")
        if job["status"] != "completed":
            return {"job": _public_job(job, safe_reports_dir), "result": None}
        result = _load_job_result(job)
        if result is None:
            return {"job_id": job_id, "status": "completed", "message": UNAVAILABLE_RESULT_MESSAGE, "result": None}
        return {"job_id": job_id, "status": "completed", "result": result}

    @app.get(
        "/jobs/{job_id}/findings",
        dependencies=[Depends(require_api_key)],
        tags=["Findings"],
        summary="Get findings for completed job",
        description="Returns findings for a completed API job with filtering, sorting, pagination, and compact response support.",
        responses={
            200: {"description": "Paginated findings for the completed job.", "content": {"application/json": {"example": FINDING_LIST_EXAMPLE}}},
            **ERROR_RESPONSES,
        },
    )
    def get_job_findings(
        job_id: str,
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        severity: str | None = Query(default=None),
        source: str | None = Query(default=None),
        category: str | None = Query(default=None),
        priority_label: str | None = Query(default=None),
        min_priority_score: float | None = Query(default=None),
        min_risk_score: float | None = Query(default=None),
        cve: str | None = Query(default=None),
        sort_by: str | None = Query(default=None),
        sort_order: str = Query(default="desc"),
        compact: bool = Query(default=False),
    ) -> dict[str, Any]:
        job = store.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job ID was not found in local job history.")
        if job["status"] != "completed":
            return {
                "job_id": job_id,
                "status": job["status"],
                "message": "Job is not completed yet.",
                "findings": [],
                "pagination": pagination_metadata(0, 0, limit, offset),
                "filters": active_filters(
                    severity=severity,
                    source=source,
                    category=category,
                    priority_label=priority_label,
                    min_priority_score=min_priority_score,
                    min_risk_score=min_risk_score,
                    cve=cve,
                    sort_by=sort_by,
                    sort_order=sort_order,
                    compact=compact,
                ),
            }
        result = _load_job_result(job)
        if result is None:
            return {
                "job_id": job_id,
                "status": "completed",
                "message": UNAVAILABLE_FINDINGS_MESSAGE,
                "findings": [],
                "pagination": pagination_metadata(0, 0, limit, offset),
                "filters": active_filters(sort_order=sort_order, compact=compact),
            }
        return _filtered_findings_response(
            {"job_id": job_id, "status": "completed"},
            list(result.get("findings") or []),
            limit=limit,
            offset=offset,
            severity=severity,
            source=source,
            category=category,
            priority_label=priority_label,
            min_priority_score=min_priority_score,
            min_risk_score=min_risk_score,
            cve=cve,
            sort_by=sort_by,
            sort_order=sort_order,
            compact=compact,
            target=str(job.get("target") or ""),
            remediation_db_path=safe_remediation_db_path,
        )

    @app.get(
        "/exports/findings",
        dependencies=[Depends(require_api_key)],
        tags=["Exports"],
        summary="Export findings",
        description="Exports saved local findings to CSV or JSON with optional filtering and pagination controls.",
        responses=ERROR_RESPONSES,
    )
    def export_saved_findings(
        format: str = Query(default="json", pattern="^(csv|json)$"),
        target: str | None = Query(default=None, min_length=1, max_length=255),
        severity: str | None = Query(default=None),
        source: str | None = Query(default=None),
        category: str | None = Query(default=None),
        priority_label: str | None = Query(default=None),
        min_priority_score: float | None = Query(default=None),
        min_risk_score: float | None = Query(default=None),
        limit: int | None = Query(default=None, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        result = export_findings(
            format,
            target=target,
            severity=severity,
            source=source,
            category=category,
            priority_label=priority_label,
            min_priority_score=min_priority_score,
            min_risk_score=min_risk_score,
            limit=limit,
            offset=offset,
        )
        if result.get("status") == "unsupported_format":
            raise HTTPException(status_code=400, detail="Supported export formats are csv and json.")
        if result.get("status") in {"missing_database", "missing_table"}:
            raise HTTPException(status_code=404, detail=result.get("message") or "No local export data is available.")
        response = dict(result)
        if response.get("path") is not None:
            response["export_path"] = str(response.pop("path"))
        return response

    @app.get(
        "/remediation",
        dependencies=[Depends(require_api_key)],
        tags=["Remediation"],
        summary="List remediation tracking records",
        description="Lists local remediation tracking records. This endpoint does not execute remediation or connect to targets.",
        responses=ERROR_RESPONSES,
    )
    def list_remediation(
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        target: str | None = Query(default=None, min_length=1, max_length=255),
        status: str | None = Query(default=None, pattern="^(open|in_progress|fixed|accepted_risk|false_positive)$"),
        severity: str | None = Query(default=None),
        source: str | None = Query(default=None),
        priority_label: str | None = Query(default=None),
    ) -> dict[str, Any]:
        try:
            records = list_remediation_records(
                target=target,
                status=status,
                severity=severity,
                source=source,
                priority_label=priority_label,
                db_path=safe_remediation_db_path,
            )
            page, pagination = paginate_items(records, limit, offset)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "records": page,
            "pagination": pagination,
            "filters": active_filters(target=target, status=status, severity=severity, source=source, priority_label=priority_label),
        }

    @app.get(
        "/remediation/summary",
        dependencies=[Depends(require_api_key)],
        tags=["Remediation"],
        summary="Get remediation tracking summary",
        description="Returns local remediation tracking counts. This endpoint does not execute remediation.",
        responses=ERROR_RESPONSES,
    )
    def remediation_summary() -> dict[str, Any]:
        return get_remediation_summary(db_path=safe_remediation_db_path)

    @app.get(
        "/remediation/{finding_key}",
        dependencies=[Depends(require_api_key)],
        tags=["Remediation"],
        summary="Get remediation tracking record",
        description="Returns local remediation tracking status and history for one finding key.",
        responses=ERROR_RESPONSES,
    )
    def remediation_record(finding_key: str) -> dict[str, Any]:
        record = get_remediation_record(finding_key, db_path=safe_remediation_db_path)
        if record is None:
            raise HTTPException(status_code=404, detail="Remediation record was not found.")
        return {"record": record}

    @app.put(
        "/remediation/{finding_key}",
        dependencies=[Depends(require_api_key)],
        tags=["Remediation"],
        summary="Update remediation tracking status",
        description="Updates local remediation tracking status and notes only. Does not run commands, patch systems, or connect to targets.",
        responses=ERROR_RESPONSES,
    )
    def update_remediation(finding_key: str, request: RemediationUpdateRequest) -> dict[str, Any]:
        try:
            record = update_remediation_record(
                finding_key,
                status=request.status,
                note=request.note,
                owner=request.owner,
                due_date=request.due_date,
                db_path=safe_remediation_db_path,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if record is None:
            raise HTTPException(status_code=404, detail="Remediation record was not found.")
        return {
            "finding_key": record["finding_key"],
            "status": record["status"],
            "updated_at": record["updated_at"],
            "note": record.get("note"),
            "record": record,
        }

    @app.get(
        "/reports",
        dependencies=[Depends(require_api_key)],
        tags=["Reports"],
        summary="List saved reports",
        description="Lists JSON and HTML reports under the local VulScan reports directory. Does not serve arbitrary file paths.",
        responses=ERROR_RESPONSES,
    )
    def list_reports(
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        type: str = Query(default="all", pattern="^(json|html|all)$"),
        target: str | None = Query(default=None, min_length=1, max_length=255),
    ) -> dict[str, Any]:
        reports = list_report_metadata(reports_dir=safe_reports_dir, report_type=type, target=target)
        page, pagination = paginate_items(reports, limit, offset)
        return {
            "reports": page,
            "pagination": pagination,
            "filters": active_filters(type=type, target=target),
        }

    @app.get(
        "/reports/{report_id}/metadata",
        dependencies=[Depends(require_api_key)],
        tags=["Reports"],
        summary="Get saved report metadata",
        description="Returns safe metadata for one JSON or HTML report under the local reports directory.",
        responses=ERROR_RESPONSES,
    )
    def get_report_metadata(report_id: str) -> dict[str, Any]:
        path = _report_path_or_404(report_id, safe_reports_dir)
        metadata = report_metadata(path, safe_reports_dir)
        if not metadata:
            raise HTTPException(status_code=404, detail="Report was not found.")
        return {"report": metadata}

    @app.get(
        "/reports/{report_id}/download",
        dependencies=[Depends(require_api_key)],
        tags=["Reports"],
        summary="Download saved report",
        description="Downloads a JSON or HTML report from the local reports directory as an attachment.",
        responses=ERROR_RESPONSES,
    )
    def download_report(report_id: str) -> FileResponse:
        path = _report_path_or_404(report_id, safe_reports_dir)
        media_type = "application/json" if path.suffix.lower() == ".json" else "text/html"
        return FileResponse(path, media_type=media_type, filename=path.name)

    @app.get(
        "/reports/{report_id}/view",
        dependencies=[Depends(require_api_key)],
        tags=["Reports"],
        summary="View saved report",
        description="Returns HTML reports for browser viewing. JSON reports return safe report JSON metadata/payload.",
        responses=ERROR_RESPONSES,
    )
    def view_report(report_id: str):
        path = _report_path_or_404(report_id, safe_reports_dir)
        if path.suffix.lower() == ".html":
            try:
                return HTMLResponse(path.read_text(encoding="utf-8"))
            except OSError as exc:
                raise HTTPException(status_code=404, detail="Report was not found.") from exc
        payload = load_json_report(path)
        if payload is None:
            return JSONResponse({"message": "JSON report view is unavailable. Use the download endpoint."})
        return JSONResponse(payload)

    _install_custom_openapi(app)
    return app


def _public_job(job: dict[str, Any], reports_dir: Path | str = Path("reports")) -> dict[str, Any]:
    response = {
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
    result_urls = report_urls_for_path(job.get("result_path"), reports_dir)
    html_urls = report_urls_for_path(job.get("html_report_path"), reports_dir)
    if result_urls["download_url"]:
        response["result_download_url"] = result_urls["download_url"]
    if html_urls["view_url"]:
        response["html_view_url"] = html_urls["view_url"]
    if html_urls["download_url"]:
        response["html_download_url"] = html_urls["download_url"]
    return response


def _report_path_or_404(report_id: str, reports_dir: Path | str) -> Path:
    path = decode_report_id(report_id, reports_dir)
    if path is None or not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="Report was not found.")
    return path


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


def _filtered_findings_response(
    base: dict[str, Any],
    findings: list[dict[str, Any]],
    *,
    limit: int,
    offset: int,
    severity: str | None,
    source: str | None,
    category: str | None,
    priority_label: str | None,
    min_priority_score: float | None,
    min_risk_score: float | None,
    cve: str | None,
    sort_by: str | None,
    sort_order: str,
    compact: bool,
    target: str | None = None,
    remediation_db_path: Path | str = DB_PATH,
) -> dict[str, Any]:
    try:
        findings = attach_finding_keys(findings, target=target, db_path=remediation_db_path)
        sort_by = validate_sort_by(
            sort_by,
            {"severity", "risk_score", "priority_score", "title", "source", "category"},
        )
        sort_order = validate_sort_order(sort_order)
        filters = active_filters(
            severity=severity,
            source=source,
            category=category,
            priority_label=priority_label,
            min_priority_score=min_priority_score,
            min_risk_score=min_risk_score,
            cve=cve,
            sort_by=sort_by,
            sort_order=sort_order,
            compact=compact,
        )
        filtered = filter_findings(findings, filters)
        sorted_findings = sort_findings(filtered, sort_by, sort_order)
        page, pagination = paginate_items(sorted_findings, limit, offset)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    response = dict(base)
    response["findings"] = compact_findings(page, compact)
    response["pagination"] = pagination
    response["filters"] = filters
    return response


def _install_custom_openapi(app: FastAPI) -> None:
    """Install OpenAPI metadata that documents local API key protection."""

    def custom_openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
            tags=TAGS_METADATA,
        )
        components = schema.setdefault("components", {})
        security_schemes = components.setdefault("securitySchemes", {})
        security_schemes["VulScanApiKey"] = {
            "type": "apiKey",
            "in": "header",
            "name": "X-VulScan-API-Key",
            "description": "Local API key from the VULSCAN_API_KEY environment variable. Do not include real keys in examples or code.",
        }
        for path, methods in schema.get("paths", {}).items():
            for operation in methods.values():
                if path in PROTECTED_PATHS:
                    operation["security"] = [{"VulScanApiKey": []}]
                else:
                    operation["security"] = []
        app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = custom_openapi


app = create_app()
