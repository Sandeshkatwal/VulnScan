"""Local FastAPI application for the VulScan API foundation."""

from __future__ import annotations

from typing import Any, Callable

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from scanner import __version__
from scanner.api_models import FindingResponse, JobSummaryResponse, ScanRequest, ScanResponse, ScanSummaryResponse
from scanner.api_runner import run_scan_pipeline
from scanner.api_security import require_api_key
from scanner.exporter import export_findings
from scanner.history import get_findings_for_scan_id, get_recent_scans, get_scan_result_by_id
from scanner.port_scan import PortScanError


API_VERSION = "15.2"
ScanExecutor = Callable[..., dict[str, Any]]


def create_app(scan_executor: ScanExecutor | None = None) -> FastAPI:
    """Create the local VulScan FastAPI app."""
    executor = scan_executor or run_scan_pipeline
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
    def start_scan(request: ScanRequest) -> dict[str, Any]:
        if request.scan_mode.lower() != "safe":
            raise HTTPException(status_code=400, detail="Version 15.2 API supports only safe scan_mode.")
        try:
            result = executor(
                target=request.target,
                scan_mode=request.scan_mode,
                json_report=request.json_report,
                html_report=request.html_report,
                save_db=request.save_db,
                vuln_intel=request.vuln_intel,
                prioritise=request.prioritise,
                fix_first_dashboard=request.fix_first_dashboard,
                scanner_name="VulScan",
                scanner_version=__version__,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except PortScanError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail="Scan failed. Review the target and local scanner configuration.") from exc
        return {
            "scan_id": str(result.get("scan_id") or ""),
            "status": str(result.get("status") or "completed"),
            "target": str(result.get("target") or request.target),
            "summary": dict(result.get("summary") or {}),
            "result_path": result.get("result_path"),
            "html_report_path": result.get("html_report_path"),
            "retrievable": bool(result.get("retrievable", request.save_db)),
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
    def list_jobs() -> dict[str, list[dict[str, Any]]]:
        return {"jobs": []}

    @app.get("/jobs/{job_id}", dependencies=[Depends(require_api_key)])
    def get_job(job_id: str) -> dict[str, Any]:
        raise HTTPException(status_code=404, detail="Job ID was not found in local job history.")

    @app.get("/jobs/{job_id}/result", dependencies=[Depends(require_api_key)])
    def get_job_result(job_id: str) -> dict[str, Any]:
        raise HTTPException(status_code=404, detail="Job ID was not found in local job history.")

    @app.get("/jobs/{job_id}/findings", dependencies=[Depends(require_api_key)])
    def get_job_findings(job_id: str) -> dict[str, Any]:
        raise HTTPException(status_code=404, detail="Job ID was not found in local job history.")

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
