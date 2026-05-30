"""Pydantic models for the local VulScan API foundation."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class StrictApiModel(BaseModel):
    """Base model that rejects unexpected fields, including credential-like inputs."""

    model_config = ConfigDict(extra="forbid")


class PaginationMetadata(StrictApiModel):
    limit: int = Field(20, description="Maximum number of records returned in this page.", examples=[20])
    offset: int = Field(0, description="Zero-based offset into the matching result set.", examples=[0])
    returned: int = Field(0, description="Number of records returned in this response.", examples=[0])
    total: int = Field(0, description="Total number of records matching the request.", examples=[0])
    has_next: bool = Field(False, description="Whether another page exists after this response.", examples=[False])
    has_previous: bool = Field(False, description="Whether a previous page exists before this response.", examples=[False])
    next_offset: int | None = Field(None, description="Offset to request the next page, if available.", examples=[20])
    previous_offset: int | None = Field(None, description="Offset to request the previous page, if available.", examples=[0])


class ScanRequest(StrictApiModel):
    """Safe scan request accepted by the Version 18.0 API."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "target": "127.0.0.1",
                    "scan_mode": "safe",
                    "json_report": True,
                    "html_report": False,
                    "save_db": True,
                    "vuln_intel": False,
                    "prioritise": True,
                    "fix_first_dashboard": True,
                }
            ]
        },
    )

    target: str = Field(..., min_length=1, max_length=255, description="Authorised local scan target.", examples=["127.0.0.1"])
    scan_mode: str = Field("safe", description="API scan mode. Version 18.0 accepts safe mode only.", examples=["safe"])
    json_report: bool = Field(False, description="Write a local JSON report for the job.", examples=[True])
    html_report: bool = Field(False, description="Write a local HTML report for the job.", examples=[False])
    save_db: bool = Field(True, description="Save scan history and findings to local SQLite storage.", examples=[True])
    vuln_intel: bool = Field(False, description="Enable local vulnerability intelligence matching.", examples=[False])
    prioritise: bool = Field(False, description="Enable local prioritisation for findings.", examples=[True])
    fix_first_dashboard: bool = Field(False, description="Include fix-first dashboard data when prioritisation is enabled.", examples=[True])


class ScanResponse(StrictApiModel):
    job_id: str | None = Field(None, description="Persistent API job identifier.", examples=["job_..."])
    scan_id: str = Field("", description="Completed scan identifier, if already available.", examples=["scan_..."])
    status: str = Field(..., description="Current job status.", examples=["queued"])
    target: str = Field(..., description="Authorised scan target.", examples=["127.0.0.1"])
    summary: dict[str, Any] = Field(default_factory=dict, description="Safe result summary for completed jobs.", examples=[{}])
    result_path: str | None = Field(None, description="Local JSON report path, if a report was written.", examples=["reports/example.json"])
    html_report_path: str | None = Field(None, description="Local HTML report path, if a report was written.", examples=["reports/example.html"])
    retrievable: bool = Field(True, description="Whether VulScan expects result retrieval to be available.", examples=[True])
    status_url: str | None = Field(None, description="Relative URL for job status.", examples=["/jobs/job_..."])
    result_url: str | None = Field(None, description="Relative URL for job result retrieval.", examples=["/jobs/job_.../result"])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "job_id": "job_...",
                    "status": "queued",
                    "target": "127.0.0.1",
                    "status_url": "/jobs/job_...",
                    "result_url": "/jobs/job_.../result",
                }
            ]
        },
    )


class ScanSummaryResponse(StrictApiModel):
    scans: list[dict[str, Any]] = Field(default_factory=list, description="Saved scan summaries.")
    pagination: PaginationMetadata | dict[str, Any] | None = Field(None, description="Pagination metadata for this response.")
    filters: dict[str, Any] | None = Field(None, description="Active filters and sorting applied to this response.", examples=[{"target": "127.0.0.1"}])


class JobSummaryResponse(StrictApiModel):
    jobs: list[dict[str, Any]] = Field(default_factory=list, description="Persistent API job summaries.")
    pagination: PaginationMetadata | dict[str, Any] | None = Field(None, description="Pagination metadata for this response.")
    filters: dict[str, Any] | None = Field(None, description="Active filters and sorting applied to this response.", examples=[{"status": "completed"}])


class FindingResponse(StrictApiModel):
    scan_id: str = Field("", description="Saved scan identifier.", examples=["scan_..."])
    findings: list[dict[str, Any]] = Field(default_factory=list, description="Finding records matching the request.", examples=[[]])
    pagination: PaginationMetadata | dict[str, Any] | None = Field(None, description="Pagination metadata for this response.")
    filters: dict[str, Any] | None = Field(None, description="Active finding filters and sorting applied to this response.", examples=[{"severity": "High"}])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
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
            ]
        },
    )


class RemediationUpdateRequest(StrictApiModel):
    """Tracking-only remediation status update."""

    status: str = Field(..., description="Tracking status only. Does not execute remediation.", examples=["in_progress"])
    note: str | None = Field(None, max_length=1000, description="Local tracking note. Do not include secrets.", examples=["Reviewing remediation options."])
    owner: str | None = Field(None, max_length=255, description="Optional local owner note.", examples=["security-team"])
    due_date: str | None = Field(None, max_length=64, description="Optional ISO date or datetime.", examples=["2026-06-15"])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "status": "in_progress",
                    "note": "Reviewing remediation options.",
                    "owner": "security-team",
                    "due_date": "2026-06-15",
                }
            ]
        },
    )


class ScopeCheckRequest(StrictApiModel):
    """Local bug bounty scope decision request."""

    target: str = Field(..., min_length=1, max_length=2048, description="Target, domain, IP, or URL to check.", examples=["https://demo-web.local/"])
    scope_file: str = Field(..., min_length=1, max_length=512, description="Local scope JSON file under data/bug_bounty.", examples=["data/bug_bounty/sample_program_scope.json"])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "target": "https://demo-web.local/",
                    "scope_file": "data/bug_bounty/sample_program_scope.json",
                }
            ]
        },
    )


class ErrorResponse(StrictApiModel):
    error: str | None = Field(None, description="Short safe error category.", examples=["Request failed."])
    detail: str | None = Field(None, description="User-facing safe error detail without tracebacks or secrets.", examples=["Invalid or missing API key."])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"examples": [{"detail": "Invalid or missing API key."}]},
    )
