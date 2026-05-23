"""Pydantic models for the local VulScan API foundation."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class StrictApiModel(BaseModel):
    """Base model that rejects unexpected fields, including credential-like inputs."""

    model_config = ConfigDict(extra="forbid")


class ScanRequest(StrictApiModel):
    """Safe scan request accepted by the Version 15.2 API."""

    target: str = Field(..., min_length=1, max_length=255)
    scan_mode: str = "safe"
    json_report: bool = False
    html_report: bool = False
    save_db: bool = True
    vuln_intel: bool = False
    prioritise: bool = False
    fix_first_dashboard: bool = False


class ScanResponse(StrictApiModel):
    scan_id: str
    status: str
    target: str
    summary: dict[str, Any]
    result_path: str | None = None
    html_report_path: str | None = None
    retrievable: bool = True


class ScanSummaryResponse(StrictApiModel):
    scans: list[dict[str, Any]]


class JobSummaryResponse(StrictApiModel):
    jobs: list[dict[str, Any]]


class FindingResponse(StrictApiModel):
    scan_id: str
    findings: list[dict[str, Any]]


class ErrorResponse(StrictApiModel):
    error: str
    detail: str | None = None
