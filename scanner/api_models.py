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
    """Safe scan request accepted by the Version 18.1 API."""

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
    scan_mode: str = Field("safe", description="API scan mode. Version 18.1 accepts safe mode only.", examples=["safe"])
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
    """Local program scope decision request."""

    target: str = Field(..., min_length=1, max_length=2048, description="Target, domain, IP, or URL to check.", examples=["https://demo-web.local/"])
    scope_file: str = Field(..., min_length=1, max_length=512, description="Local Program Scope JSON file under data/programs or legacy data/bug_bounty.", examples=["data/programs/sample_program_scope.json"])

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


class BugBountyReconRequest(StrictApiModel):
    """Synchronous Recon Intelligence request."""

    targets: list[str] = Field(default_factory=list, description="Manual targets, one item per provided string.", examples=[["http://127.0.0.1:8000/", "demo-web.local"]])
    scope_file: str | None = Field(None, max_length=512, description="Optional local Program Scope JSON file under data/programs or legacy data/bug_bounty.", examples=["data/programs/sample_program_scope.json"])
    enforce_scope: bool = Field(True, description="Skip out-of-scope targets before probing.", examples=[True])
    request_delay: float = Field(1.0, ge=0, le=30, description="Seconds to wait between requests.", examples=[1.0])
    max_requests_per_minute: int = Field(30, ge=1, le=120, description="Maximum request rate.", examples=[30])
    timeout: float = Field(5.0, gt=0, le=30, description="Per-request timeout in seconds.", examples=[5.0])
    max_redirects: int = Field(5, ge=0, le=10, description="Maximum redirects to allow.", examples=[5])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "targets": ["http://127.0.0.1:8000/", "demo-web.local"],
                    "scope_file": "data/bug_bounty/sample_program_scope.json",
                    "enforce_scope": True,
                    "request_delay": 1.0,
                    "max_requests_per_minute": 30,
                    "timeout": 5,
                }
            ]
        },
    )


class EndpointDiscoveryRequest(StrictApiModel):
    """Synchronous safe endpoint discovery request."""

    urls: list[str] = Field(default_factory=list, description="URLs or paths to analyse, one item per string.", examples=[["http://127.0.0.1:8000/account?id=123"]])
    base_url: str | None = Field(None, max_length=2048, description="Base URL for path-only entries.", examples=["http://127.0.0.1:8000"])
    scope_file: str | None = Field(None, max_length=512, description="Optional local Program Scope JSON file under data/programs or legacy data/bug_bounty.", examples=["data/programs/sample_program_scope.json"])
    enforce_scope: bool = Field(True, description="Skip out-of-scope URLs before returning candidates.", examples=[True])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "urls": [
                        "http://127.0.0.1:8000/account?id=123",
                        "http://127.0.0.1:8000/redirect?next=/dashboard",
                    ],
                    "base_url": "http://127.0.0.1:8000",
                    "scope_file": "data/bug_bounty/sample_program_scope.json",
                    "enforce_scope": True,
                }
            ]
        },
    )


class RoleMappingValidateRequest(StrictApiModel):
    """Validate Role Profiles and Access-Control Matrix data without live requests."""

    roles: list[dict[str, Any]] = Field(default_factory=list, description="Safe Role Profiles. Do not include credentials.")
    permission_matrix: dict[str, Any] = Field(default_factory=dict, description="Access-Control Matrix planning data.")

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "roles": [{"role_id": "standard_user", "role_name": "standard_user", "role_label": "Standard User", "user_type": "standard_user"}],
                    "permission_matrix": {"matrix_id": "sample", "matrix_name": "Sample Access-Control Matrix", "target": "local-demo", "actions": [], "role_action_rules": []},
                }
            ]
        },
    )


class RoleEndpointMapRequest(StrictApiModel):
    """Build Role Endpoint Matrix and Manual Validation Plans without live requests."""

    roles: list[dict[str, Any]] = Field(default_factory=list, description="Safe Role Profiles.")
    permission_matrix: dict[str, Any] = Field(default_factory=dict, description="Access-Control Matrix planning data.")
    endpoint_results: list[dict[str, Any]] = Field(default_factory=list, description="Existing endpoint metadata. No requests are made.")

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "roles": [{"role_id": "standard_user", "role_name": "standard_user", "role_label": "Standard User", "user_type": "standard_user"}],
                    "permission_matrix": {"matrix_id": "sample", "matrix_name": "Sample Access-Control Matrix", "target": "local-demo"},
                    "endpoint_results": [{"url": "http://127.0.0.1:8000/admin/users", "method": "GET"}],
                }
            ]
        },
    )


class RoleManualPlanRequest(StrictApiModel):
    """Generate one Role and Permission Mapping manual validation plan."""

    role: dict[str, Any] = Field(default_factory=dict, description="Safe Role Profile. Do not include credentials.")
    endpoint: dict[str, Any] | str = Field(..., description="Endpoint metadata or URL string. No request is made.")
    expected_permission: str = Field("unknown", description="Expected permission: allowed, denied, conditional, or unknown.", examples=["denied"])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "role": {"role_id": "standard_user", "role_name": "standard_user", "role_label": "Standard User", "user_type": "standard_user"},
                    "endpoint": {"url": "http://127.0.0.1:8000/admin/users", "method": "GET"},
                    "expected_permission": "denied",
                }
            ]
        },
    )


class AccessTestGenerateRequest(StrictApiModel):
    a01_evidence_items: list[dict[str, Any]] = Field(default_factory=list, description="Existing A01 candidate evidence. No live requests are made.")
    role_profiles: list[dict[str, Any]] = Field(default_factory=list, description="Safe Role Profiles.")
    permission_matrix: dict[str, Any] = Field(default_factory=dict, description="Access-Control Matrix planning data.")


class AccessTestCreateRequest(StrictApiModel):
    role: dict[str, Any] = Field(default_factory=dict, description="Safe Role Profile.")
    endpoint: dict[str, Any] | str = Field(..., description="Endpoint metadata or URL string. No request is made.")
    expected_permission: str = Field("unknown", description="Expected permission.")
    test_type: str = Field("custom", description="A01 manual test type.")


class AccessTestObserveRequest(StrictApiModel):
    test_plan_id: str = Field(..., min_length=1, max_length=255)
    observed_access_result: str = Field(..., description="Manual observed access result.")
    observed_status_code: int | None = Field(None, ge=100, le=599)
    observed_message_summary: str = Field("", max_length=2000)
    evidence_summary: str = Field("", max_length=4000)
    evidence_file_path: str = Field("", max_length=1024)
    tester_notes: str = Field("", max_length=4000)


class AccessTestRetestRequest(StrictApiModel):
    test_plan_id: str = Field(..., min_length=1, max_length=255)
    retest_status: str = Field(..., description="Retest Workflow status.")
    original_observed_result: str = Field("", max_length=1000)
    remediation_summary: str = Field("", max_length=4000)
    retest_steps: list[str] = Field(default_factory=list)
    retest_observed_result: str = Field("", max_length=1000)
    retest_notes: str = Field("", max_length=4000)


class AccessTestReportTemplateRequest(StrictApiModel):
    plan: dict[str, Any] = Field(default_factory=dict)
    observation: dict[str, Any] | None = None
    retest: dict[str, Any] | None = None


class AuthProfileValidateRequest(StrictApiModel):
    """Validate a redacted Session Profile object."""

    profile: dict[str, Any] = Field(default_factory=dict, description="Redacted Session Profile object. Raw secrets are not required.", examples=[{}])


class AuthBoundaryCheckRequest(StrictApiModel):
    """Check a URL against a redacted Session Profile boundary."""

    profile: dict[str, Any] = Field(default_factory=dict, description="Redacted Session Profile object.", examples=[{}])
    url: str = Field(..., min_length=1, max_length=2048, description="URL to check against the Authenticated Scope.", examples=["http://127.0.0.1:8000/dashboard"])


class AuthEndpointClassifyRequest(StrictApiModel):
    """Classify supplied endpoint metadata for Auth-Required Endpoint signals."""

    profile: dict[str, Any] = Field(default_factory=dict, description="Redacted Session Profile object.", examples=[{}])
    endpoint_results: list[dict[str, Any]] = Field(default_factory=list, description="Existing endpoint result dictionaries.", examples=[[]])


class AuthenticatedCrawlRequest(StrictApiModel):
    """Run a GET-only Authenticated Crawl with Session Boundary Controls."""

    url: str = Field(..., min_length=1, max_length=2048, description="Authenticated Crawl start URL.", examples=["http://127.0.0.1:8000/dashboard"])
    profile: dict[str, Any] = Field(default_factory=dict, description="Session Profile content. Auth material is redacted from the response.", examples=[{}])
    scope_file: str | None = Field(None, max_length=512, description="Optional local Program Scope file for future scope enforcement.", examples=["data/programs/sample_program_scope.json"])
    enforce_scope: bool = Field(True, description="Keep Program Scope enforcement enabled when a scope file is provided.", examples=[True])
    max_pages: int = Field(30, ge=1, le=200, description="Maximum pages to crawl.", examples=[30])
    max_depth: int = Field(2, ge=0, le=10, description="Maximum link depth.", examples=[2])
    request_delay: float = Field(1.0, ge=0, le=30, description="Seconds between requests.", examples=[1.0])
    timeout: float = Field(5.0, gt=0, le=30, description="Per-request timeout.", examples=[5])
    max_redirects: int = Field(5, ge=0, le=10, description="Maximum redirect entries retained.", examples=[5])
    same_origin_only: bool = Field(True, description="Keep the crawl to the start URL origin.", examples=[True])
    dry_run: bool = Field(False, description="Classify the start URL without sending HTTP requests.", examples=[False])


class OWASPMapRequest(StrictApiModel):
    """Indicator-only OWASP Top 10 mapping request."""

    findings: list[dict[str, Any]] = Field(default_factory=list, description="Existing VulScan finding dictionaries.", examples=[[]])
    endpoint_results: list[dict[str, Any]] = Field(default_factory=list, description="Endpoint discovery candidates.", examples=[[]])
    parameter_results: list[dict[str, Any]] = Field(default_factory=list, description="Parameter intelligence candidates.", examples=[[]])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "findings": [],
                    "endpoint_results": [{"path": "/admin", "endpoint_category": "admin"}],
                    "parameter_results": [{"parameter_name": "id", "parameter_type": "idor"}],
                }
            ]
        },
    )


class OWASPAssessmentBuildRequest(StrictApiModel):
    """Build OWASP Assessment Engine results from supplied local evidence."""

    target: str | None = Field(None, max_length=2048, description="Optional assessment target label.", examples=["https://demo-web.local/"])
    owasp_assessment_summary: dict[str, Any] = Field(default_factory=dict, description="Existing OWASP Assessment summary to consolidate.", examples=[{}])
    owasp_category_results: list[dict[str, Any]] = Field(default_factory=list, description="Existing OWASP category results to consolidate.", examples=[[]])
    owasp_evidence_items: list[dict[str, Any]] = Field(default_factory=list, description="Existing OWASP evidence items to consolidate.", examples=[[]])
    findings: list[dict[str, Any]] = Field(default_factory=list, description="Existing VulScan finding dictionaries.", examples=[[]])
    endpoint_results: list[dict[str, Any]] = Field(default_factory=list, description="Endpoint discovery candidates.", examples=[[]])
    parameter_results: list[dict[str, Any]] = Field(default_factory=list, description="Parameter intelligence candidates.", examples=[[]])
    safe_validation_results: list[dict[str, Any]] = Field(default_factory=list, description="Safe validation result dictionaries.", examples=[[]])
    evidence_records: list[dict[str, Any]] = Field(default_factory=list, description="Manual evidence records without secrets or full response bodies.", examples=[[]])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "findings": [],
                    "endpoint_results": [{"path": "/admin", "endpoint_category": "admin"}],
                    "parameter_results": [{"url": "http://127.0.0.1/account?id=1", "parameter_name": "id", "parameter_type": "idor"}],
                    "safe_validation_results": [],
                    "evidence_records": [],
                }
            ]
        },
    )


class A04AssessmentRequest(StrictApiModel):
    """Build A04 Cryptographic Failures evidence from supplied safe metadata."""

    target: str = Field("", max_length=2048, description="Authorised target URL.", examples=["https://127.0.0.1:8000"])
    headers: dict[str, Any] = Field(default_factory=dict, description="Response headers for the target URL.", examples=[{}])
    set_cookie_headers: list[str] = Field(default_factory=list, description="Set-Cookie header values. Cookie values are redacted and not returned.", examples=[[]])
    urls: list[str] = Field(default_factory=list, description="Known HTTP/HTTPS URLs to assess.", examples=[[]])
    forms: list[dict[str, Any]] = Field(default_factory=list, description="Form metadata from safe discovery. Forms are not submitted.", examples=[[]])
    html_snippet: str = Field("", max_length=20000, description="Limited HTML snippet for mixed content indicators. Full response bodies should not be supplied.", examples=[""])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "target": "https://127.0.0.1:8000",
                    "headers": {},
                    "set_cookie_headers": [],
                    "urls": ["http://127.0.0.1:8000/login?token=example"],
                    "forms": [],
                    "html_snippet": "",
                }
            ]
        },
    )


class A07AssessmentRequest(StrictApiModel):
    """Build A07 Authentication Failures evidence from supplied safe metadata."""

    target: str = Field("", max_length=2048, description="Authorised target URL.", examples=["https://127.0.0.1:8000"])
    urls: list[str] = Field(default_factory=list, description="Known HTTP/HTTPS URLs to assess.", examples=[[]])
    headers: dict[str, Any] = Field(default_factory=dict, description="Response headers for the target URL.", examples=[{}])
    set_cookie_headers: list[str] = Field(default_factory=list, description="Set-Cookie header values. Cookie values are redacted and not returned.", examples=[[]])
    forms: list[dict[str, Any]] = Field(default_factory=list, description="Form metadata from safe discovery. Forms are not submitted.", examples=[[]])
    endpoint_results: list[dict[str, Any]] = Field(default_factory=list, description="Endpoint discovery candidates.", examples=[[]])
    parameter_results: list[dict[str, Any]] = Field(default_factory=list, description="Parameter intelligence candidates.", examples=[[]])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "target": "https://127.0.0.1:8000",
                    "urls": ["https://127.0.0.1:8000/login"],
                    "headers": {},
                    "set_cookie_headers": [],
                    "forms": [],
                    "endpoint_results": [],
                    "parameter_results": [],
                }
            ]
        },
    )


class A05AssessmentRequest(StrictApiModel):
    """Build A05 Injection candidate evidence from supplied safe metadata."""

    target: str = Field("", max_length=2048, description="Authorised target URL.", examples=["http://127.0.0.1:8000"])
    endpoint_results: list[dict[str, Any]] = Field(default_factory=list, description="Endpoint discovery candidates.", examples=[[]])
    parameter_results: list[dict[str, Any]] = Field(default_factory=list, description="Parameter intelligence candidates.", examples=[[]])
    forms: list[dict[str, Any]] = Field(default_factory=list, description="Form metadata from safe discovery. Forms are not submitted.", examples=[[]])
    safe_reflection: bool = Field(False, description="Run harmless marker reflection observation for selected GET parameters.")
    max_reflection_checks: int = Field(10, ge=0, le=50)
    request_delay: float = Field(1.0, ge=0.0, le=30.0)

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "target": "http://127.0.0.1:8000",
                    "endpoint_results": [],
                    "parameter_results": [{"url": "http://127.0.0.1:8000/search?q=test", "parameter_name": "q"}],
                    "forms": [],
                    "safe_reflection": False,
                }
            ]
        },
    )


class A01AssessmentRequest(StrictApiModel):
    """Build A01 Broken Access Control candidate evidence from supplied safe metadata."""

    target: str = Field("", max_length=2048, description="Authorised target URL.", examples=["http://127.0.0.1:8000"])
    endpoint_results: list[dict[str, Any]] = Field(default_factory=list, description="Endpoint discovery candidates.", examples=[[]])
    parameter_results: list[dict[str, Any]] = Field(default_factory=list, description="Parameter intelligence candidates. Parameter values are not required.", examples=[[]])
    evidence_records: list[dict[str, Any]] = Field(default_factory=list, description="Optional manual evidence records without secrets, cookies, tokens, or full response bodies.", examples=[[]])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "target": "http://127.0.0.1:8000",
                    "endpoint_results": [{"url": "http://127.0.0.1:8000/api/users/123"}],
                    "parameter_results": [{"url": "http://127.0.0.1:8000/account?id=123", "parameter_name": "id"}],
                    "evidence_records": [],
                }
            ]
        },
    )


class A01ManualPlanRequest(StrictApiModel):
    """Generate an A01 manual validation plan and evidence template for a candidate."""

    evidence_item: dict[str, Any] = Field(default_factory=dict, description="A01 candidate evidence item. Do not include secrets or sensitive response bodies.", examples=[{}])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "evidence_item": {
                        "title": "Object-level authorization candidate: id",
                        "affected_url": "http://127.0.0.1:8000/account?id",
                        "affected_parameter": "id",
                        "access_control_candidate_type": "object-level authorization candidate",
                        "manual_test_plan_id": "horizontal_access_control_review",
                    }
                }
            ]
        },
    )


class A03AssessmentRequest(StrictApiModel):
    """Build A03 Software Supply Chain evidence from supplied safe metadata."""

    target: str = Field("", max_length=2048, description="Authorised target URL.", examples=["http://127.0.0.1:8000"])
    headers: dict[str, Any] = Field(default_factory=dict, description="Observed response headers. Secrets should not be supplied.", examples=[{}])
    html_snippet: str = Field("", max_length=20000, description="Limited HTML snippet for script and generator hints. Full response bodies should not be supplied.", examples=[""])
    scripts: list[Any] = Field(default_factory=list, description="Observed script URLs or script metadata. External scripts are not fetched.", examples=[["/static/jquery-3.6.0.min.js"]])
    endpoint_results: list[dict[str, Any]] = Field(default_factory=list, description="Endpoint discovery candidates or discovered asset URLs.", examples=[[]])
    sbom_components: list[dict[str, Any]] = Field(default_factory=list, description="Local SBOM components already parsed by the caller.", examples=[[]])
    vuln_intel: dict[str, Any] = Field(default_factory=dict, description="Optional local vulnerability-intelligence metadata. No external registries are queried.", examples=[{}])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "target": "http://127.0.0.1:8000",
                    "headers": {"Server": "nginx/1.24.0"},
                    "html_snippet": "<script src=\"/static/jquery-3.6.0.min.js\"></script>",
                    "scripts": ["/static/jquery-3.6.0.min.js"],
                    "endpoint_results": [{"url": "http://127.0.0.1:8000/package.json"}],
                    "sbom_components": [],
                    "vuln_intel": {},
                }
            ]
        },
    )


class A08AssessmentRequest(StrictApiModel):
    """Build A08 Software or Data Integrity Failures indicator evidence from supplied safe metadata."""

    target: str = Field("", max_length=2048, description="Authorised target URL.", examples=["http://127.0.0.1:8000"])
    endpoint_results: list[dict[str, Any]] = Field(default_factory=list, description="Endpoint discovery candidates. Endpoints are not called.", examples=[[]])
    parameter_results: list[dict[str, Any]] = Field(default_factory=list, description="Parameter intelligence candidates. Values are not required.", examples=[[]])
    forms: list[dict[str, Any]] = Field(default_factory=list, description="Form metadata from safe discovery. Forms are not submitted.", examples=[[]])
    scripts: list[Any] = Field(default_factory=list, description="Observed script URLs or metadata. External scripts are not fetched.", examples=[[]])
    stylesheets: list[Any] = Field(default_factory=list, description="Observed stylesheet URLs or metadata. External stylesheets are not fetched.", examples=[[]])
    html_snippet: str = Field("", max_length=20000, description="Limited HTML snippet for SRI analysis. Full response bodies should not be supplied.", examples=[""])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "target": "http://127.0.0.1:8000",
                    "endpoint_results": [{"url": "http://127.0.0.1:8000/api/import"}],
                    "parameter_results": [{"url": "http://127.0.0.1:8000/webhook?signature", "parameter_name": "signature"}],
                    "forms": [{"action": "/upload", "enctype": "multipart/form-data", "fields": [{"name": "file", "type": "file"}]}],
                    "scripts": [{"src": "https://cdn.example.test/app.js"}],
                    "stylesheets": [],
                    "html_snippet": "",
                }
            ]
        },
    )


class A08ManualPlanRequest(StrictApiModel):
    """Generate an A08 manual validation plan and evidence template for an integrity indicator."""

    evidence_item: dict[str, Any] = Field(default_factory=dict, description="A08 candidate evidence item. Do not include secrets or sensitive response bodies.", examples=[{}])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "evidence_item": {
                        "title": "Webhook/callback integrity indicator",
                        "affected_url": "http://127.0.0.1:8000/webhook?signature",
                        "affected_parameter": "signature",
                        "workflow_type": "webhook_callback",
                        "manual_test_plan_id": "webhook_signature_review",
                    }
                }
            ]
        },
    )


class SBOMAnalyseRequest(StrictApiModel):
    """Analyse a supplied SBOM document body without accepting server-side paths."""

    sbom: dict[str, Any] = Field(default_factory=dict, description="CycloneDX or SPDX JSON SBOM document body.", examples=[{}])
    use_vuln_intel: bool = Field(False, description="Use supplied local vulnerability-intelligence metadata if provided.", examples=[False])
    vuln_intel: dict[str, Any] = Field(default_factory=dict, description="Optional local vulnerability-intelligence metadata supplied in the request body.", examples=[{}])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "sbom": {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.5",
                        "components": [{"type": "library", "name": "jquery", "version": "3.6.0"}],
                    },
                    "use_vuln_intel": False,
                    "vuln_intel": {},
                }
            ]
        },
    )


class A10ResponseObservation(StrictApiModel):
    url: str = Field(..., min_length=1, max_length=2048)
    status_code: int | None = Field(None, ge=100, le=599)
    body_snippet: str = Field("", max_length=20000)
    headers: dict[str, Any] = Field(default_factory=dict)
    source: str | None = Field(None, max_length=128)
    endpoint_category: str | None = Field(None, max_length=128)


class A10AssessmentRequest(StrictApiModel):
    """Build A10 error-handling evidence from supplied observed metadata."""

    target: str = Field("", max_length=2048, description="Authorised target URL.", examples=["http://127.0.0.1:8000"])
    responses: list[A10ResponseObservation] = Field(default_factory=list, description="Observed response snippets and status codes. Full bodies should not be supplied.")
    endpoint_results: list[dict[str, Any]] = Field(default_factory=list, description="Endpoint discovery candidates.", examples=[[]])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "target": "http://127.0.0.1:8000",
                    "responses": [{"url": "http://127.0.0.1:8000/error", "status_code": 500, "body_snippet": "Traceback ...", "headers": {}}],
                    "endpoint_results": [],
                }
            ]
        },
    )


class SafeValidationTarget(StrictApiModel):
    url: str = Field(..., min_length=1, max_length=2048, description="Authorised HTTP/HTTPS URL to validate.", examples=["http://127.0.0.1:8000/search?q=test"])
    candidate_type: str = Field("manual", max_length=64, description="Candidate type such as reflected_input, open_redirect, cors, directory_listing, default_file, or http_methods.", examples=["reflected_input"])
    parameter: str | None = Field(None, max_length=128, description="Optional query parameter for parameter-specific checks.", examples=["q"])
    source: str | None = Field(None, max_length=128, description="Local source label.", examples=["parameter_intelligence"])


class SafeValidationRequest(StrictApiModel):
    """Synchronous safe active validation request."""

    targets: list[SafeValidationTarget] = Field(default_factory=list, description="Validation targets.")
    scope_file: str | None = Field(None, max_length=512, description="Optional local Program Scope JSON file under data/programs or legacy data/bug_bounty.", examples=["data/programs/sample_program_scope.json"])
    enforce_scope: bool = Field(True, description="Skip out-of-scope targets before making requests.", examples=[True])
    checks: list[str] | None = Field(None, description="Optional safe check names to run.", examples=[["reflected_input_observation"]])
    request_delay: float = Field(1.0, ge=0, le=30, description="Seconds to wait between requests.", examples=[1.0])
    max_requests_per_minute: int = Field(20, ge=1, le=120, description="Maximum safe validation requests per minute.", examples=[20])
    timeout: float = Field(5.0, gt=0, le=30, description="Per-request timeout in seconds.", examples=[5.0])
    max_validation_requests: int = Field(100, ge=1, le=500, description="Maximum requests for this validation run.", examples=[100])
    safe_active_confirm: bool = Field(True, description="Required explicit acknowledgement that checks are safe and authorised.", examples=[True])


class ReplayPlanCreateRequest(StrictApiModel):
    """Create one Safe Authenticated Parameter Replay Planner record. No live request is made."""

    endpoint: dict[str, Any] | str = Field(..., description="Endpoint metadata or URL. Values are used for redacted planning only.", examples=["http://127.0.0.1:8000/users/123?user_id=123"])
    parameter: dict[str, Any] | str = Field(..., description="Parameter metadata or parameter name. Parameter values are not required.", examples=["user_id"])
    intent: str = Field("", max_length=128, description="Optional replay_intent override.", examples=["object_ownership_review"])
    role: dict[str, Any] | str | None = Field(None, description="Safe role label or Role Profile metadata without credentials.", examples=["standard_user"])


class ReplayPlanGenerateRequest(StrictApiModel):
    """Generate Replay Plans from local/supplied parameter and endpoint metadata only."""

    parameter_results: list[dict[str, Any]] = Field(default_factory=list, description="Parameter Intelligence candidates. Values are redacted or omitted.", examples=[[]])
    endpoint_results: list[dict[str, Any]] = Field(default_factory=list, description="Endpoint/crawl candidates. Endpoints are not called.", examples=[[]])
    a01_evidence: list[dict[str, Any]] = Field(default_factory=list, description="Optional A01 candidate evidence.", examples=[[]])
    a05_evidence: list[dict[str, Any]] = Field(default_factory=list, description="Optional A05 candidate evidence.", examples=[[]])
    a07_evidence: list[dict[str, Any]] = Field(default_factory=list, description="Optional A07 candidate evidence.", examples=[[]])
    roles: list[dict[str, Any]] = Field(default_factory=list, description="Safe Role Profiles without credentials.", examples=[[]])


class ReplayPlanObserveRequest(StrictApiModel):
    """Record manual Observed Behaviour for a Replay Plan."""

    replay_plan_id: str = Field(..., min_length=1, max_length=255)
    observed_access_result: str = Field(..., max_length=128)
    observed_status_code: int | None = Field(None, ge=100, le=599)
    observed_message_summary: str = Field("", max_length=2000)
    observed_parameter_effect: str = Field("", max_length=2000)
    evidence_summary: str = Field("", max_length=2000)
    evidence_file_path: str = Field("", max_length=1024)
    tester_notes: str = Field("", max_length=2000)


class ReplayPlanRetestRequest(StrictApiModel):
    """Record Retest Workflow status for a Replay Plan."""

    replay_plan_id: str = Field(..., min_length=1, max_length=255)
    retest_status: str = Field(..., max_length=64)
    original_observed_result: str = Field("", max_length=128)
    remediation_summary: str = Field("", max_length=2000)
    retest_steps: list[str] = Field(default_factory=list)
    retest_observed_result: str = Field("", max_length=128)
    retest_notes: str = Field("", max_length=2000)


class ReplayPlanReportTemplateRequest(StrictApiModel):
    """Generate report-ready text for a Replay Plan without confirming an issue automatically."""

    plan: dict[str, Any] = Field(default_factory=dict)
    observation: dict[str, Any] | None = Field(None)
    retest: dict[str, Any] | None = Field(None)


class SubmissionCreateRequest(StrictApiModel):
    """Create a local submission tracking record. Does not submit externally."""

    report_id: str | None = Field(None, max_length=255)
    evidence_ids: list[str] = Field(default_factory=list)
    finding_title: str | None = Field(None, max_length=500)
    program_name: str | None = Field(None, max_length=255)
    platform: str | None = Field("manual", max_length=100)
    submission_url: str | None = Field(None, max_length=1000)
    external_reference: str | None = Field(None, max_length=255)
    status: str = Field("draft", max_length=50)
    severity_submitted: str | None = Field(None, max_length=50)
    notes: str | None = Field(None, max_length=2000)


class SubmissionUpdateRequest(StrictApiModel):
    report_id: str | None = Field(None, max_length=255)
    evidence_ids: list[str] | None = Field(None)
    finding_title: str | None = Field(None, max_length=500)
    program_name: str | None = Field(None, max_length=255)
    platform: str | None = Field(None, max_length=100)
    submission_url: str | None = Field(None, max_length=1000)
    external_reference: str | None = Field(None, max_length=255)
    status: str | None = Field(None, max_length=50)
    severity_submitted: str | None = Field(None, max_length=50)
    severity_accepted: str | None = Field(None, max_length=50)
    duplicate_of: str | None = Field(None, max_length=255)
    bounty_amount: str | None = Field(None, max_length=50)
    bounty_currency: str | None = Field(None, max_length=10)
    next_follow_up_date: str | None = Field(None, max_length=64)
    notes: str | None = Field(None, max_length=2000)


class SubmissionStatusRequest(StrictApiModel):
    status: str = Field(..., max_length=50)
    note: str | None = Field(None, max_length=2000)


class SubmissionNoteRequest(StrictApiModel):
    note: str = Field(..., min_length=1, max_length=2000)


class RetestCreateRequest(StrictApiModel):
    submission_id: str = Field(..., min_length=1, max_length=255)
    report_id: str | None = Field(None, max_length=255)
    target: str | None = Field(None, max_length=255)
    affected_url: str | None = Field(None, max_length=1000)
    status: str = Field("retest_required", max_length=50)
    retest_result: str | None = Field(None, max_length=100)
    evidence_id: str | None = Field(None, max_length=255)
    notes: str | None = Field(None, max_length=2000)


class RetestUpdateRequest(StrictApiModel):
    report_id: str | None = Field(None, max_length=255)
    target: str | None = Field(None, max_length=255)
    affected_url: str | None = Field(None, max_length=1000)
    status: str | None = Field(None, max_length=50)
    retest_result: str | None = Field(None, max_length=100)
    evidence_id: str | None = Field(None, max_length=255)
    notes: str | None = Field(None, max_length=2000)


class DuplicateFingerprintRequest(StrictApiModel):
    """Create a stable local fingerprint without storing sensitive values."""

    url: str | None = Field(None, max_length=2048, description="URL to normalise for fingerprinting.", examples=["http://127.0.0.1:8000/account?id=123"])
    target: str | None = Field(None, max_length=2048, description="Optional target or host label.", examples=["127.0.0.1"])
    host: str | None = Field(None, max_length=255)
    path: str | None = Field(None, max_length=2048)
    title: str | None = Field(None, max_length=500)
    issue_type: str = Field(..., min_length=1, max_length=255, description="Candidate issue type, such as idor_candidate.")
    parameter_names: list[str] = Field(default_factory=list, description="Parameter names only. Values are not accepted.")
    parameter: str | None = Field(None, max_length=128, description="Optional single parameter name alias.")
    source: str | None = Field(None, max_length=255)
    owasp_category: str | None = Field(None, max_length=50)
    cve: str | None = Field(None, max_length=64)
    service: str | None = Field(None, max_length=100)
    port: int | None = Field(None, ge=1, le=65535)
    method: str | None = Field(None, max_length=16)
    item_type: str | None = Field("candidate", max_length=64)
    item_id: str | None = Field(None, max_length=255)
    store: bool = Field(False, description="Store the fingerprint locally.")

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "url": "http://127.0.0.1:8000/account?id=123",
                    "issue_type": "idor_candidate",
                    "parameter_names": ["id"],
                    "source": "endpoint_discovery",
                }
            ]
        },
    )


class DuplicateCheckRequest(DuplicateFingerprintRequest):
    """Create a fingerprint and check it against local duplicate metadata."""

    store: bool = Field(True, description="Duplicate checks store metadata locally for future comparisons.")


class ErrorResponse(StrictApiModel):
    error: str | None = Field(None, description="Short safe error category.", examples=["Request failed."])
    detail: str | None = Field(None, description="User-facing safe error detail without tracebacks or secrets.", examples=["Invalid or missing API key."])

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"examples": [{"detail": "Invalid or missing API key."}]},
    )
