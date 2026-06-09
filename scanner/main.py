"""Command-line entry point for VulScan."""

import sys
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from scanner import __version__
from scanner.audit_profiles import (
    AuditProfileError,
    DEFAULT_AUDIT_PROFILE,
    get_audit_profile,
)
from scanner.api_runner import run_api_server
from scanner.api_security import API_KEY_ENV_VAR, LOCAL_DEVELOPMENT_WARNING, get_configured_api_key
from scanner.auth_context import build_auth_context
from scanner.authenticated_crawler import AUTHENTICATED_CRAWL_REPORTS_DIR, authenticated_crawl
from scanner.authenticated_scope import classify_auth_boundary, classify_auth_required_endpoints
from scanner.session_profiles import SessionProfileError, ensure_auth_profile_dirs, list_session_profiles, load_session_profile, validate_session_profile
from scanner.access_control_matrix import infer_action_from_endpoint, save_role_mapping_reports
from scanner.permission_matrix import PermissionMatrixError, load_permission_matrix, permission_matrix_summary
from scanner.role_mapping_assistant import build_manual_plan, build_role_mapping_from_files
from scanner.role_profiles import RoleProfileError, find_role, load_role_profiles, role_profiles_summary
from scanner.api_bug_bounty import check_scope as api_check_scope, list_scope_files as api_list_scope_files
from scanner.assets import get_asset_services, get_assets
from scanner.asset_criticality import (
    DEFAULT_ASSET_CRITICALITY_PATH,
    disabled_asset_context,
    load_asset_criticality_context,
    resolve_asset_criticality,
)
from scanner.bug_bounty_scope import (
    BugBountyScopeError,
    build_bug_bounty_scope_summary,
    build_scope_applied_finding,
    get_scope_decision,
    load_bug_bounty_scope,
)
from scanner.bug_bounty_recon import (
    RECON_REPORTS_DIR,
    BugBountyReconError,
    load_recon_targets,
    run_bug_bounty_recon,
)
from scanner.bug_intelligence_metrics import (
    MetricsDateRangeError,
    build_bug_intelligence_metrics,
    export_metrics,
)
from scanner.endpoint_discovery import (
    ENDPOINT_REPORTS_DIR,
    EndpointDiscoveryError,
    load_url_list,
    run_endpoint_discovery,
)
from scanner.finding import assign_sequential_finding_ids, create_finding, create_port_exposure_findings
from scanner.owasp_mapping import (
    OWASPMappingError,
    attach_owasp_metadata,
    build_owasp_summary,
    load_owasp_mapping,
)
from scanner.owasp_assessment import attach_owasp_assessment
from scanner.owasp_report_builder import save_markdown_report
from scanner.owasp_a01_access_control import A01RulesError, attach_a01_access_control
from scanner.owasp_a03_supply_chain import A03RulesError, analyse_sbom_file, attach_a03_supply_chain
from scanner.owasp_a08_integrity import A08RulesError, attach_a08_integrity
from scanner.owasp_a05_injection import A05RulesError, attach_a05_injection
from scanner.owasp_a04_crypto import A04RulesError, attach_a04_crypto
from scanner.owasp_a07_authentication import A07RulesError, attach_a07_authentication
from scanner.owasp_a10_error_handling import A10RulesError, attach_a10_error_handling
from scanner.owasp_rules import OWASPAssessmentRulesError
from scanner.safe_active_validation import (
    VALIDATION_REPORTS_DIR,
    SafeActiveValidationError,
    load_validation_targets,
    run_safe_active_validation,
)
from scanner.submission_tracker import (
    SubmissionTrackerError,
    add_submission_note,
    create_retest,
    create_submission,
    get_retest,
    get_submission,
    get_submission_summary,
    get_submission_timeline,
    list_retests,
    list_submissions,
    update_payment,
    update_retest,
    update_submission_status,
)
from scanner.cve_feed import DEFAULT_CVE_FEED_PATH, CveFeedError, load_cve_feed
from scanner.epss_importer import DEFAULT_EPSS_PATH
from scanner.exploit_metadata import DEFAULT_EXPLOIT_METADATA_PATH
from scanner.database import database_exists, get_missing_required_tables
from scanner.diff import compare_latest_two_scans
from scanner.duplicate_detection import (
    check_duplicate,
    duplicate_summary,
    fingerprint_item,
    get_duplicate_group,
    list_duplicate_groups,
    rebuild_from_submissions,
)
from scanner.evidence import redact_nested
from scanner.exporter import (
    export_assets,
    export_findings,
    export_history,
    export_prioritisation,
    export_remediation,
)
from scanner.history import (
    get_database_path,
    get_latest_scan_finding_summaries,
    get_latest_scan_for_prioritisation_trends,
    get_scan_history,
    save_scan_result,
)
from scanner.http_audit import audit_http_services
from scanner.port_scan import PortScanError, scan_tcp_ports
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report
from scanner.prioritisation import build_prioritisation
from scanner.prioritisation_report import (
    build_dashboard_finding,
    build_fix_first_dashboard,
    disabled_fix_first_dashboard,
)
from scanner.prioritisation_trends import (
    build_finding_stable_key,
    build_prioritisation_trends,
    build_trend_finding,
    disabled_prioritisation_trends,
    unavailable_prioritisation_trends,
)
from scanner.remediation import (
    enrich_findings_with_remediation,
    get_remediation_list,
    get_remediation_summary,
    update_remediation_status,
)
from scanner.software_inventory import build_software_inventory
from scanner.sbom_import import SBOMImportError
from scanner.ssh_audit import (
    SshAuditConfigurationError,
    audit_ssh_host,
    validate_ssh_audit_options,
)
from scanner.tls_audit import audit_tls_services
from scanner.web_crawler import DEFAULT_USER_AGENT, crawl_web
from scanner.web_cookie_audit import audit_web_cookies
from scanner.web_form_audit import audit_web_forms
from scanner.web_header_audit import audit_web_headers
from scanner.web_passive_summary import (
    build_web_passive_summary,
    build_web_passive_summary_findings,
)
from scanner.web_rate_limit import (
    WebRateLimitConfigurationError,
    build_politeness_findings,
    build_web_rate_limiter,
    validate_web_politeness_options,
)
from scanner.web_report_summary import (
    build_web_dast_sections,
    build_web_dast_summary,
    build_web_report_consolidation_finding,
)
from scanner.web_robots import (
    DEFAULT_ROBOTS_USER_AGENT,
    build_robots_findings,
    fetch_robots_policy,
)
from scanner.web_scope import build_scope_findings, build_web_scope
from scanner.web_sitemap import discover_sitemaps
from scanner.vuln_intel import (
    DEFAULT_RULES_PATH,
    VulnIntelRulesError,
    disabled_vulnerability_intelligence_summary,
    run_vulnerability_intelligence,
)
from scanner.windows_demo import DEMO_NOTICE, build_demo_scan_result, build_windows_demo_result
from scanner.windows_audit_profiles import (
    WindowsAuditProfileError,
    get_windows_audit_profile,
    resolve_windows_audit_profile,
)
from scanner.windows_audit import (
    WindowsAuditConfigurationError,
    audit_windows_host,
    validate_windows_audit_options,
)
from scanner.windows_result import (
    build_windows_audit_sections,
    build_windows_consolidated_summary,
)


app = typer.Typer(
    help="VulScan defensive vulnerability scanner.",
    no_args_is_help=True,
)
remediation_app = typer.Typer(help="Track remediation status for saved findings.")
export_app = typer.Typer(help="Export saved VulScan data.")
submission_app = typer.Typer(help="Track Security Finding Report submission workflow status.")
retest_app = typer.Typer(help="Track manual retest workflow status.")
duplicates_app = typer.Typer(help="Fingerprint findings and detect duplicate security findings.")
metrics_app = typer.Typer(help="Local Bug Intelligence metrics and personal performance dashboard data.")
scope_app = typer.Typer(help="Manage local Program Scope files.")
sbom_app = typer.Typer(help="Analyse local SBOM files and build A03 software supply chain evidence.")
auth_app = typer.Typer(help="Manage redacted Authenticated Web Assessment Session Profiles.")
roles_app = typer.Typer(help="Role and Permission Mapping planning commands.")
app.add_typer(remediation_app, name="remediation")
app.add_typer(export_app, name="export")
app.add_typer(submission_app, name="submission")
app.add_typer(retest_app, name="retest")
app.add_typer(duplicates_app, name="duplicates")
app.add_typer(metrics_app, name="metrics")
app.add_typer(scope_app, name="scope")
app.add_typer(sbom_app, name="sbom")
app.add_typer(auth_app, name="auth")
app.add_typer(roles_app, name="roles")
console = Console()


@app.callback()
def main() -> None:
    """Run VulScan commands."""


@app.command("api")
def api_command(
    host: Annotated[
        str,
        typer.Option(
            "--host",
            help="API bind host. Defaults to localhost only.",
        ),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option(
            "--port",
            min=1,
            max=65535,
            help="API bind port.",
        ),
    ] = 8088,
    reload: Annotated[
        bool,
        typer.Option(
            "--reload",
            help="Enable uvicorn reload for local development.",
        ),
    ] = False,
    require_api_key: Annotated[
        bool,
        typer.Option(
            "--require-api-key",
            help="Refuse to start unless VULSCAN_API_KEY is configured.",
        ),
    ] = False,
    allow_remote_api: Annotated[
        bool,
        typer.Option(
            "--allow-remote-api",
            help="Explicitly allow binding the API to a non-localhost interface.",
        ),
    ] = False,
) -> None:
    """Start the local VulScan API foundation."""
    normalised_host = host.strip().lower()
    if not normalised_host:
        console.print("[red]API host cannot be empty.[/red]")
        raise typer.Exit(code=1)
    if normalised_host not in {"127.0.0.1", "localhost"} and not allow_remote_api:
        console.print(
            "[red]The VulScan API binds to localhost only by default. Use --allow-remote-api only for explicitly authorised local-network testing.[/red]"
        )
        raise typer.Exit(code=1)
    if normalised_host not in {"127.0.0.1", "localhost"}:
        console.print(
            "[yellow]Remote API binding was explicitly enabled. Do not expose this development API publicly.[/yellow]"
        )
    configured_api_key = get_configured_api_key()
    if require_api_key and configured_api_key is None:
        console.print(
            f"[red]VulScan API key protection was required, but {API_KEY_ENV_VAR} is not set.[/red]"
        )
        console.print(
            f"[yellow]Set it for this PowerShell session with: $env:{API_KEY_ENV_VAR}=\"change-this-local-dev-key\"[/yellow]"
        )
        raise typer.Exit(code=1)
    if configured_api_key is None:
        console.print(f"[yellow]{LOCAL_DEVELOPMENT_WARNING}[/yellow]")
    else:
        console.print("[green]API key protection enabled via environment variable.[/green]")
    console.print(f"[bold]Starting VulScan API:[/bold] http://{host}:{port}")
    console.print("[yellow]Version 19.0 API is for local development only and does not expose credentialed scans.[/yellow]")
    run_api_server(host=host, port=port, reload=reload)


def _list_program_scope_files() -> list[Path]:
    paths: list[Path] = []
    seen: set[str] = set()
    for root in (Path("data") / "programs", Path("data") / "bug_bounty"):
        if not root.exists():
            continue
        for path in sorted(root.glob("*.json")):
            key = str(path.resolve())
            if path.is_file() and key not in seen:
                paths.append(path)
                seen.add(key)
    return paths


def _program_scope_command(alias_note: str | None = None) -> None:
    console.print(Panel.fit(f"VulScan version {__version__}", style="bold cyan"))
    if alias_note:
        console.print(f"[yellow]{alias_note}[/yellow]")
    table = Table(title="Program Scope Files")
    table.add_column("Program")
    table.add_column("Program ID")
    table.add_column("Scope File")
    for path in _list_program_scope_files():
        try:
            scope = load_bug_bounty_scope(path)
        except BugBountyScopeError:
            continue
        table.add_row(str(scope.get("program_name") or ""), str(scope.get("program_id") or ""), str(path))
    console.print(table)


def _warn_legacy_scope_alias(scope_file: str | None = None) -> None:
    if "--bug-bounty-scope" in sys.argv or (scope_file and "data/bug_bounty" in scope_file.replace("\\", "/")):
        console.print("[yellow]Alias retained for compatibility. Prefer --scope-file.[/yellow]")


@auth_app.command("profiles")
def auth_profiles() -> None:
    """List local redacted Session Profiles."""
    ensure_auth_profile_dirs()
    table = Table(title="Session Profiles")
    for column in ("Profile", "Target", "Auth Type", "Role", "Redaction", "Updated"):
        table.add_column(column)
    for profile in list_session_profiles():
        table.add_row(
            str(profile.get("profile_name") or ""),
            str(profile.get("target_base_url") or ""),
            str(profile.get("auth_type") or ""),
            str(profile.get("role_label") or ""),
            str(profile.get("redaction_status") or ""),
            str(profile.get("updated_at") or ""),
        )
    console.print(table)


@auth_app.command("show")
def auth_show(profile_file: Annotated[Path, typer.Option("--profile-file", help="Session Profile JSON under data/auth_profiles.")]) -> None:
    """Show a redacted Session Profile summary."""
    try:
        context = build_auth_context(load_session_profile(profile_file))
    except SessionProfileError as exc:
        console.print(f"[red]Session Profile error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    _print_auth_context(context)


@auth_app.command("validate")
def auth_validate(profile_file: Annotated[Path, typer.Option("--profile-file", help="Session Profile JSON under data/auth_profiles.")]) -> None:
    """Validate a Session Profile without printing raw auth material."""
    try:
        validation = validate_session_profile(load_session_profile(profile_file))
    except SessionProfileError as exc:
        console.print(f"[red]Session Profile error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(f"[bold]Valid:[/bold] {validation.get('valid')}")
    for warning in validation.get("warnings") or []:
        console.print(f"[yellow]Warning:[/yellow] {warning}")
    for error in validation.get("errors") or []:
        console.print(f"[red]Error:[/red] {error}")
    _print_auth_profile_summary(validation.get("session_profile") or {})
    if not validation.get("valid"):
        raise typer.Exit(code=1)


@auth_app.command("check-url")
def auth_check_url(
    profile_file: Annotated[Path, typer.Option("--profile-file", help="Session Profile JSON under data/auth_profiles.")],
    url: Annotated[str, typer.Option("--url", help="URL to check against the Authenticated Scope.")],
) -> None:
    """Check whether a URL is inside the Authenticated Scope boundary."""
    try:
        result = classify_auth_boundary(url, load_session_profile(profile_file))
    except SessionProfileError as exc:
        console.print(f"[red]Session Profile error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    table = Table(title="Authenticated Scope Boundary")
    table.add_column("Field")
    table.add_column("Value")
    for key in ("url", "allowed_by_profile", "blocked_by_profile", "reason", "matched_rule", "auth_profile_id", "role_label"):
        table.add_row(key.replace("_", " ").title(), str(result.get(key, "")))
    console.print(table)


@roles_app.command("list")
def roles_list_command(
    roles_file: Annotated[Path, typer.Option("--roles-file", help="Role Profile JSON file under data/roles.")] = Path("data") / "roles" / "sample_roles.json",
) -> None:
    """List safe Role Profiles."""
    try:
        roles = load_role_profiles(roles_file)
    except RoleProfileError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    summary = role_profiles_summary(roles)
    table = Table(title="Role Profiles")
    table.add_column("Role ID")
    table.add_column("Role Label")
    table.add_column("User Type")
    table.add_column("Tenant")
    table.add_column("Access Level")
    for item in roles:
        table.add_row(str(item.get("role_id") or ""), str(item.get("role_label") or ""), str(item.get("user_type") or ""), str(item.get("tenant_label") or ""), str(item.get("expected_access_level") or ""))
    console.print(table)
    console.print(f"[bold]Role count:[/bold] {summary['role_count']}")
    console.print("[yellow]Authorised Test Accounts Only. No credentials are stored or displayed.[/yellow]")


@roles_app.command("show")
def roles_show_command(
    roles_file: Annotated[Path, typer.Option("--roles-file", help="Role Profile JSON file under data/roles.")] = Path("data") / "roles" / "sample_roles.json",
    role: Annotated[str, typer.Option("--role", help="Role ID, name, or label to show.")] = "",
) -> None:
    """Show a safe Role Profile summary."""
    try:
        selected = find_role(load_role_profiles(roles_file), role)
    except RoleProfileError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    table = Table(title=f"Role Profile: {selected.get('role_label')}")
    table.add_column("Field")
    table.add_column("Value")
    for key in ("role_id", "role_name", "role_label", "user_type", "tenant_label", "linked_session_profile_name", "test_account_label", "expected_access_level", "notes"):
        table.add_row(key, _format_summary_list(selected.get(key)))
    table.add_row("allowed_actions", _format_summary_list(selected.get("allowed_actions")))
    table.add_row("disallowed_actions", _format_summary_list(selected.get("disallowed_actions")))
    table.add_row("sensitive_actions", _format_summary_list(selected.get("sensitive_actions")))
    console.print(table)


@roles_app.command("matrix")
def roles_matrix_command(
    matrix_file: Annotated[Path, typer.Option("--matrix-file", help="Permission Matrix JSON file under data/roles.")] = Path("data") / "roles" / "sample_permission_matrix.json",
) -> None:
    """Print Access-Control Matrix summary."""
    try:
        matrix = load_permission_matrix(matrix_file)
    except PermissionMatrixError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    summary = permission_matrix_summary(matrix)
    table = Table(title="Access-Control Matrix Summary")
    table.add_column("Metric")
    table.add_column("Value")
    for key in ("matrix_name", "target", "role_count", "action_count", "rule_count", "manual_validation_required_count", "destructive_action_count", "state_changing_action_count"):
        table.add_row(key, str(summary.get(key) or matrix.get(key) or 0))
    console.print(table)
    rules_table = Table(title="Role Action Rules")
    rules_table.add_column("Role")
    rules_table.add_column("Action")
    rules_table.add_column("Expected Permission")
    rules_table.add_column("Validation Status")
    for rule in matrix.get("role_action_rules") or []:
        rules_table.add_row(str(rule.get("role_id") or ""), str(rule.get("action_id") or ""), str(rule.get("expected_permission") or ""), str(rule.get("validation_status") or ""))
    console.print(rules_table)
    console.print("[yellow]Planning only. VulScan does not automatically test permissions.[/yellow]")


@roles_app.command("map-endpoints")
def roles_map_endpoints_command(
    roles_file: Annotated[Path, typer.Option("--roles-file", help="Role Profile JSON file under data/roles.")] = Path("data") / "roles" / "sample_roles.json",
    matrix_file: Annotated[Path, typer.Option("--matrix-file", help="Permission Matrix JSON file under data/roles.")] = Path("data") / "roles" / "sample_permission_matrix.json",
    endpoints_file: Annotated[Path, typer.Option("--endpoints-file", help="Local endpoints file to map.")] = Path("data") / "endpoints" / "sample_urls.txt",
    json_report: Annotated[bool, typer.Option("--json", help="Write JSON role mapping report.")] = False,
    html_report: Annotated[bool, typer.Option("--html", help="Write HTML role mapping report.")] = False,
) -> None:
    """Infer endpoint actions and build a Role Endpoint Matrix."""
    try:
        urls = load_url_list(endpoints_file)
        endpoints = [{"url": url, "normalised_url": url, "method": "GET"} for url in urls]
        package = build_role_mapping_from_files(str(roles_file), str(matrix_file), endpoints)
        json_path, html_path = save_role_mapping_reports(package, json_report=json_report, html_report=html_report)
    except (EndpointDiscoveryError, PermissionMatrixError, RoleProfileError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    summary = package.get("role_mapping_summary") or {}
    table = Table(title="Role Endpoint Matrix")
    table.add_column("Role")
    table.add_column("Endpoint")
    table.add_column("Action")
    table.add_column("Expected")
    table.add_column("Plan")
    for row in (package.get("role_endpoint_matrix") or [])[:25]:
        table.add_row(str(row.get("role_label") or ""), str(row.get("endpoint") or ""), str(row.get("inferred_action") or ""), str(row.get("expected_permission") or ""), str(row.get("manual_plan_id") or ""))
    console.print(table)
    console.print(f"[bold]Manual validation plans:[/bold] {summary.get('manual_validation_plan_count', 0)}")
    if json_path:
        console.print(f"[bold]JSON report:[/bold] {json_path}")
    if html_path:
        console.print(f"[bold]HTML report:[/bold] {html_path}")
    console.print("[yellow]No requests were made. Endpoint-to-action mapping is inference only.[/yellow]")


@roles_app.command("plan")
def roles_plan_command(
    role: Annotated[str, typer.Option("--role", help="Role ID, name, or label.")] = "standard_user",
    endpoint: Annotated[str, typer.Option("--endpoint", help="Endpoint to plan manual validation for.")] = "",
    expected: Annotated[str, typer.Option("--expected", help="Expected permission: allowed, denied, conditional, or unknown.")] = "unknown",
    roles_file: Annotated[Path, typer.Option("--roles-file", help="Role Profile JSON file under data/roles.")] = Path("data") / "roles" / "sample_roles.json",
) -> None:
    """Build a safe manual validation plan for one role and endpoint."""
    try:
        selected = find_role(load_role_profiles(roles_file), role)
        result = build_manual_plan(selected, endpoint, expected)
    except RoleProfileError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    inferred = result["inferred_action"]
    plan = result["manual_validation_plan"]
    console.print(Panel(f"{plan['role_label']} -> {plan['endpoint']}", title="Manual Validation Required"))
    table = Table(title="Endpoint Action Inference")
    table.add_column("Field")
    table.add_column("Value")
    for key in ("inferred_action", "sensitivity", "state_changing", "destructive", "inference_reason"):
        table.add_row(key, str(inferred.get(key) or ""))
    console.print(table)
    plan_table = Table(title="Manual Validation Plan")
    plan_table.add_column("Field")
    plan_table.add_column("Value")
    for key in ("plan_id", "expected_permission", "expected_secure_result", "risk_if_failed", "status"):
        plan_table.add_row(key, str(plan.get(key) or ""))
    plan_table.add_row("safe_manual_steps", "\n".join(plan.get("safe_manual_steps") or []))
    plan_table.add_row("evidence_to_collect", "\n".join(plan.get("evidence_to_collect") or []))
    plan_table.add_row("safety_notes", "\n".join(plan.get("safety_notes") or []))
    console.print(plan_table)


@app.command("authenticated-crawl")
def authenticated_crawl_command(
    url: Annotated[str, typer.Option("--url", help="Authenticated Crawl start URL.")],
    auth_profile: Annotated[Path, typer.Option("--auth-profile", help="Session Profile JSON under data/auth_profiles.")],
    scope_file: Annotated[Path | None, typer.Option("--scope-file", help="Optional Program Scope file. Reserved for future Authenticated Crawl scope integration.")] = None,
    enforce_scope: Annotated[bool, typer.Option("--enforce-scope/--no-enforce-scope", help="Keep Program Scope enforcement enabled when a scope file is supplied.")] = True,
    max_pages: Annotated[int, typer.Option("--max-pages", min=1, max=200, help="Maximum pages to crawl.")] = 30,
    max_depth: Annotated[int, typer.Option("--max-depth", min=0, max=10, help="Maximum crawl depth.")] = 2,
    request_delay: Annotated[float, typer.Option("--request-delay", min=0, max=30, help="Seconds between GET requests.")] = 1.0,
    timeout: Annotated[float, typer.Option("--timeout", min=1, max=30, help="Per-request timeout.")] = 5.0,
    max_redirects: Annotated[int, typer.Option("--max-redirects", min=0, max=10, help="Maximum redirect entries retained in results.")] = 5,
    same_origin_only: Annotated[bool, typer.Option("--same-origin-only/--allow-cross-origin", help="Keep Authenticated Crawl to the start URL origin.")] = True,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Validate boundary and reporting without sending HTTP requests.")] = False,
    json_report: Annotated[bool, typer.Option("--json", help="Write a redacted JSON Authenticated Crawl report.")] = False,
    html_report: Annotated[bool, typer.Option("--html", help="Write a redacted HTML Authenticated Crawl report.")] = False,
) -> None:
    """Run a safe GET-only Authenticated Crawl with Session Boundary Controls."""
    console.print(Panel(f"VulScan version {__version__}"))
    console.print("[yellow]Authenticated Crawl safety:[/yellow] authorised testing only; GET-only; no form submission; logout/delete/payment/destructive paths are blocked.")
    scan_start_time = datetime.now()
    try:
        profile = load_session_profile(auth_profile)
        validation = validate_session_profile(profile)
        if not validation.get("valid"):
            for error in validation.get("errors") or []:
                console.print(f"[red]Session Profile error:[/red] {error}")
            raise typer.Exit(code=1)
        for warning in validation.get("warnings") or []:
            console.print(f"[yellow]Warning:[/yellow] {warning}")
        _print_auth_profile_summary(validation.get("session_profile") or {})
        if scope_file and enforce_scope:
            console.print("[yellow]Scope note:[/yellow] Program Scope file accepted; Authenticated Crawl 21.1 still enforces Session Boundary Controls before requests.")
        result = authenticated_crawl(
            url,
            profile,
            {
                "max_pages": max_pages,
                "max_depth": max_depth,
                "request_delay": request_delay,
                "timeout": timeout,
                "max_redirects": max_redirects,
                "same_origin_only": same_origin_only,
                "dry_run": dry_run,
                "scope_file": str(scope_file) if scope_file else None,
                "enforce_scope": enforce_scope,
            },
        )
    except SessionProfileError as exc:
        console.print(f"[red]Session Profile error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except ValueError as exc:
        console.print(f"[red]Authenticated Crawl error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    _print_authenticated_crawl_summary(result.get("authenticated_crawl_summary") or {})
    _print_authenticated_crawl_rows(result.get("authenticated_crawl_results") or [], result.get("authenticated_crawl_skipped") or [], result.get("authenticated_boundary_events") or [])
    scan_end_time = datetime.now()
    scan_result = {
        "host": url,
        "resolved_ip": "",
        "scan_mode": "authenticated_crawl",
        "duration_seconds": round((scan_end_time - scan_start_time).total_seconds(), 3),
        "open_ports": [],
        "findings": [],
        **result,
    }
    if json_report:
        report_path = save_json_report(scan_result=scan_result, scanner_name="VulScan", scanner_version=__version__, scan_start_time=scan_start_time, scan_end_time=scan_end_time, reports_dir=AUTHENTICATED_CRAWL_REPORTS_DIR)
        console.print(f"[green]JSON authenticated crawl report saved:[/green] {report_path}")
    if html_report:
        report_path = save_html_report(scan_result=scan_result, scanner_name="VulScan", scanner_version=__version__, scan_start_time=scan_start_time, scan_end_time=scan_end_time, reports_dir=AUTHENTICATED_CRAWL_REPORTS_DIR)
        console.print(f"[green]HTML authenticated crawl report saved:[/green] {report_path}")


@sbom_app.command("analyse")
def sbom_analyse(
    sbom_file: Annotated[
        Path,
        typer.Option("--sbom-file", help="Path to a local CycloneDX or SPDX JSON SBOM file."),
    ],
    a03_checks: Annotated[
        bool,
        typer.Option("--a03-checks", help="Build A03 Software Supply Chain evidence from the local SBOM."),
    ] = False,
    owasp_assess: Annotated[
        bool,
        typer.Option("--owasp-assess", help="Build OWASP Assessment Engine category results from SBOM/A03 evidence."),
    ] = False,
    json_report: Annotated[
        bool,
        typer.Option("--json", help="Save SBOM analysis results to a JSON report."),
    ] = False,
    html_report: Annotated[
        bool,
        typer.Option("--html", help="Save SBOM analysis results to an HTML report."),
    ] = False,
    use_cve_feed: Annotated[
        bool,
        typer.Option("--use-cve-feed", help="Enable local CVE feed enrichment for SBOM components."),
    ] = False,
    cve_feed: Annotated[
        Path,
        typer.Option("--cve-feed", help="Path to a local CVE-style JSON feed file."),
    ] = DEFAULT_CVE_FEED_PATH,
    epss_file: Annotated[
        Path | None,
        typer.Option("--epss-file", help="Accepted for command compatibility. EPSS values are read from local CVE feed metadata in this version."),
    ] = None,
    exploit_metadata_file: Annotated[
        Path | None,
        typer.Option("--exploit-metadata-file", help="Accepted for command compatibility. No exploit code is downloaded or executed."),
    ] = None,
    component_intel: Annotated[
        Path | None,
        typer.Option("--component-intel", help="Reserved for future local component intelligence files. External registry fetching is not performed."),
    ] = None,
) -> None:
    """Analyse a local SBOM and generate A03 software supply chain evidence."""
    console.print(Panel.fit(f"VulScan version {__version__}", style="bold cyan"))
    console.print("[bold]SBOM Analysis[/bold]")
    console.print("[yellow]A03 safety:[/yellow] local SBOM only; no package registry fetching, dependency confusion testing, or exploit code use.")
    scan_start_time = datetime.now().astimezone()
    try:
        payload = analyse_sbom_file(sbom_file, vuln_intel=_build_a03_vuln_intel(use_cve_feed, cve_feed))
    except (A03RulesError, CveFeedError, SBOMImportError) as exc:
        console.print(f"[red]SBOM analysis error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    scan_end_time = datetime.now().astimezone()
    if not a03_checks:
        console.print("[yellow]--a03-checks was not supplied; A03 evidence was still generated from the local SBOM for report consistency.[/yellow]")
    scan_result = {
        "host": "sbom-analysis",
        "target": str(sbom_file),
        "resolved_ip": "",
        "scan_mode": "sbom-analysis",
        "duration_seconds": round((scan_end_time - scan_start_time).total_seconds(), 3),
        "open_ports": [],
        "findings": list(payload.get("findings", [])),
        "sbom_components": payload.get("sbom_components", []),
        "a03_supply_chain_summary": payload.get("a03_supply_chain_summary", {}),
        "a03_supply_chain_evidence": payload.get("a03_supply_chain_evidence", []),
        "demo_mode": False,
        "demo_notice": "",
        "scan_start_time": scan_start_time.isoformat(timespec="seconds"),
        "scan_end_time": scan_end_time.isoformat(timespec="seconds"),
    }
    _print_a03_supply_chain_summary(scan_result.get("a03_supply_chain_summary", {}))
    if owasp_assess:
        try:
            attach_owasp_assessment(scan_result)
        except OWASPAssessmentRulesError as exc:
            console.print(f"[red]OWASP assessment error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_owasp_assessment_summary(scan_result.get("owasp_assessment_summary", {}), scan_result.get("owasp_category_results", []))
    _print_findings(scan_result["findings"])
    if epss_file:
        console.print("[yellow]EPSS note:[/yellow] Version 20.7 SBOM analysis reads EPSS values only from local vulnerability-intelligence metadata.")
    if exploit_metadata_file:
        console.print("[yellow]Exploit metadata note:[/yellow] No exploit code is downloaded or executed.")
    if component_intel:
        console.print("[yellow]Component intelligence note:[/yellow] --component-intel is reserved for future local-only enrichment.")
    if json_report:
        report_path = save_json_report(
            scan_result=scan_result,
            scanner_name="VulScan",
            scanner_version=__version__,
            scan_start_time=scan_start_time,
            scan_end_time=scan_end_time,
            reports_dir=Path("reports") / "owasp" / "a03",
        )
        console.print(f"[bold]JSON SBOM report saved:[/bold] {report_path}")
    if html_report:
        report_path = save_html_report(
            scan_result=scan_result,
            scanner_name="VulScan",
            scanner_version=__version__,
            scan_start_time=scan_start_time,
            scan_end_time=scan_end_time,
            reports_dir=Path("reports") / "owasp" / "a03",
        )
        console.print(f"[bold]HTML SBOM report saved:[/bold] {report_path}")


@app.command("program-scope")
def program_scope() -> None:
    """List local program scope files."""
    _program_scope_command()


@scope_app.callback(invoke_without_command=True)
def scope_group(ctx: typer.Context) -> None:
    """Manage local Program Scope files."""
    if ctx.invoked_subcommand is None:
        _program_scope_command("Alias retained for compatibility. Prefer: scope list.")


@scope_app.command("list")
def scope_list() -> None:
    """List local Program Scope files."""
    _program_scope_command()


@scope_app.command("check")
def scope_check(
    target: Annotated[str, typer.Option("--target", help="Target, URL, domain, or IP to evaluate against Program Scope.")],
    scope_file: Annotated[str, typer.Option("--scope-file", "--bug-bounty-scope", help="Local Program Scope JSON file. Legacy --bug-bounty-scope is retained for compatibility.")],
) -> None:
    """Check whether a target is allowed by a local Program Scope file."""
    _warn_legacy_scope_alias(scope_file)
    try:
        decision = api_check_scope(target, scope_file)
    except BugBountyScopeError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    table = Table(title="Program Scope Decision")
    table.add_column("Field")
    table.add_column("Value")
    for key in ("target", "in_scope", "decision", "matched_rule", "reason"):
        table.add_row(key.replace("_", " ").title(), str(decision.get(key, "")))
    console.print(table)


def _security_report_command(alias_note: str | None = None) -> None:
    console.print(Panel.fit(f"VulScan version {__version__}", style="bold cyan"))
    if alias_note:
        console.print(f"[yellow]{alias_note}[/yellow]")
    reports_root = Path("reports")
    files = sorted(
        [path for path in reports_root.rglob("*") if path.is_file() and path.suffix.lower() in {".json", ".html"}],
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )[:25] if reports_root.exists() else []
    table = Table(title="Security Finding Reports")
    table.add_column("File")
    table.add_column("Type")
    for path in files:
        table.add_row(str(path), path.suffix.lower().lstrip("."))
    console.print(table)


@app.command("security-report")
def security_report(action: Annotated[str | None, typer.Argument(help="Optional action. Use 'list' to list local reports.")] = None) -> None:
    """List local Security Finding Reports."""
    if action and action != "list":
        console.print("[red]Unsupported security-report action. Use: security-report list[/red]")
        raise typer.Exit(code=1)
    _security_report_command()


@app.command("bug-report")
def bug_report_alias(action: Annotated[str | None, typer.Argument(help="Optional action. Use 'list' to list local reports.")] = None) -> None:
    """Alias for security-report."""
    if action and action != "list":
        console.print("[red]Unsupported bug-report action. Use: bug-report list[/red]")
        raise typer.Exit(code=1)
    _security_report_command("Alias retained for compatibility. Prefer security-report list.")


@app.command("evidence")
def evidence_reports(action: Annotated[str | None, typer.Argument(help="Optional action. Use 'list' to list local evidence and reports.")] = None) -> None:
    """List local evidence and Security Finding Reports."""
    if action and action != "list":
        console.print("[red]Unsupported evidence action. Use: evidence list[/red]")
        raise typer.Exit(code=1)
    _security_report_command("Evidence & Reports view for local Security Finding Reports.")


@submission_app.callback(invoke_without_command=True)
def submission_tracker(ctx: typer.Context) -> None:
    """Track Security Finding Report submissions locally."""
    if ctx.invoked_subcommand is None:
        console.print("[bold]Submission and Retest Tracking[/bold]")
        console.print("Tracking only. VulScan does not submit reports or modify targets.")
        console.print("[yellow]Do not store platform credentials or secrets in notes.[/yellow]")


@submission_app.command("create")
def submission_create(
    report_id: Annotated[str, typer.Option("--report-id", help="Local report ID or report reference.")],
    program_name: Annotated[str, typer.Option("--program-name", help="Program or client name.")],
    platform: Annotated[str, typer.Option("--platform", help="Tracking platform label such as manual.")],
    status: Annotated[str, typer.Option("--status", help="Initial submission status.")] = "draft",
    finding_title: Annotated[str | None, typer.Option("--finding-title", help="Finding or report title.")] = None,
    severity_submitted: Annotated[str | None, typer.Option("--severity-submitted", help="Submitted severity label.")] = None,
    note: Annotated[str | None, typer.Option("--note", help="Optional redacted local note.")] = None,
) -> None:
    """Create a local submission tracking record."""
    try:
        record = create_submission(
            report_id=report_id,
            program_name=program_name,
            platform=platform,
            status=status,
            finding_title=finding_title,
            severity_submitted=severity_submitted,
            notes=note,
        )
    except SubmissionTrackerError as exc:
        console.print(f"[red]Submission error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    _print_submission_record(record)


@submission_app.command("list")
def submission_list(status: Annotated[str | None, typer.Option("--status", help="Optional status filter.")] = None) -> None:
    """List local submission tracking records."""
    try:
        _print_submissions(list_submissions(status=status))
    except SubmissionTrackerError as exc:
        console.print(f"[red]Submission error:[/red] {exc}")
        raise typer.Exit(code=1) from exc


@submission_app.command("show")
def submission_show(submission_id: Annotated[str, typer.Option("--submission-id")]) -> None:
    """Show one local submission tracking record."""
    record = get_submission(submission_id)
    if record is None:
        console.print("[red]Submission record was not found.[/red]")
        raise typer.Exit(code=1)
    _print_submission_record(record)
    _print_submission_timeline(get_submission_timeline(submission_id))
    _print_retests(list_retests(submission_id=submission_id))


@submission_app.command("update-status")
def submission_update_status(
    submission_id: Annotated[str, typer.Option("--submission-id")],
    status: Annotated[str, typer.Option("--status")],
    note: Annotated[str | None, typer.Option("--note")] = None,
) -> None:
    """Update submission status and record a timeline event."""
    try:
        record = update_submission_status(submission_id, status, note=note)
    except SubmissionTrackerError as exc:
        console.print(f"[red]Submission error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    if record is None:
        console.print("[red]Submission record was not found.[/red]")
        raise typer.Exit(code=1)
    _print_submission_record(record)


@submission_app.command("add-note")
def submission_add_note(
    submission_id: Annotated[str, typer.Option("--submission-id")],
    note: Annotated[str, typer.Option("--note")],
) -> None:
    """Append a redacted local note to a submission."""
    try:
        record = add_submission_note(submission_id, note)
    except SubmissionTrackerError as exc:
        console.print(f"[red]Submission error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    if record is None:
        console.print("[red]Submission record was not found.[/red]")
        raise typer.Exit(code=1)
    _print_submission_record(record)


@submission_app.command("update-payment")
def submission_update_payment(
    submission_id: Annotated[str, typer.Option("--submission-id")],
    bounty_amount: Annotated[str | None, typer.Option("--bounty-amount")] = None,
    bounty_currency: Annotated[str | None, typer.Option("--bounty-currency")] = None,
    status: Annotated[str | None, typer.Option("--status")] = None,
) -> None:
    """Track local bounty/payment outcome details."""
    try:
        record = update_payment(submission_id, bounty_amount=bounty_amount, bounty_currency=bounty_currency, status=status)
    except SubmissionTrackerError as exc:
        console.print(f"[red]Submission error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    if record is None:
        console.print("[red]Submission record was not found.[/red]")
        raise typer.Exit(code=1)
    _print_submission_record(record)


@retest_app.command("create")
def retest_create(
    submission_id: Annotated[str, typer.Option("--submission-id")],
    status: Annotated[str, typer.Option("--status")] = "retest_required",
    note: Annotated[str | None, typer.Option("--note")] = None,
    report_id: Annotated[str | None, typer.Option("--report-id")] = None,
    target: Annotated[str | None, typer.Option("--target")] = None,
    affected_url: Annotated[str | None, typer.Option("--affected-url")] = None,
    evidence_id: Annotated[str | None, typer.Option("--evidence-id")] = None,
) -> None:
    """Create a local retest tracking record."""
    try:
        record = create_retest(submission_id=submission_id, status=status, notes=note, report_id=report_id, target=target, affected_url=affected_url, evidence_id=evidence_id)
    except SubmissionTrackerError as exc:
        console.print(f"[red]Retest error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    _print_retests([record])


@retest_app.command("update")
def retest_update(
    retest_id: Annotated[str, typer.Option("--retest-id")],
    status: Annotated[str | None, typer.Option("--status")] = None,
    result: Annotated[str | None, typer.Option("--result")] = None,
    note: Annotated[str | None, typer.Option("--note")] = None,
    evidence_id: Annotated[str | None, typer.Option("--evidence-id")] = None,
) -> None:
    """Update a local retest tracking record."""
    try:
        record = update_retest(retest_id, status=status, retest_result=result, notes=note, evidence_id=evidence_id)
    except SubmissionTrackerError as exc:
        console.print(f"[red]Retest error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    if record is None:
        console.print("[red]Retest record was not found.[/red]")
        raise typer.Exit(code=1)
    _print_retests([record])


@retest_app.command("list")
def retest_list(submission_id: Annotated[str | None, typer.Option("--submission-id")] = None) -> None:
    """List local retest tracking records."""
    _print_retests(list_retests(submission_id=submission_id))


@duplicates_app.callback(invoke_without_command=True)
def duplicate_detection(ctx: typer.Context) -> None:
    """Fingerprint findings and check duplicate indicators locally."""
    if ctx.invoked_subcommand is None:
        console.print("[bold]Finding Fingerprinting and Duplicate Detection[/bold]")
        console.print("Metadata-only duplicate checks. Parameter values and secrets are not stored.")


@duplicates_app.command("fingerprint")
def duplicates_fingerprint(
    url: Annotated[str | None, typer.Option("--url", help="URL to fingerprint. Query values are ignored.")] = None,
    issue_type: Annotated[str, typer.Option("--issue-type", help="Issue or candidate type.")] = "unknown",
    parameter: Annotated[str | None, typer.Option("--parameter", help="Parameter name only.")] = None,
    source: Annotated[str | None, typer.Option("--source", help="Optional local source label.")] = None,
    host: Annotated[str | None, typer.Option("--host", help="Optional host when no URL is available.")] = None,
    path: Annotated[str | None, typer.Option("--path", help="Optional path when no URL is available.")] = None,
) -> None:
    """Build a stable fingerprint from local metadata."""
    item = _duplicate_cli_item(url=url, issue_type=issue_type, parameter=parameter, source=source, host=host, path=path)
    fingerprint = fingerprint_item(item, item_type="candidate", store=False)
    _print_fingerprint(fingerprint)


@duplicates_app.command("check")
def duplicates_check(
    url: Annotated[str | None, typer.Option("--url", help="URL to check. Query values are ignored.")] = None,
    issue_type: Annotated[str, typer.Option("--issue-type", help="Issue or candidate type.")] = "unknown",
    parameter: Annotated[str | None, typer.Option("--parameter", help="Parameter name only.")] = None,
    source: Annotated[str | None, typer.Option("--source", help="Optional local source label.")] = None,
    host: Annotated[str | None, typer.Option("--host", help="Optional host when no URL is available.")] = None,
    path: Annotated[str | None, typer.Option("--path", help="Optional path when no URL is available.")] = None,
) -> None:
    """Check local duplicate metadata and store the fingerprint."""
    item = _duplicate_cli_item(url=url, issue_type=issue_type, parameter=parameter, source=source, host=host, path=path)
    result = check_duplicate(item, item_type="candidate", store=True)
    _print_fingerprint(result["fingerprint"])
    _print_duplicate_result(result["duplicate_result"])


@duplicates_app.command("groups")
def duplicates_groups() -> None:
    """List local duplicate groups."""
    _print_duplicate_summary(duplicate_summary())
    _print_duplicate_groups(list_duplicate_groups())


@duplicates_app.command("show")
def duplicates_show(group_id: Annotated[str, typer.Option("--group-id", help="Duplicate group ID.")]) -> None:
    """Show one duplicate group and its members."""
    group = get_duplicate_group(group_id)
    if group is None:
        console.print("[red]Duplicate group was not found.[/red]")
        raise typer.Exit(code=1)
    _print_duplicate_groups([group])
    _print_duplicate_group_members(group.get("members") or [])


@duplicates_app.command("rebuild")
def duplicates_rebuild() -> None:
    """Rebuild duplicate metadata from stored submission records where possible."""
    summary = rebuild_from_submissions()
    console.print(f"[green]Rebuilt fingerprints:[/green] {summary.get('fingerprints_created', 0)}")


@metrics_app.command("summary")
def metrics_summary(
    range_name: Annotated[str, typer.Option("--range", help="Date range: all-time, last-7-days, last-30-days, last-90-days, this-year, custom.")] = "all-time",
    start_date: Annotated[str | None, typer.Option("--start-date", help="Custom range start date, YYYY-MM-DD or ISO datetime.")] = None,
    end_date: Annotated[str | None, typer.Option("--end-date", help="Custom range end date, YYYY-MM-DD or ISO datetime.")] = None,
    program_name: Annotated[str | None, typer.Option("--program-name", help="Optional Program Scope name filter.")] = None,
) -> None:
    """Show local Bug Intelligence Metrics summary."""
    metrics = _load_metrics_or_exit(range_name, start_date, end_date, program_name)["bug_intelligence_metrics"]
    _print_metrics_summary(metrics)


@metrics_app.command("programs")
def metrics_programs(
    range_name: Annotated[str, typer.Option("--range", help="Date range filter.")] = "all-time",
    start_date: Annotated[str | None, typer.Option("--start-date")] = None,
    end_date: Annotated[str | None, typer.Option("--end-date")] = None,
    program_name: Annotated[str | None, typer.Option("--program-name")] = None,
) -> None:
    """Show local Program Performance metrics."""
    metrics = _load_metrics_or_exit(range_name, start_date, end_date, program_name)["bug_intelligence_metrics"]
    table = Table(title="Program Performance")
    for column in ("Program", "Submissions", "Accepted", "Duplicates", "Acceptance Rate", "Bounty", "Last Activity"):
        table.add_column(column)
    for row in metrics["top_programs"]:
        table.add_row(
            str(row.get("program_name") or ""),
            str(row.get("total_submissions") or 0),
            str(row.get("accepted") or 0),
            str(row.get("duplicates") or 0),
            f"{row.get('acceptance_rate', 0)}%",
            _format_currency_map(row.get("total_bounty_by_currency") or {}),
            str(row.get("last_activity") or ""),
        )
    console.print(table)


@metrics_app.command("classes")
def metrics_classes(
    range_name: Annotated[str, typer.Option("--range", help="Date range filter.")] = "all-time",
    start_date: Annotated[str | None, typer.Option("--start-date")] = None,
    end_date: Annotated[str | None, typer.Option("--end-date")] = None,
    program_name: Annotated[str | None, typer.Option("--program-name")] = None,
) -> None:
    """Show local vulnerability class metrics."""
    metrics = _load_metrics_or_exit(range_name, start_date, end_date, program_name)["bug_intelligence_metrics"]
    table = Table(title="Vulnerability Class Metrics")
    for column in ("Class", "Count", "Accepted", "Duplicates", "Acceptance Rate", "Avg Severity"):
        table.add_column(column)
    for row in metrics["top_vulnerability_classes"]:
        table.add_row(
            str(row.get("class_name") or ""),
            str(row.get("count") or 0),
            str(row.get("accepted_count") or 0),
            str(row.get("duplicate_count") or 0),
            f"{row.get('acceptance_rate', 0)}%",
            str(row.get("average_severity") or 0),
        )
    console.print(table)


@metrics_app.command("export")
def metrics_export(
    format_name: Annotated[str, typer.Option("--format", help="Export format: json or csv.")] = "json",
    range_name: Annotated[str, typer.Option("--range", help="Date range filter.")] = "all-time",
    start_date: Annotated[str | None, typer.Option("--start-date")] = None,
    end_date: Annotated[str | None, typer.Option("--end-date")] = None,
    program_name: Annotated[str | None, typer.Option("--program-name")] = None,
) -> None:
    """Export local Bug Intelligence Metrics."""
    try:
        console.print(
            export_metrics(
                format_name=format_name,
                range_name=range_name,
                start_date=start_date,
                end_date=end_date,
                program_name=program_name,
            )
        )
    except (MetricsDateRangeError, ValueError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Option(
            "--target",
            "-t",
            help="Authorised target to scan.",
        ),
    ],
    mode: Annotated[
        str,
        typer.Option(
            "--mode",
            "-m",
            help="Defensive scan mode.",
        ),
    ] = "safe",
    json_report: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Save scan results to a JSON report in the reports folder.",
        ),
    ] = False,
    html_report: Annotated[
        bool,
        typer.Option(
            "--html",
            help="Save scan results to an HTML report in the reports folder.",
        ),
    ] = False,
    http_audit: Annotated[
        bool,
        typer.Option(
            "--http-audit",
            help="Run safe HTTP security header checks against detected web services.",
        ),
    ] = False,
    tls_audit: Annotated[
        bool,
        typer.Option(
            "--tls-audit",
            help="Run passive TLS certificate checks against detected HTTPS services.",
        ),
    ] = False,
    windows_audit: Annotated[
        bool,
        typer.Option(
            "--windows-audit",
            help="Run safe Windows SMB/WinRM/RDP audit foundation checks.",
        ),
    ] = False,
    windows_demo: Annotated[
        bool,
        typer.Option(
            "--windows-demo",
            help="Generate fake Windows audit demo data only. No network connection is made.",
        ),
    ] = False,
    windows_user: Annotated[
        str | None,
        typer.Option(
            "--windows-user",
            help="Username for Windows WinRM authentication validation. Password is not stored or printed.",
        ),
    ] = None,
    windows_password: Annotated[
        str | None,
        typer.Option(
            "--windows-password",
            help="Password for Windows WinRM authentication validation. Not stored or printed.",
        ),
    ] = None,
    windows_domain: Annotated[
        str | None,
        typer.Option(
            "--windows-domain",
            help="Optional Windows domain or workgroup name.",
        ),
    ] = None,
    windows_auth_method: Annotated[
        str,
        typer.Option(
            "--windows-auth-method",
            help="Windows auth method: none, smb foundation metadata, or winrm authentication validation.",
        ),
    ] = "none",
    windows_audit_profile: Annotated[
        str | None,
        typer.Option(
            "--windows-audit-profile",
            help="Windows audit profile when --windows-audit is used: foundation, standard, or detailed. Default: standard.",
        ),
    ] = None,
    windows_host_info: Annotated[
        bool,
        typer.Option(
            "--windows-host-info",
            help="Collect basic Windows host information using safe read-only WinRM commands after successful authentication.",
        ),
    ] = False,
    windows_security_status: Annotated[
        bool,
        typer.Option(
            "--windows-security-status",
            help="Collect Windows Firewall and Microsoft Defender status using safe read-only WinRM commands after successful authentication.",
        ),
    ] = False,
    windows_patch_status: Annotated[
        bool,
        typer.Option(
            "--windows-patch-status",
            help="Reserved Windows patch/update indicator flag for existing 12.4-compatible command lines.",
        ),
    ] = False,
    windows_policy_status: Annotated[
        bool,
        typer.Option(
            "--windows-policy-status",
            help="Collect Windows local security policy indicators using the read-only net accounts command after successful WinRM authentication.",
        ),
    ] = False,
    windows_registry_audit: Annotated[
        bool,
        typer.Option(
            "--windows-registry-audit",
            help="Run narrow read-only Windows registry checks from an explicit template after successful WinRM authentication.",
        ),
    ] = False,
    windows_registry_template: Annotated[
        Path | None,
        typer.Option(
            "--windows-registry-template",
            help="Path to a Windows registry audit template JSON file. Applies only with --windows-registry-audit.",
        ),
    ] = None,
    windows_timeout: Annotated[
        float,
        typer.Option(
            "--windows-timeout",
            help="WinRM connection/session timeout in seconds. Must be greater than 0 and no more than 60.",
        ),
    ] = 10.0,
    windows_command_timeout: Annotated[
        float,
        typer.Option(
            "--windows-command-timeout",
            help="Timeout for each read-only Windows command in seconds. Must be greater than 0 and no more than 180.",
        ),
    ] = 15.0,
    windows_audit_timeout: Annotated[
        float | None,
        typer.Option(
            "--windows-audit-timeout",
            help="Overall Windows audit time budget in seconds. Defaults by Windows audit profile.",
        ),
    ] = None,
    windows_progress: Annotated[
        bool,
        typer.Option(
            "--windows-progress/--no-windows-progress",
            help="Show compact terminal progress for Windows audit.",
        ),
    ] = True,
    ssh_audit: Annotated[
        bool,
        typer.Option(
            "--ssh-audit",
            help="Run authenticated read-only SSH checks against an authorised Linux target.",
        ),
    ] = False,
    ssh_user: Annotated[
        str | None,
        typer.Option(
            "--ssh-user",
            help="Username for SSH audit. Use a least-privilege account.",
        ),
    ] = None,
    ssh_password: Annotated[
        str | None,
        typer.Option(
            "--ssh-password",
            help="Password for SSH audit. Not stored or printed.",
        ),
    ] = None,
    ssh_key: Annotated[
        Path | None,
        typer.Option(
            "--ssh-key",
            help="Private key for SSH audit. Path is not stored or printed in reports.",
        ),
    ] = None,
    ssh_port: Annotated[
        int,
        typer.Option(
            "--ssh-port",
            min=1,
            max=65535,
            help="SSH port for authenticated audit.",
        ),
    ] = 22,
    ssh_timeout: Annotated[
        float,
        typer.Option(
            "--ssh-timeout",
            help="SSH connection timeout in seconds. Must be greater than 0 and no more than 60.",
        ),
    ] = 8.0,
    ssh_command_timeout: Annotated[
        float,
        typer.Option(
            "--ssh-command-timeout",
            help="Timeout for each read-only SSH audit command in seconds. Must be greater than 0 and no more than 120.",
        ),
    ] = 10.0,
    ssh_audit_timeout: Annotated[
        float | None,
        typer.Option(
            "--ssh-audit-timeout",
            help="Overall SSH audit check budget after login. Defaults by profile: basic 30, standard 60, detailed 90 seconds.",
        ),
    ] = None,
    ssh_progress: Annotated[
        bool,
        typer.Option(
            "--ssh-progress/--no-ssh-progress",
            help="Show compact terminal progress for authenticated SSH audit.",
        ),
    ] = True,
    audit_profile: Annotated[
        str,
        typer.Option(
            "--audit-profile",
            help="Credentialed SSH audit profile: basic, standard, or detailed.",
        ),
    ] = DEFAULT_AUDIT_PROFILE,
    save_db: Annotated[
        bool,
        typer.Option(
            "--save-db",
            help="Save scan results to the local SQLite history database.",
        ),
    ] = False,
    prioritise: Annotated[
        bool,
        typer.Option(
            "--prioritise",
            help="Build a vulnerability prioritisation view from local scan evidence.",
        ),
    ] = False,
    fix_first_dashboard: Annotated[
        bool,
        typer.Option(
            "--fix-first-dashboard",
            help="Generate a fix-first dashboard from prioritised findings.",
        ),
    ] = False,
    priority_trends: Annotated[
        bool,
        typer.Option(
            "--priority-trends",
            help="Compare current prioritised findings with the latest saved scan for the same target.",
        ),
    ] = False,
    owasp_map: Annotated[
        bool,
        typer.Option(
            "--owasp-map",
            help="Attach OWASP Top 10:2025 indicator mapping to findings and reports.",
        ),
    ] = False,
    owasp_assess: Annotated[
        bool,
        typer.Option(
            "--owasp-assess",
            help="Build OWASP Assessment Engine category results from existing evidence.",
        ),
    ] = False,
    owasp_report: Annotated[
        bool,
        typer.Option(
            "--owasp-report",
            help="Generate a unified Markdown-ready OWASP Assessment report from existing assessment evidence.",
        ),
    ] = False,
    a03_checks: Annotated[
        bool,
        typer.Option(
            "--a03-checks",
            help="Run safe A03 Software Supply Chain and component exposure checks from local evidence.",
        ),
    ] = False,
    use_asset_criticality: Annotated[
        bool,
        typer.Option(
            "--use-asset-criticality",
            help="Enable local asset criticality enrichment for prioritisation.",
        ),
    ] = False,
    asset_criticality: Annotated[
        str | None,
        typer.Option(
            "--asset-criticality",
            help="Direct asset criticality for the current target: critical, high, medium, low, or unknown.",
        ),
    ] = None,
    asset_criticality_file: Annotated[
        Path,
        typer.Option(
            "--asset-criticality-file",
            help="Path to a local JSON asset criticality context file.",
        ),
    ] = DEFAULT_ASSET_CRITICALITY_PATH,
    vuln_intel: Annotated[
        bool,
        typer.Option(
            "--vuln-intel",
            help="Enable local vulnerability intelligence matching.",
        ),
    ] = False,
    vuln_rules: Annotated[
        Path,
        typer.Option(
            "--vuln-rules",
            help="Path to a local vulnerability intelligence rules JSON file.",
        ),
    ] = DEFAULT_RULES_PATH,
    use_cve_feed: Annotated[
        bool,
        typer.Option(
            "--use-cve-feed",
            help="Enable matching against a local CVE-style JSON feed. Requires --vuln-intel.",
        ),
    ] = False,
    cve_feed: Annotated[
        Path,
        typer.Option(
            "--cve-feed",
            help="Path to a local CVE-style JSON feed file.",
        ),
    ] = DEFAULT_CVE_FEED_PATH,
    use_epss: Annotated[
        bool,
        typer.Option(
            "--use-epss",
            help="Enable offline EPSS enrichment for local CVE feed matches. Requires --vuln-intel and --use-cve-feed.",
        ),
    ] = False,
    epss_file: Annotated[
        Path,
        typer.Option(
            "--epss-file",
            help="Path to a local EPSS CSV or JSON metadata file.",
        ),
    ] = DEFAULT_EPSS_PATH,
    use_exploit_metadata: Annotated[
        bool,
        typer.Option(
            "--use-exploit-metadata",
            help="Enable offline exploit availability metadata enrichment for local CVE feed matches.",
        ),
    ] = False,
    exploit_metadata_file: Annotated[
        Path,
        typer.Option(
            "--exploit-metadata-file",
            help="Path to a local exploit availability metadata JSON or CSV file.",
        ),
    ] = DEFAULT_EXPLOIT_METADATA_PATH,
    bug_bounty_scope: Annotated[
        Path | None,
        typer.Option(
            "--scope-file",
            "--bug-bounty-scope",
            help="Path to a local Program Scope JSON file. Legacy --bug-bounty-scope name is retained for compatibility.",
        ),
    ] = None,
    enforce_scope: Annotated[
        bool,
        typer.Option(
            "--enforce-scope",
            help="Refuse to scan targets outside the configured program scope.",
        ),
    ] = False,
) -> None:
    """Run a defensive TCP connect scan against an authorised target."""
    bug_bounty_scope_summary: dict[str, Any] | None = None
    bug_bounty_scope_finding: dict[str, Any] | None = None
    if bug_bounty_scope is not None:
        try:
            loaded_scope = load_bug_bounty_scope(bug_bounty_scope)
        except BugBountyScopeError as exc:
            console.print(f"[red]Bug bounty scope error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        decision = get_scope_decision(target, loaded_scope)
        bug_bounty_scope_summary = build_bug_bounty_scope_summary(loaded_scope, decision)
        bug_bounty_scope_finding = build_scope_applied_finding(bug_bounty_scope_summary)
        _print_bug_bounty_scope_summary(bug_bounty_scope_summary)
        if enforce_scope and not decision.get("in_scope"):
            console.print(f"[red]Bug bounty scope blocked scan:[/red] {decision.get('reason')}")
            raise typer.Exit(code=1)
        if not enforce_scope and not decision.get("in_scope"):
            console.print("[yellow]Bug bounty scope warning: target is outside configured scope. Scan will continue because --enforce-scope was not used.[/yellow]")
    if asset_criticality and not use_asset_criticality:
        console.print(
            "[yellow]--asset-criticality was provided without --use-asset-criticality. Asset criticality enrichment has been enabled automatically.[/yellow]"
        )
        use_asset_criticality = True
    if use_asset_criticality and not prioritise:
        console.print(
            "[yellow]--use-asset-criticality is most useful with --prioritise. Prioritisation has been enabled automatically.[/yellow]"
        )
        prioritise = True
    if fix_first_dashboard and not prioritise:
        console.print(
            "[yellow]--fix-first-dashboard requires prioritisation. Prioritisation has been enabled automatically.[/yellow]"
        )
        prioritise = True
    if priority_trends and not prioritise:
        console.print(
            "[yellow]--priority-trends requires prioritisation. Prioritisation has been enabled automatically.[/yellow]"
        )
        prioritise = True
    if priority_trends and not save_db:
        console.print(
            "[yellow]--priority-trends can compare with previous saved scans, but this current scan will not be saved for future trend comparison unless --save-db is used.[/yellow]"
        )

    if windows_demo and ssh_audit:
        console.print("[red]Windows demo mode cannot be combined with --ssh-audit because demo mode must not connect to any host.[/red]")
        raise typer.Exit(code=1)

    if use_cve_feed and not vuln_intel:
        console.print("[red]--use-cve-feed requires --vuln-intel because CVE feed matching uses the vulnerability intelligence inventory.[/red]")
        raise typer.Exit(code=1)
    if use_epss and not vuln_intel:
        console.print("[red]--use-epss requires --vuln-intel because EPSS enrichment uses vulnerability intelligence CVE matches.[/red]")
        raise typer.Exit(code=1)
    if use_exploit_metadata and not vuln_intel:
        console.print("[red]--use-exploit-metadata requires --vuln-intel because exploit metadata enriches vulnerability intelligence CVE matches.[/red]")
        raise typer.Exit(code=1)
    if use_epss and not use_cve_feed:
        console.print("[red]--use-epss enriches local CVE feed matches, so it requires --use-cve-feed.[/red]")
        raise typer.Exit(code=1)
    if use_exploit_metadata and not use_cve_feed:
        console.print("[red]--use-exploit-metadata enriches local CVE feed matches, so it requires --use-cve-feed.[/red]")
        raise typer.Exit(code=1)
    if cve_feed != DEFAULT_CVE_FEED_PATH and not use_cve_feed:
        console.print("[yellow]--cve-feed was provided without --use-cve-feed. The local CVE feed will not be loaded.[/yellow]")
    if epss_file != DEFAULT_EPSS_PATH and not use_epss:
        console.print("[yellow]--epss-file was provided without --use-epss. The local EPSS file will not be loaded.[/yellow]")
    if exploit_metadata_file != DEFAULT_EXPLOIT_METADATA_PATH and not use_exploit_metadata:
        console.print("[yellow]--exploit-metadata-file was provided without --use-exploit-metadata. The local exploit metadata file will not be loaded.[/yellow]")

    try:
        selected_audit_profile = get_audit_profile(audit_profile)
    except AuditProfileError as exc:
        console.print(f"[red]Audit profile error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if not ssh_audit and selected_audit_profile.name != DEFAULT_AUDIT_PROFILE:
        console.print(
            "[yellow]Audit profiles apply to SSH audit only. The selected audit profile will be ignored because --ssh-audit was not provided.[/yellow]"
        )

    try:
        validate_ssh_audit_options(
            ssh_audit=ssh_audit,
            ssh_user=ssh_user,
            ssh_password=ssh_password,
            ssh_key=ssh_key,
            ssh_timeout=ssh_timeout,
            ssh_command_timeout=ssh_command_timeout,
            ssh_audit_timeout=ssh_audit_timeout,
        )
    except SshAuditConfigurationError as exc:
        console.print(f"[red]SSH audit configuration error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if windows_demo and not windows_audit:
        console.print(
            "[yellow]Windows demo mode implies --windows-audit. No real target will be scanned.[/yellow]"
        )
        windows_audit = True

    if windows_audit_profile and not windows_audit:
        console.print(
            "[yellow]Windows audit profiles apply only when --windows-audit is provided. The selected Windows audit profile will be ignored.[/yellow]"
        )

    try:
        selected_windows_profile = get_windows_audit_profile(windows_audit_profile)
    except WindowsAuditProfileError as exc:
        console.print(f"[red]Windows audit profile error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    preliminary_windows_auth_method = "winrm" if windows_demo else (windows_auth_method or "none").strip().lower()
    windows_profile_plan = resolve_windows_audit_profile(
        profile_name=selected_windows_profile.profile_name,
        auth_method=preliminary_windows_auth_method,
        manual_host_info=windows_host_info,
        manual_security_status=windows_security_status,
        manual_patch_status=windows_patch_status,
        manual_policy_status=windows_policy_status,
        manual_registry_audit=windows_registry_audit,
    )
    effective_windows_audit_timeout = (
        windows_audit_timeout
        if windows_audit_timeout is not None
        else selected_windows_profile.default_audit_timeout_seconds
    )
    if windows_demo:
        selected_windows_auth_method = "demo"
    else:
        try:
            selected_windows_auth_method = validate_windows_audit_options(
                windows_audit=windows_audit,
                windows_user=windows_user,
                windows_password=windows_password,
                windows_auth_method=windows_auth_method,
                windows_host_info=bool(windows_profile_plan["collect_host_info"]),
                windows_security_status=bool(windows_profile_plan["collect_security_status"]),
                windows_policy_status=bool(windows_profile_plan["collect_policy_status"]),
                windows_registry_audit=bool(windows_profile_plan["collect_registry_audit"]),
                windows_registry_template=windows_registry_template,
                windows_timeout=windows_timeout,
                windows_command_timeout=windows_command_timeout,
                windows_audit_timeout=effective_windows_audit_timeout,
            )
        except WindowsAuditConfigurationError as exc:
            console.print(f"[red]Windows audit configuration error:[/red] {exc}")
            raise typer.Exit(code=1) from exc

    console.print(Panel.fit(f"VulScan version {__version__}", style="bold cyan"))
    console.print(f"[bold]Target:[/bold] {target}")
    console.print(f"[bold]Scan mode:[/bold] {mode}")
    console.print(
        "[yellow]Safe usage warning:[/yellow] Only scan systems you own or have explicit permission to assess."
    )

    try:
        scan_start_time = datetime.now().astimezone()
        scan_result = build_demo_scan_result(target) if windows_demo else scan_tcp_ports(target)
        scan_result["scan_mode"] = mode
        scan_result["http_findings"] = []
        scan_result["tls_findings"] = []
        scan_result["ssh_audit"] = {"enabled": False, "status": "skipped", "findings": []}
        scan_result["ssh_audit_summary"] = {"enabled": False, "status": "skipped"}
        scan_result["windows_audit"] = {"enabled": False, "status": "skipped", "findings": []}
        scan_result["windows_audit_summary"] = {"enabled": False, "status": "skipped"}
        scan_result["windows_audit_sections"] = []
        scan_result["windows_audit_consolidated_summary"] = {"enabled": False, "status": "skipped"}
        scan_result["software_inventory"] = {"items": [], "total_items": 0, "sources_used": [], "limitations": []}
        scan_result["vulnerability_intelligence"] = disabled_vulnerability_intelligence_summary()
        scan_result["vuln_intel_findings"] = []
        scan_result["credentialed_audits"] = []
        scan_result["ssh_findings"] = []
        scan_result["windows_findings"] = []
        scan_result["asset_context"] = disabled_asset_context(target)
        scan_result["prioritisation_summary"] = {"enabled": False}
        scan_result["prioritised_findings"] = []
        scan_result.update(disabled_fix_first_dashboard(target))
        scan_result.update(disabled_prioritisation_trends(target))
        scan_result["demo_mode"] = bool(windows_demo)
        scan_result["demo_notice"] = DEMO_NOTICE if windows_demo else ""
        if bug_bounty_scope_summary:
            scan_result["bug_bounty_scope"] = bug_bounty_scope_summary
        findings = [] if windows_demo else create_port_exposure_findings(scan_result["open_ports"])
        if bug_bounty_scope_finding:
            findings.append(bug_bounty_scope_finding)
        if http_audit:
            http_findings = audit_http_services(scan_result["open_ports"])
            findings.extend(http_findings)
        if tls_audit:
            tls_findings = audit_tls_services(scan_result["open_ports"])
            findings.extend(tls_findings)
        if windows_audit:
            if windows_progress:
                console.print("Windows Audit")
            profile_summary_fields = _windows_profile_summary_fields(
                profile_plan=windows_profile_plan,
                audit_timeout_seconds=effective_windows_audit_timeout,
            )
            if windows_demo:
                console.print("[yellow]DEMO MODE: No real target was scanned.[/yellow]")
                console.print("[yellow]Demo Mode Notice: Demo data only. No real target was scanned.[/yellow]")
                windows_result = build_windows_demo_result(
                    target=scan_result["host"],
                    profile_summary=profile_summary_fields,
                    audit_timeout_seconds=effective_windows_audit_timeout,
                )
            else:
                windows_result = audit_windows_host(
                    target=scan_result["host"],
                    resolved_ip=scan_result["resolved_ip"],
                    username=windows_user,
                    password=windows_password,
                    domain=windows_domain,
                    auth_method=selected_windows_auth_method,
                    collect_host_info=bool(windows_profile_plan["collect_host_info"]),
                    collect_security_status=bool(windows_profile_plan["collect_security_status"]),
                    collect_policy_status=bool(windows_profile_plan["collect_policy_status"]),
                    collect_registry_audit=bool(windows_profile_plan["collect_registry_audit"]),
                    registry_template_path=windows_registry_template,
                    timeout=windows_timeout,
                    command_timeout=windows_command_timeout,
                    audit_timeout=effective_windows_audit_timeout,
                    progress_callback=_windows_progress_callback if windows_progress else None,
                )
                windows_result["summary"] = dict(windows_result.get("summary") or {})
                windows_result["summary"].update(profile_summary_fields)
            scan_result["windows_audit"] = windows_result
            findings.extend(windows_result.get("findings", []))
        if ssh_audit:
            if ssh_progress:
                console.print("Credentialed SSH Audit")
            effective_ssh_audit_timeout = (
                ssh_audit_timeout
                if ssh_audit_timeout is not None
                else selected_audit_profile.default_audit_timeout_seconds
            )
            ssh_result = audit_ssh_host(
                host=scan_result["host"],
                resolved_ip=scan_result["resolved_ip"],
                username=str(ssh_user),
                password=ssh_password,
                key_path=ssh_key,
                port=ssh_port,
                timeout=ssh_timeout,
                command_timeout=ssh_command_timeout,
                audit_timeout=effective_ssh_audit_timeout,
                open_ports=scan_result["open_ports"],
                audit_profile=selected_audit_profile,
                progress_callback=_ssh_progress_callback if ssh_progress else None,
            )
            scan_result["ssh_audit"] = ssh_result
            findings.extend(ssh_result.get("findings", []))
        scan_result["findings"] = assign_sequential_finding_ids(findings)
        _apply_asset_fields_to_findings(scan_result["findings"], scan_result.get("asset_context", {}))
        scan_result["http_findings"] = [
            finding for finding in scan_result["findings"] if finding["source"] == "http_audit"
        ]
        scan_result["tls_findings"] = [
            finding for finding in scan_result["findings"] if finding["source"] == "tls_audit"
        ]
        scan_result["ssh_findings"] = [
            finding
            for finding in scan_result["findings"]
            if _is_ssh_related_finding(finding)
        ]
        scan_result["windows_findings"] = [
            finding
            for finding in scan_result["findings"]
            if _is_windows_related_finding(finding)
        ]
        if ssh_audit:
            scan_result["ssh_audit"]["findings"] = scan_result["ssh_findings"]
            scan_result["credentialed_audits"] = _build_credentialed_audits(
                ssh_result=scan_result["ssh_audit"],
                ssh_findings=scan_result["ssh_findings"],
            )
            scan_result["ssh_audit_summary"] = _build_ssh_audit_summary(
                scan_result=scan_result,
                username=str(ssh_user),
                auth_method="key" if ssh_key is not None else "password",
                ssh_port=ssh_port,
                audit_profile=selected_audit_profile,
            )
        if windows_audit:
            scan_result["windows_audit"]["findings"] = scan_result["windows_findings"]
            scan_result["windows_audit_sections"] = build_windows_audit_sections(
                windows_result=scan_result["windows_audit"],
                windows_findings=scan_result["windows_findings"],
            )
            scan_result["windows_audit"]["windows_audit_sections"] = scan_result["windows_audit_sections"]
            scan_result["windows_audit_summary"] = _build_windows_audit_summary(
                scan_result=scan_result,
            )
            scan_result["windows_audit_consolidated_summary"] = build_windows_consolidated_summary(
                sections=scan_result["windows_audit_sections"],
                windows_findings=scan_result["windows_findings"],
                base_summary=scan_result["windows_audit_summary"],
            )
            scan_result["credentialed_audits"].extend(
                _build_windows_credentialed_audits(
                    windows_result=scan_result["windows_audit"],
                    windows_findings=scan_result["windows_findings"],
                    windows_summary=scan_result["windows_audit_summary"],
                )
            )
        scan_result["software_inventory"] = build_software_inventory(scan_result)
        if vuln_intel:
            try:
                inventory, vulnerability_intelligence, vuln_intel_findings = run_vulnerability_intelligence(
                    scan_result=scan_result,
                    rules_path=vuln_rules,
                    use_cve_feed=use_cve_feed,
                    cve_feed_path=cve_feed,
                    use_epss=use_epss,
                    epss_file=epss_file,
                    use_exploit_metadata=use_exploit_metadata,
                    exploit_metadata_file=exploit_metadata_file,
                )
            except VulnIntelRulesError as exc:
                console.print(f"[red]Vulnerability intelligence error:[/red] {exc}")
                raise typer.Exit(code=1) from exc
            scan_result["software_inventory"] = inventory
            scan_result["vulnerability_intelligence"] = vulnerability_intelligence
            scan_result["vuln_intel_findings"] = vuln_intel_findings
            findings.extend(vuln_intel_findings)
        if use_asset_criticality:
            asset_context_file = load_asset_criticality_context(asset_criticality_file)
            for warning in asset_context_file.get("warnings") or []:
                console.print(f"[yellow]{warning}[/yellow]")
            asset_context = resolve_asset_criticality(
                target=scan_result["host"],
                direct_value=asset_criticality,
                context=asset_context_file,
            )
            for warning in asset_context.get("warnings") or []:
                console.print(f"[yellow]{warning}[/yellow]")
            scan_result["asset_context"] = asset_context
            findings.append(_build_asset_criticality_finding(asset_context))
        scan_result["findings"] = assign_sequential_finding_ids(findings)
        _apply_asset_fields_to_findings(scan_result["findings"], scan_result.get("asset_context", {}))
        scan_result["http_findings"] = [
            finding for finding in scan_result["findings"] if finding["source"] == "http_audit"
        ]
        scan_result["tls_findings"] = [
            finding for finding in scan_result["findings"] if finding["source"] == "tls_audit"
        ]
        scan_result["ssh_findings"] = [
            finding
            for finding in scan_result["findings"]
            if _is_ssh_related_finding(finding)
        ]
        scan_result["windows_findings"] = [
            finding
            for finding in scan_result["findings"]
            if _is_windows_related_finding(finding)
        ]
        scan_result["vuln_intel_findings"] = [
            finding
            for finding in scan_result["findings"]
            if finding["source"] in {"vuln_intel", "cve_feed", "epss_importer", "exploit_metadata"}
        ]
        if prioritise:
            prioritisation_summary, prioritised_findings = build_prioritisation(
                scan_result["findings"],
                asset_context=scan_result.get("asset_context"),
                enabled=True,
            )
            scan_result["prioritisation_summary"] = prioritisation_summary
            scan_result["prioritised_findings"] = prioritised_findings
            scan_result.update(
                build_fix_first_dashboard(
                    target=scan_result["host"],
                    findings=scan_result["findings"],
                    prioritised_findings=prioritised_findings,
                )
            )
            _apply_dashboard_export_fields(
                scan_result["findings"],
                scan_result.get("top_fix_first_findings", []),
                prioritised_findings,
            )
            if not _has_dashboard_finding(scan_result["findings"]):
                findings.append(build_dashboard_finding())
                scan_result["findings"] = assign_sequential_finding_ids(findings)
                _apply_asset_fields_to_findings(scan_result["findings"], scan_result.get("asset_context", {}))
                _apply_dashboard_export_fields(
                    scan_result["findings"],
                    scan_result.get("top_fix_first_findings", []),
                    prioritised_findings,
                )
            if priority_trends:
                current_scan_time = scan_start_time.isoformat(timespec="seconds")
                try:
                    previous_scan = get_latest_scan_for_prioritisation_trends(scan_result["host"])
                    if previous_scan and previous_scan.get("trend_warning"):
                        console.print(f"[yellow]{previous_scan['trend_warning']}[/yellow]")
                    trends_payload = build_prioritisation_trends(
                        target=scan_result["host"],
                        current_prioritised_findings=prioritised_findings,
                        previous_scan=previous_scan,
                        current_scan_time=current_scan_time,
                    )
                except Exception:
                    console.print("[yellow]Priority trend comparison is unavailable because local scan history could not be read.[/yellow]")
                    trends_payload = unavailable_prioritisation_trends(
                        scan_result["host"],
                        "Priority trend comparison was unavailable because local scan history could not be read.",
                        current_scan_time=current_scan_time,
                    )
                scan_result.update(trends_payload)
                trends = scan_result.get("prioritisation_trends", {})
                if trends.get("status") == "baseline":
                    console.print("[yellow]No previous saved prioritised scan was found. This scan is the trend baseline.[/yellow]")
                _apply_trends_to_dashboard(scan_result)
                _apply_trend_export_fields(
                    scan_result["findings"],
                    scan_result.get("prioritisation_trend_details", {}),
                    scan_result["host"],
                )
                if trends.get("status") in {"baseline", "compared"} and not _has_trend_finding(scan_result["findings"]):
                    findings.append(build_trend_finding(str(trends.get("status") or "")))
                    scan_result["findings"] = assign_sequential_finding_ids(findings)
                    _apply_asset_fields_to_findings(scan_result["findings"], scan_result.get("asset_context", {}))
                    _apply_dashboard_export_fields(
                        scan_result["findings"],
                        scan_result.get("top_fix_first_findings", []),
                        prioritised_findings,
                    )
                    _apply_trend_export_fields(
                        scan_result["findings"],
                        scan_result.get("prioritisation_trend_details", {}),
                        scan_result["host"],
                    )
        scan_result["http_findings"] = [
            finding for finding in scan_result["findings"] if finding["source"] == "http_audit"
        ]
        scan_result["tls_findings"] = [
            finding for finding in scan_result["findings"] if finding["source"] == "tls_audit"
        ]
        scan_result["ssh_findings"] = [
            finding
            for finding in scan_result["findings"]
            if _is_ssh_related_finding(finding)
        ]
        scan_result["windows_findings"] = [
            finding
            for finding in scan_result["findings"]
            if _is_windows_related_finding(finding)
        ]
        scan_result["vuln_intel_findings"] = [
            finding
            for finding in scan_result["findings"]
            if finding["source"] in {"vuln_intel", "cve_feed", "epss_importer", "exploit_metadata"}
        ]
        if ssh_audit:
            scan_result["ssh_audit"]["findings"] = scan_result["ssh_findings"]
            scan_result["credentialed_audits"] = _build_credentialed_audits(
                ssh_result=scan_result["ssh_audit"],
                ssh_findings=scan_result["ssh_findings"],
            )
        if windows_audit:
            scan_result["windows_audit"]["findings"] = scan_result["windows_findings"]
            if not ssh_audit:
                scan_result["credentialed_audits"] = []
            scan_result["credentialed_audits"].extend(
                _build_windows_credentialed_audits(
                    windows_result=scan_result["windows_audit"],
                    windows_findings=scan_result["windows_findings"],
                    windows_summary=scan_result["windows_audit_summary"],
                )
            )
        scan_end_time = datetime.now().astimezone()
        scan_result["scan_start_time"] = scan_start_time.isoformat(timespec="seconds")
        scan_result["scan_end_time"] = scan_end_time.isoformat(timespec="seconds")
    except PortScanError as exc:
        console.print(f"[red]Scan error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(f"[bold]Resolved IP:[/bold] {scan_result['resolved_ip']}")

    open_ports = scan_result["open_ports"]
    if open_ports:
        table = Table(title="Open TCP Ports")
        table.add_column("Port", justify="right")
        table.add_column("Protocol")
        table.add_column("Service")
        table.add_column("Status")
        table.add_column("Evidence")
        table.add_column("Recommendation")

        for result in open_ports:
            table.add_row(
                str(result["port"]),
                result["protocol"],
                result["service"],
                result["status"],
                result["evidence"],
                result["recommendation"],
            )

        console.print(table)
    else:
        console.print("[green]Open TCP ports:[/green] None found in the default safe port list.")

    console.print(f"[bold]Total scan time:[/bold] {scan_result['duration_seconds']} seconds")
    _print_ssh_audit_summary(scan_result.get("ssh_audit_summary", {"enabled": False}))
    _print_windows_audit_summary(scan_result.get("windows_audit_summary", {"enabled": False}))
    _print_credentialed_audit_modules(scan_result.get("credentialed_audits", []))
    _print_vulnerability_intelligence(scan_result.get("vulnerability_intelligence", {}))
    _print_asset_context(scan_result.get("asset_context", {}))
    _print_bug_bounty_scope_summary(scan_result.get("bug_bounty_scope", {}))
    _print_prioritisation(
        scan_result.get("prioritisation_summary", {}),
        scan_result.get("prioritised_findings", []),
    )
    _print_fix_first_dashboard(
        scan_result.get("fix_first_dashboard", {}),
        scan_result.get("top_fix_first_findings", []),
    )
    _print_prioritisation_trends(
        scan_result.get("prioritisation_trends", {}),
        scan_result.get("prioritisation_trend_details", {}),
    )
    if a03_checks:
        try:
            attach_a03_supply_chain(scan_result, vuln_intel=_build_a03_vuln_intel(use_cve_feed, cve_feed))
        except (A03RulesError, CveFeedError) as exc:
            console.print(f"[red]A03 Software Supply Chain error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a03_supply_chain_summary(scan_result.get("a03_supply_chain_summary", {}))
    if owasp_map or owasp_assess:
        try:
            attach_owasp_metadata(scan_result)
        except OWASPMappingError as exc:
            console.print(f"[red]OWASP mapping error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_owasp_summary(scan_result.get("owasp_top10_summary", {}), scan_result.get("owasp_top10_mapped_items", []))
    if owasp_assess:
        try:
            attach_owasp_assessment(scan_result)
        except OWASPAssessmentRulesError as exc:
            console.print(f"[red]OWASP assessment error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_owasp_assessment_summary(scan_result.get("owasp_assessment_summary", {}), scan_result.get("owasp_category_results", []))
    if owasp_report:
        try:
            if not scan_result.get("owasp_assessment_summary", {}).get("enabled"):
                attach_owasp_metadata(scan_result)
                attach_owasp_assessment(scan_result)
            report_path = _generate_owasp_markdown_report(scan_result)
        except (OWASPMappingError, OWASPAssessmentRulesError) as exc:
            console.print(f"[red]OWASP report error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        console.print(f"[bold]OWASP Markdown report saved:[/bold] {report_path}")

    _print_findings(scan_result["findings"])

    if save_db:
        scan_id = save_scan_result(scan_result)
        console.print(f"[bold]Scan saved to database:[/bold] data\\vulscan.db ({scan_id})")
    elif json_report or html_report:
        enrich_findings_with_remediation(scan_result["findings"])

    if json_report:
        report_path = save_json_report(
            scan_result=scan_result,
            scanner_name="VulScan",
            scanner_version=__version__,
            scan_start_time=scan_start_time,
            scan_end_time=scan_end_time,
        )
        console.print(f"[bold]JSON report saved:[/bold] {report_path}")

    if html_report:
        report_path = save_html_report(
            scan_result=scan_result,
            scanner_name="VulScan",
            scanner_version=__version__,
            scan_start_time=scan_start_time,
            scan_end_time=scan_end_time,
        )
        console.print(f"HTML report saved: {report_path}")


@app.command("web-scan")
def web_scan(
    url: Annotated[
        str,
        typer.Option(
            "--url",
            help="Authorised web application URL to crawl.",
        ),
    ],
    crawl: Annotated[
        bool,
        typer.Option(
            "--crawl/--no-crawl",
            help="Follow same-host links using safe GET requests only.",
        ),
    ] = True,
    max_pages: Annotated[
        int,
        typer.Option(
            "--max-pages",
            min=1,
            help="Maximum number of same-host pages to fetch.",
        ),
    ] = 20,
    max_depth: Annotated[
        int,
        typer.Option(
            "--max-depth",
            min=0,
            help="Maximum same-host crawl depth from the start URL.",
        ),
    ] = 2,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            min=1.0,
            help="Per-request timeout in seconds.",
        ),
    ] = 10.0,
    request_delay: Annotated[
        float,
        typer.Option(
            "--request-delay",
            help="Seconds to wait between HTTP requests. Valid range: 0 to 30.",
        ),
    ] = 0.5,
    max_requests_per_minute: Annotated[
        int,
        typer.Option(
            "--max-requests-per-minute",
            help="Maximum Web DAST HTTP requests per minute. Valid range: 1 to 600.",
        ),
    ] = 60,
    retry_limit: Annotated[
        int,
        typer.Option(
            "--retry-limit",
            help="Number of safe retries for transient GET request errors. Valid range: 0 to 5.",
        ),
    ] = 1,
    retry_backoff: Annotated[
        float,
        typer.Option(
            "--retry-backoff",
            help="Seconds multiplier used for retry delay. Valid range: 0 to 60.",
        ),
    ] = 2.0,
    max_errors: Annotated[
        int,
        typer.Option(
            "--max-errors",
            help="Stop the web crawl when this many request errors occur. Valid range: 1 to 100.",
        ),
    ] = 10,
    respect_retry_after: Annotated[
        bool,
        typer.Option(
            "--respect-retry-after/--no-respect-retry-after",
            help="Respect Retry-After headers when retrying throttled responses.",
        ),
    ] = True,
    user_agent: Annotated[
        str,
        typer.Option(
            "--user-agent",
            help="User-Agent header for safe crawler requests.",
        ),
    ] = DEFAULT_USER_AGENT,
    robots: Annotated[
        bool,
        typer.Option(
            "--robots",
            help="Fetch and report robots.txt guidance for the start URL origin.",
        ),
    ] = False,
    respect_robots: Annotated[
        bool,
        typer.Option(
            "--respect-robots/--no-respect-robots",
            help="Respect robots.txt disallow rules when --robots is enabled.",
        ),
    ] = True,
    robots_user_agent: Annotated[
        str,
        typer.Option(
            "--robots-user-agent",
            help="User-agent used when evaluating robots.txt rules.",
        ),
    ] = DEFAULT_ROBOTS_USER_AGENT,
    sitemap: Annotated[
        bool,
        typer.Option(
            "--sitemap",
            help="Discover and report in-scope XML sitemaps.",
        ),
    ] = False,
    sitemap_url: Annotated[
        list[str] | None,
        typer.Option(
            "--sitemap-url",
            help="Explicit sitemap URL to fetch. Can be repeated.",
        ),
    ] = None,
    use_sitemap_for_crawl: Annotated[
        bool,
        typer.Option(
            "--use-sitemap-for-crawl",
            help="Add in-scope sitemap URL entries to the crawl queue.",
        ),
    ] = False,
    max_sitemap_urls: Annotated[
        int,
        typer.Option(
            "--max-sitemap-urls",
            min=1,
            help="Maximum sitemap URL entries to parse and store.",
        ),
    ] = 100,
    max_sitemap_depth: Annotated[
        int,
        typer.Option(
            "--max-sitemap-depth",
            min=0,
            help="Maximum nested sitemap index depth to follow.",
        ),
    ] = 2,
    headers: Annotated[
        bool,
        typer.Option(
            "--headers",
            help="Run passive security header checks for crawled pages or the start URL.",
        ),
    ] = False,
    cookies: Annotated[
        bool,
        typer.Option(
            "--cookies",
            help="Run passive cookie attribute checks for crawled pages or the start URL.",
        ),
    ] = False,
    forms: Annotated[
        bool,
        typer.Option(
            "--forms",
            help="Run enhanced passive form discovery for crawled pages or the start URL.",
        ),
    ] = False,
    allow_host: Annotated[
        list[str] | None,
        typer.Option(
            "--allow-host",
            help="Additional host allowed for Web DAST crawling and passive checks. Can be repeated.",
        ),
    ] = None,
    deny_host: Annotated[
        list[str] | None,
        typer.Option(
            "--deny-host",
            help="Host blocked from Web DAST crawling and passive checks. Can be repeated.",
        ),
    ] = None,
    allow_path: Annotated[
        list[str] | None,
        typer.Option(
            "--allow-path",
            help="Only allow URL paths starting with this prefix. Can be repeated.",
        ),
    ] = None,
    deny_path: Annotated[
        list[str] | None,
        typer.Option(
            "--deny-path",
            help="Block URL paths starting with this prefix. Can be repeated.",
        ),
    ] = None,
    include_subdomains: Annotated[
        bool,
        typer.Option(
            "--include-subdomains",
            help="Allow subdomains of the start URL domain.",
        ),
    ] = False,
    same_host_only: Annotated[
        bool,
        typer.Option(
            "--same-host-only/--no-same-host-only",
            help="Restrict crawling to the exact start host unless allow-host or include-subdomains is used.",
        ),
    ] = True,
    show_scope: Annotated[
        bool,
        typer.Option(
            "--show-scope",
            help="Print effective Web DAST scope rules before scanning.",
        ),
    ] = False,
    passive_summary: Annotated[
        bool,
        typer.Option(
            "--passive-summary",
            help="Build a consolidated passive Web DAST risk summary.",
        ),
    ] = False,
    json_report: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Save web scan results to a JSON report in the reports folder.",
        ),
    ] = False,
    html_report: Annotated[
        bool,
        typer.Option(
            "--html",
            help="Save web scan results to an HTML report in the reports folder.",
        ),
    ] = False,
    owasp_map: Annotated[
        bool,
        typer.Option(
            "--owasp-map",
            help="Attach OWASP Top 10:2025 indicator mapping to web findings and reports.",
        ),
    ] = False,
    owasp_assess: Annotated[
        bool,
        typer.Option(
            "--owasp-assess",
            help="Build OWASP Assessment Engine category results from existing web evidence.",
        ),
    ] = False,
    owasp_report: Annotated[
        bool,
        typer.Option(
            "--owasp-report",
            help="Generate a unified Markdown-ready OWASP Assessment report from existing web evidence.",
        ),
    ] = False,
    a02_checks: Annotated[
        bool,
        typer.Option(
            "--a02-checks",
            help="Accepted for Version 20.1 compatibility; A02 evidence is built from existing passive web and OWASP assessment evidence.",
        ),
    ] = False,
    a01_checks: Annotated[
        bool,
        typer.Option(
            "--a01-checks",
            help="Run safe A01 Broken Access Control candidate discovery and manual validation planning.",
        ),
    ] = False,
    a03_checks: Annotated[
        bool,
        typer.Option(
            "--a03-checks",
            help="Run safe A03 Software Supply Chain and component exposure checks from observed web metadata.",
        ),
    ] = False,
    a08_checks: Annotated[
        bool,
        typer.Option(
            "--a08-checks",
            help="Run safe A08 Software/Data Integrity indicator checks from observed endpoints, forms, scripts, and metadata.",
        ),
    ] = False,
    a04_checks: Annotated[
        bool,
        typer.Option(
            "--a04-checks",
            help="Run safe A04 Cryptographic Failures and transport security evidence checks.",
        ),
    ] = False,
    a05_checks: Annotated[
        bool,
        typer.Option(
            "--a05-checks",
            help="Run safe A05 Injection candidate and reflection analysis.",
        ),
    ] = False,
    safe_reflection: Annotated[
        bool,
        typer.Option(
            "--safe-reflection",
            help="Run limited harmless marker reflection observation for selected GET parameters.",
        ),
    ] = False,
    max_reflection_checks: Annotated[
        int,
        typer.Option(
            "--max-reflection-checks",
            min=0,
            help="Maximum harmless reflection observations when --safe-reflection is enabled.",
        ),
    ] = 10,
    a07_checks: Annotated[
        bool,
        typer.Option(
            "--a07-checks",
            help="Run safe A07 Authentication Failures and session indicator checks.",
        ),
    ] = False,
    a10_checks: Annotated[
        bool,
        typer.Option(
            "--a10-checks",
            help="Run safe A10 Mishandling of Exceptional Conditions error-handling checks.",
        ),
    ] = False,
    bug_bounty_scope: Annotated[
        Path | None,
        typer.Option(
            "--scope-file",
            "--bug-bounty-scope",
            help="Path to a local Program Scope JSON file. Legacy --bug-bounty-scope name is retained for compatibility.",
        ),
    ] = None,
    enforce_scope: Annotated[
        bool,
        typer.Option(
            "--enforce-scope",
            help="Refuse to crawl URLs outside the configured program scope.",
        ),
    ] = False,
) -> None:
    """Run the safe Web DAST crawler foundation."""
    console.print(Panel.fit(f"VulScan version {__version__}", style="bold cyan"))
    console.print("[bold]Web DAST Crawler[/bold]")
    console.print(f"[bold]Start URL:[/bold] {url}")
    console.print(
        "[yellow]Safe usage warning:[/yellow] Only crawl web applications you own or have explicit permission to assess."
    )
    console.print(
        "[yellow]Web DAST safety:[/yellow] GET-only crawling. Forms are discovered but never submitted."
    )
    bug_bounty_scope_summary: dict[str, Any] | None = None
    bug_bounty_scope_finding: dict[str, Any] | None = None
    if bug_bounty_scope is not None:
        try:
            loaded_scope = load_bug_bounty_scope(bug_bounty_scope)
        except BugBountyScopeError as exc:
            console.print(f"[red]Bug bounty scope error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        decision = get_scope_decision(url, loaded_scope)
        bug_bounty_scope_summary = build_bug_bounty_scope_summary(loaded_scope, decision)
        bug_bounty_scope_finding = build_scope_applied_finding(bug_bounty_scope_summary)
        _print_bug_bounty_scope_summary(bug_bounty_scope_summary)
        if enforce_scope and not decision.get("in_scope"):
            console.print(f"[red]Bug bounty scope blocked web scan:[/red] {decision.get('reason')}")
            raise typer.Exit(code=1)
        if not enforce_scope and not decision.get("in_scope"):
            console.print("[yellow]Bug bounty scope warning: URL is outside configured scope. Web scan will continue because --enforce-scope was not used.[/yellow]")

    try:
        validate_web_politeness_options(
            request_delay=request_delay,
            max_requests_per_minute=max_requests_per_minute,
            retry_limit=retry_limit,
            retry_backoff=retry_backoff,
            max_errors=max_errors,
        )
    except WebRateLimitConfigurationError as exc:
        console.print(f"[red]Web DAST politeness configuration error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    try:
        scan_start_time = datetime.now().astimezone()
        scope = build_web_scope(
            start_url=url,
            allow_hosts=allow_host,
            deny_hosts=deny_host,
            allow_paths=allow_path,
            deny_paths=deny_path,
            include_subdomains=include_subdomains,
            same_host_only=same_host_only,
            max_pages=max_pages,
            max_depth=max_depth,
        )
        if show_scope:
            _print_web_scope_summary(scope.summary())
        rate_limiter = build_web_rate_limiter(
            request_delay=request_delay,
            max_requests_per_minute=max_requests_per_minute,
            retry_limit=retry_limit,
            retry_backoff=retry_backoff,
            max_errors=max_errors,
            respect_retry_after=respect_retry_after,
        )
        robots_policy = fetch_robots_policy(
            start_url=scope.start_url,
            session=None,
            headers={"User-Agent": user_agent},
            timeout=timeout,
            limiter=rate_limiter,
            enabled=False,
            respect_robots=respect_robots,
            robots_user_agent=robots_user_agent,
        )
        client_session = None
        if robots or sitemap:
            import requests

            client_session = requests.Session()
        if robots:
            robots_policy = fetch_robots_policy(
                start_url=scope.start_url,
                session=client_session,
                headers={"User-Agent": user_agent},
                timeout=timeout,
                limiter=rate_limiter,
                enabled=True,
                respect_robots=respect_robots,
                robots_user_agent=robots_user_agent,
            )
        web_sitemap_result = discover_sitemaps(
            start_url=scope.start_url,
            session=client_session,
            headers={"User-Agent": user_agent},
            timeout=timeout,
            limiter=rate_limiter,
            scope=scope,
            robots_policy=robots_policy if robots else None,
            explicit_sitemap_urls=sitemap_url,
            enabled=sitemap,
            use_sitemap_for_crawl=use_sitemap_for_crawl,
            max_sitemap_urls=max_sitemap_urls,
            max_sitemap_depth=max_sitemap_depth,
        )
        passive_summary_only = passive_summary and not _any_explicit_web_module_flag()
        effective_headers = headers or passive_summary_only
        effective_cookies = cookies or passive_summary_only
        effective_forms = forms or passive_summary_only
        crawl_requested = False if passive_summary_only else _effective_web_crawl(
            crawl=crawl,
            headers=effective_headers,
            cookies=effective_cookies,
            forms=effective_forms,
        )
        web_result = crawl_web(
            start_url=url,
            crawl=crawl_requested,
            max_pages=max_pages,
            max_depth=max_depth,
            timeout=timeout,
            user_agent=user_agent,
            session=client_session,
            scope=scope,
            rate_limiter=rate_limiter,
            robots_policy=robots_policy if robots else None,
            seed_urls=web_sitemap_result.get("crawl_urls", []),
        )
        web_header_result = (
            audit_web_headers(web_result.get("crawled_pages", []))
            if effective_headers
            else {
                "enabled": False,
                "status": "skipped",
                "web_header_summary": {"enabled": False, "status": "skipped"},
                "web_header_results": [],
                "findings": [],
            }
        )
        web_cookie_result = (
            audit_web_cookies(web_result.get("crawled_pages", []))
            if effective_headers or effective_cookies
            else {
                "enabled": False,
                "status": "skipped",
                "web_cookie_summary": {"enabled": False, "status": "skipped"},
                "web_cookie_results": [],
                "findings": [],
            }
        )
        web_form_result = (
            audit_web_forms(web_result.get("crawled_pages", []))
            if effective_forms
            else {
                "enabled": False,
                "status": "skipped",
                "web_form_summary": {"enabled": False, "status": "skipped"},
                "web_form_results": [],
                "findings": [],
            }
        )
        all_web_findings = (
            list(web_result.get("findings", []))
            + list(web_header_result.get("findings", []))
            + list(web_cookie_result.get("findings", []))
            + list(web_form_result.get("findings", []))
            + list(web_sitemap_result.get("findings", []))
        )
        if bug_bounty_scope_finding:
            all_web_findings.append(bug_bounty_scope_finding)
        web_scope_summary = web_result.get("web_scope_summary", scope.summary())
        web_politeness_summary = web_result.get("web_politeness_summary", rate_limiter.summary())
        web_robots_summary = robots_policy.summary()
        web_sitemap_summary = web_sitemap_result.get("web_sitemap_summary", {"enabled": False, "status": "skipped"})
        web_sitemap_results = list(web_sitemap_result.get("web_sitemap_results", []))
        web_sitemap_url_samples = list(web_sitemap_result.get("web_sitemap_url_samples", []))
        skipped_url_samples = list(web_result.get("skipped_url_samples", []))
        request_error_samples = list(web_result.get("request_error_samples", []))
        all_web_findings.extend(build_scope_findings(web_scope_summary, skipped_url_samples))
        all_web_findings.extend(build_politeness_findings(web_politeness_summary))
        all_web_findings.extend(build_robots_findings(web_robots_summary))
        web_passive_summary = {"enabled": False, "status": "skipped"}
        if passive_summary:
            web_passive_summary = build_web_passive_summary(
                start_url=url,
                web_scan_summary=web_result.get("web_scan_summary", {}),
                web_header_summary=web_header_result.get("web_header_summary", {}),
                web_cookie_summary=web_cookie_result.get("web_cookie_summary", {}),
                web_form_summary=web_form_result.get("web_form_summary", {}),
                findings=all_web_findings,
            )
            all_web_findings.extend(
                build_web_passive_summary_findings(
                    web_passive_summary,
                    existing_findings=all_web_findings,
                )
            )
        all_web_findings.extend(
            build_web_report_consolidation_finding(existing_findings=all_web_findings)
        )
        web_findings = assign_sequential_finding_ids(all_web_findings)
        web_dast_sections = build_web_dast_sections(
            web_scope_summary=web_scope_summary,
            web_politeness_summary=web_politeness_summary,
            web_robots_summary=web_robots_summary,
            web_sitemap_summary=web_sitemap_summary,
            web_scan_summary=web_result.get("web_scan_summary", {}),
            web_header_summary=web_header_result.get("web_header_summary", {}),
            web_cookie_summary=web_cookie_result.get("web_cookie_summary", {}),
            web_form_summary=web_form_result.get("web_form_summary", {}),
            web_passive_summary=web_passive_summary,
            findings=web_findings,
        )
        web_dast_summary = build_web_dast_summary(
            start_url=url,
            web_dast_sections=web_dast_sections,
            web_scope_summary=web_scope_summary,
            web_politeness_summary=web_politeness_summary,
            web_robots_summary=web_robots_summary,
            web_sitemap_summary=web_sitemap_summary,
            web_scan_summary=web_result.get("web_scan_summary", {}),
            web_header_summary=web_header_result.get("web_header_summary", {}),
            web_cookie_summary=web_cookie_result.get("web_cookie_summary", {}),
            web_form_summary=web_form_result.get("web_form_summary", {}),
            web_passive_summary=web_passive_summary,
            findings=web_findings,
        )
        scan_end_time = datetime.now().astimezone()
    except ValueError as exc:
        console.print(f"[red]Web DAST configuration error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    summary = web_result["web_scan_summary"]
    scan_result = {
        "host": summary["allowed_host"],
        "target": url,
        "url": url,
        "resolved_ip": "",
        "scan_mode": "web-dast",
        "duration_seconds": summary["duration_seconds"],
        "open_ports": [],
        "findings": web_findings,
        "http_findings": [],
        "tls_findings": [],
        "ssh_audit": {"enabled": False, "status": "skipped", "findings": []},
        "ssh_audit_summary": {"enabled": False, "status": "skipped"},
        "windows_audit": {"enabled": False, "status": "skipped", "findings": []},
        "windows_audit_summary": {"enabled": False, "status": "skipped"},
        "windows_audit_sections": [],
        "windows_audit_consolidated_summary": {"enabled": False, "status": "skipped"},
        "credentialed_audits": [],
        "ssh_findings": [],
        "windows_findings": [],
        "web_scan": web_result,
        "web_scan_summary": summary,
        "web_header_summary": web_header_result["web_header_summary"],
        "web_header_results": web_header_result["web_header_results"],
        "web_cookie_summary": web_cookie_result["web_cookie_summary"],
        "web_cookie_results": web_cookie_result["web_cookie_results"],
        "web_form_summary": web_form_result["web_form_summary"],
        "web_form_results": web_form_result["web_form_results"],
        "web_passive_summary": web_passive_summary,
        "web_scope_summary": web_scope_summary,
        "web_politeness_summary": web_politeness_summary,
        "web_robots_summary": web_robots_summary,
        "web_sitemap_summary": web_sitemap_summary,
        "web_sitemap_results": web_sitemap_results,
        "web_sitemap_url_samples": web_sitemap_url_samples,
        "skipped_url_samples": skipped_url_samples,
        "request_error_samples": request_error_samples,
        "crawled_pages": web_result["crawled_pages"],
        "discovered_forms": web_result["discovered_forms"],
        "web_findings": web_findings,
        "web_dast_summary": web_dast_summary,
        "web_dast_sections": web_dast_sections,
        "demo_mode": False,
        "demo_notice": "",
        "bug_bounty_scope": bug_bounty_scope_summary or {},
        "scan_start_time": scan_start_time.isoformat(timespec="seconds"),
        "scan_end_time": scan_end_time.isoformat(timespec="seconds"),
    }

    _print_web_dast_report(scan_result["web_dast_summary"], scan_result["web_dast_sections"])
    _print_bug_bounty_scope_summary(scan_result.get("bug_bounty_scope", {}))
    if a01_checks:
        try:
            attach_a01_access_control(scan_result)
        except A01RulesError as exc:
            console.print(f"[red]A01 Broken Access Control error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a01_access_control_summary(scan_result.get("a01_access_control_summary", {}))
    if a03_checks:
        try:
            attach_a03_supply_chain(scan_result)
        except A03RulesError as exc:
            console.print(f"[red]A03 Software Supply Chain error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a03_supply_chain_summary(scan_result.get("a03_supply_chain_summary", {}))
    if a08_checks:
        try:
            attach_a08_integrity(scan_result)
        except A08RulesError as exc:
            console.print(f"[red]A08 Software/Data Integrity error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a08_integrity_summary(scan_result.get("a08_integrity_summary", {}))
    if a04_checks:
        try:
            attach_a04_crypto(scan_result)
        except A04RulesError as exc:
            console.print(f"[red]A04 Cryptographic Failures error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a04_crypto_summary(scan_result.get("a04_crypto_summary", {}))
    if a05_checks:
        try:
            attach_a05_injection(scan_result, safe_reflection=safe_reflection, max_reflection_checks=max_reflection_checks, request_delay=request_delay)
        except A05RulesError as exc:
            console.print(f"[red]A05 Injection error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a05_injection_summary(scan_result.get("a05_injection_summary", {}))
    if a07_checks:
        try:
            attach_a07_authentication(scan_result)
        except A07RulesError as exc:
            console.print(f"[red]A07 Authentication Failures error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a07_authentication_summary(scan_result.get("a07_authentication_summary", {}))
    if a10_checks:
        try:
            attach_a10_error_handling(scan_result)
        except A10RulesError as exc:
            console.print(f"[red]A10 Mishandling of Exceptional Conditions error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a10_error_handling_summary(scan_result.get("a10_error_handling_summary", {}))
    if owasp_map or owasp_assess:
        try:
            attach_owasp_metadata(scan_result)
        except OWASPMappingError as exc:
            console.print(f"[red]OWASP mapping error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_owasp_summary(scan_result.get("owasp_top10_summary", {}), scan_result.get("owasp_top10_mapped_items", []))
    if owasp_assess:
        try:
            attach_owasp_assessment(scan_result)
        except OWASPAssessmentRulesError as exc:
            console.print(f"[red]OWASP assessment error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_owasp_assessment_summary(scan_result.get("owasp_assessment_summary", {}), scan_result.get("owasp_category_results", []))
    if owasp_report:
        try:
            if not scan_result.get("owasp_assessment_summary", {}).get("enabled"):
                attach_owasp_metadata(scan_result)
                attach_owasp_assessment(scan_result)
            report_path = _generate_owasp_markdown_report(scan_result)
        except (OWASPMappingError, OWASPAssessmentRulesError) as exc:
            console.print(f"[red]OWASP report error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        console.print(f"[bold]OWASP Markdown report saved:[/bold] {report_path}")
    _print_findings(scan_result["findings"])

    if json_report or html_report:
        enrich_findings_with_remediation(scan_result["findings"])

    if json_report:
        report_path = save_json_report(
            scan_result=scan_result,
            scanner_name="VulScan",
            scanner_version=__version__,
            scan_start_time=scan_start_time,
            scan_end_time=scan_end_time,
        )
        console.print(f"[bold]JSON report saved:[/bold] {report_path}")

    if html_report:
        report_path = save_html_report(
            scan_result=scan_result,
            scanner_name="VulScan",
            scanner_version=__version__,
            scan_start_time=scan_start_time,
            scan_end_time=scan_end_time,
        )
        console.print(f"HTML report saved: {report_path}")


@app.command("recon")
def recon(
    targets_file: Annotated[
        Path | None,
        typer.Option(
            "--targets-file",
            help="Local newline-delimited recon targets file.",
        ),
    ] = None,
    targets: Annotated[
        str | None,
        typer.Option(
            "--targets",
            help="Optional comma-separated manual recon targets.",
        ),
    ] = None,
    bug_bounty_scope: Annotated[
        Path | None,
        typer.Option(
            "--scope-file",
            "--bug-bounty-scope",
            help="Path to a local Program Scope JSON file. Legacy --bug-bounty-scope name is retained for compatibility.",
        ),
    ] = None,
    enforce_scope: Annotated[
        bool,
        typer.Option(
            "--enforce-scope",
            help="Skip out-of-scope targets before probing.",
        ),
    ] = False,
    request_delay: Annotated[
        float,
        typer.Option(
            "--request-delay",
            help="Seconds to wait between recon requests.",
        ),
    ] = 1.0,
    max_requests_per_minute: Annotated[
        int,
        typer.Option(
            "--max-requests-per-minute",
            help="Maximum safe recon requests per minute.",
        ),
    ] = 30,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            help="Per-request timeout in seconds.",
        ),
    ] = 5.0,
    max_redirects: Annotated[
        int,
        typer.Option(
            "--max-redirects",
            help="Maximum redirects to follow.",
        ),
    ] = 5,
    json_report: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Save recon results to a JSON report in reports/recon.",
        ),
    ] = False,
    html_report: Annotated[
        bool,
        typer.Option(
            "--html",
            help="Save recon results to an HTML report in reports/recon.",
        ),
    ] = False,
) -> None:
    """Run Recon Intelligence against provided/imported authorised targets only."""
    console.print(Panel.fit(f"VulScan version {__version__}", style="bold cyan"))
    console.print("[bold]Recon Intelligence[/bold]")
    console.print("[yellow]Safe usage warning:[/yellow] Recon only probes provided targets. No brute forcing, wordlists, or third-party lookups are used.")

    raw_targets: list[str] = []
    input_source = "manual"
    if targets_file is not None:
        try:
            raw_targets.extend(load_recon_targets(targets_file))
        except BugBountyReconError as exc:
            console.print(f"[red]Recon input error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        input_source = str(targets_file)
    if targets:
        raw_targets.extend([target.strip() for target in targets.split(",") if target.strip()])
        if input_source == "manual":
            input_source = "cli"
    if not raw_targets:
        console.print("[red]No recon targets were provided. Use --targets-file or --targets.[/red]")
        raise typer.Exit(code=1)

    try:
        recon_payload = run_bug_bounty_recon(
            raw_targets=raw_targets,
            scope_file=bug_bounty_scope,
            enforce_scope=enforce_scope,
            request_delay=request_delay,
            max_requests_per_minute=max_requests_per_minute,
            timeout=timeout,
            max_redirects=max_redirects,
            input_source=input_source,
        )
    except (BugBountyScopeError, BugBountyReconError) as exc:
        console.print(f"[red]Recon intelligence error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    summary = recon_payload["bug_bounty_recon"]
    _print_bug_bounty_recon_summary(summary)
    _print_bug_bounty_recon_results(recon_payload["bug_bounty_recon_results"])
    _print_bug_bounty_recon_skipped(recon_payload["bug_bounty_recon_skipped"])
    _print_findings(recon_payload["findings"])

    scan_start_time = datetime.fromisoformat(summary["started_at"])
    scan_end_time = datetime.fromisoformat(summary["completed_at"])
    scan_result = {
        "host": "bug-bounty-recon",
        "resolved_ip": "",
        "scan_mode": "bug-bounty-recon",
        "duration_seconds": round((scan_end_time - scan_start_time).total_seconds(), 3),
        "open_ports": [],
        "findings": recon_payload["findings"],
        "bug_bounty_recon": summary,
        "bug_bounty_recon_results": recon_payload["bug_bounty_recon_results"],
        "bug_bounty_recon_skipped": recon_payload["bug_bounty_recon_skipped"],
        "demo_mode": False,
        "demo_notice": "",
    }
    if json_report:
        report_path = save_json_report(
            scan_result=scan_result,
            scanner_name="VulScan",
            scanner_version=__version__,
            scan_start_time=scan_start_time,
            scan_end_time=scan_end_time,
            reports_dir=RECON_REPORTS_DIR,
        )
        console.print(f"[bold]JSON recon report saved:[/bold] {report_path}")
    if html_report:
        report_path = save_html_report(
            scan_result=scan_result,
            scanner_name="VulScan",
            scanner_version=__version__,
            scan_start_time=scan_start_time,
            scan_end_time=scan_end_time,
            reports_dir=RECON_REPORTS_DIR,
        )
        console.print(f"HTML recon report saved: {report_path}")


@app.command("endpoints")
def endpoints(
    urls_file: Annotated[
        Path,
        typer.Option(
            "--urls-file",
            help="Local newline-delimited URL/path file.",
        ),
    ],
    base_url: Annotated[
        str | None,
        typer.Option(
            "--base-url",
            help="Base URL for path-only entries.",
        ),
    ] = None,
    bug_bounty_scope: Annotated[
        Path | None,
        typer.Option(
            "--scope-file",
            "--bug-bounty-scope",
            help="Path to a local Program Scope JSON file. Legacy --bug-bounty-scope name is retained for compatibility.",
        ),
    ] = None,
    enforce_scope: Annotated[
        bool,
        typer.Option(
            "--enforce-scope",
            help="Skip out-of-scope URLs before returning candidates.",
        ),
    ] = False,
    json_report: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Save endpoint discovery results to a JSON report in reports/endpoints.",
        ),
    ] = False,
    html_report: Annotated[
        bool,
        typer.Option(
            "--html",
            help="Save endpoint discovery results to an HTML report in reports/endpoints.",
        ),
    ] = False,
    owasp_map: Annotated[
        bool,
        typer.Option(
            "--owasp-map",
            help="Attach OWASP Top 10:2025 indicator mapping to endpoint candidates.",
        ),
    ] = False,
    owasp_assess: Annotated[
        bool,
        typer.Option(
            "--owasp-assess",
            help="Build OWASP Assessment Engine category results from endpoint candidates.",
        ),
    ] = False,
    owasp_report: Annotated[
        bool,
        typer.Option(
            "--owasp-report",
            help="Generate a unified Markdown-ready OWASP Assessment report from endpoint candidates.",
        ),
    ] = False,
    auth_profile: Annotated[
        Path | None,
        typer.Option(
            "--auth-profile",
            help="Redacted Session Profile JSON under data/auth_profiles for Authenticated Web Assessment context.",
        ),
    ] = None,
    classify_auth: Annotated[
        bool,
        typer.Option(
            "--classify-auth",
            help="Classify supplied endpoints for Auth-Required Endpoint signals without making requests.",
        ),
    ] = False,
    a04_checks: Annotated[
        bool,
        typer.Option(
            "--a04-checks",
            help="Run safe A04 Cryptographic Failures and transport security evidence checks on supplied URLs.",
        ),
    ] = False,
    a01_checks: Annotated[
        bool,
        typer.Option(
            "--a01-checks",
            help="Run safe A01 Broken Access Control candidate discovery and manual validation planning.",
        ),
    ] = False,
    a03_checks: Annotated[
        bool,
        typer.Option(
            "--a03-checks",
            help="Run safe A03 Software Supply Chain and component exposure checks from supplied/discovered URLs.",
        ),
    ] = False,
    a08_checks: Annotated[
        bool,
        typer.Option(
            "--a08-checks",
            help="Run safe A08 Software/Data Integrity indicator checks from supplied endpoint and parameter metadata.",
        ),
    ] = False,
    a05_checks: Annotated[
        bool,
        typer.Option(
            "--a05-checks",
            help="Run safe A05 Injection candidate and reflection analysis.",
        ),
    ] = False,
    safe_reflection: Annotated[
        bool,
        typer.Option(
            "--safe-reflection",
            help="Run limited harmless marker reflection observation for selected GET parameters.",
        ),
    ] = False,
    max_reflection_checks: Annotated[
        int,
        typer.Option(
            "--max-reflection-checks",
            min=0,
            help="Maximum harmless reflection observations when --safe-reflection is enabled.",
        ),
    ] = 10,
    request_delay: Annotated[
        float,
        typer.Option(
            "--request-delay",
            min=0.0,
            help="Delay in seconds between safe reflection requests.",
        ),
    ] = 1.0,
    a07_checks: Annotated[
        bool,
        typer.Option(
            "--a07-checks",
            help="Run safe A07 Authentication Failures and session indicator checks on supplied URLs.",
        ),
    ] = False,
    a10_checks: Annotated[
        bool,
        typer.Option(
            "--a10-checks",
            help="Run safe A10 Mishandling of Exceptional Conditions error-handling checks on supplied metadata.",
        ),
    ] = False,
    save_db: Annotated[
        bool,
        typer.Option(
            "--save-db",
            help="Accepted for workflow consistency; endpoint discovery reports are file-based in Version 18.2.",
        ),
    ] = False,
) -> None:
    """Run safe endpoint and parameter discovery from provided URL lists."""
    console.print(Panel.fit(f"VulScan version {__version__}", style="bold cyan"))
    console.print("[bold]Endpoint and Parameter Discovery[/bold]")
    console.print("[yellow]Safe usage warning:[/yellow] This command analyses supplied URLs only. It does not send requests, fuzz, submit forms, or run payloads.")
    try:
        raw_urls = load_url_list(urls_file)
        endpoint_payload = run_endpoint_discovery(
            raw_urls=raw_urls,
            base_url=base_url,
            scope_file=bug_bounty_scope,
            enforce_scope=enforce_scope,
            input_source=str(urls_file),
        )
    except (BugBountyScopeError, EndpointDiscoveryError) as exc:
        console.print(f"[red]Endpoint discovery error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    summary = endpoint_payload["endpoint_discovery"]
    _print_endpoint_discovery_summary(summary)
    _print_endpoint_results(endpoint_payload["endpoint_results"])
    _print_parameter_results(endpoint_payload["parameter_results"])
    _print_endpoint_skipped(endpoint_payload["endpoint_skipped"])
    _print_findings(endpoint_payload["findings"])
    if save_db:
        console.print("[yellow]--save-db was accepted, but Version 18.2 stores endpoint discovery output in reports only.[/yellow]")

    scan_start_time = datetime.fromisoformat(summary["started_at"])
    scan_end_time = datetime.fromisoformat(summary["completed_at"])
    scan_result = {
        "host": "endpoint-discovery",
        "resolved_ip": "",
        "scan_mode": "endpoint-discovery",
        "duration_seconds": round((scan_end_time - scan_start_time).total_seconds(), 3),
        "open_ports": [],
        "findings": endpoint_payload["findings"],
        "endpoint_discovery": summary,
        "endpoint_results": endpoint_payload["endpoint_results"],
        "parameter_results": endpoint_payload["parameter_results"],
        "endpoint_skipped": endpoint_payload["endpoint_skipped"],
        "demo_mode": False,
        "demo_notice": "",
    }
    if auth_profile or classify_auth:
        try:
            profile = load_session_profile(auth_profile) if auth_profile else {}
            if profile:
                validation = validate_session_profile(profile)
                if not validation.get("valid"):
                    console.print(f"[red]Session Profile validation failed:[/red] {', '.join(validation.get('errors') or [])}")
                    raise typer.Exit(code=1)
                scan_result["auth_context_summary"] = build_auth_context(profile)
                scan_result["redaction_status"] = "redacted"
                boundary_results = []
                for endpoint in scan_result.get("endpoint_results", []):
                    url = str(endpoint.get("normalised_url") or endpoint.get("url") or "")
                    if url:
                        boundary_results.append(classify_auth_boundary(url, profile))
                scan_result["auth_boundary_results"] = boundary_results
            if classify_auth:
                classification = classify_auth_required_endpoints(scan_result.get("endpoint_results", []), profile)
                scan_result["auth_required_endpoint_classification"] = classification["auth_required_endpoint_classification"]
                scan_result["endpoint_results"] = classification["classified_endpoints"]
                _print_auth_endpoint_classification(scan_result["auth_required_endpoint_classification"])
        except SessionProfileError as exc:
            console.print(f"[red]Session Profile error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
    if a01_checks:
        try:
            attach_a01_access_control(scan_result)
        except A01RulesError as exc:
            console.print(f"[red]A01 Broken Access Control error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a01_access_control_summary(scan_result.get("a01_access_control_summary", {}))
    if a03_checks:
        try:
            attach_a03_supply_chain(scan_result)
        except A03RulesError as exc:
            console.print(f"[red]A03 Software Supply Chain error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a03_supply_chain_summary(scan_result.get("a03_supply_chain_summary", {}))
    if a08_checks:
        try:
            attach_a08_integrity(scan_result)
        except A08RulesError as exc:
            console.print(f"[red]A08 Software/Data Integrity error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a08_integrity_summary(scan_result.get("a08_integrity_summary", {}))
    if a04_checks:
        try:
            attach_a04_crypto(scan_result, collect_tls=False)
        except A04RulesError as exc:
            console.print(f"[red]A04 Cryptographic Failures error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a04_crypto_summary(scan_result.get("a04_crypto_summary", {}))
    if a05_checks:
        try:
            attach_a05_injection(scan_result, safe_reflection=safe_reflection, max_reflection_checks=max_reflection_checks, request_delay=request_delay)
        except A05RulesError as exc:
            console.print(f"[red]A05 Injection error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a05_injection_summary(scan_result.get("a05_injection_summary", {}))
    if a07_checks:
        try:
            attach_a07_authentication(scan_result)
        except A07RulesError as exc:
            console.print(f"[red]A07 Authentication Failures error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a07_authentication_summary(scan_result.get("a07_authentication_summary", {}))
    if a10_checks:
        try:
            attach_a10_error_handling(scan_result)
        except A10RulesError as exc:
            console.print(f"[red]A10 Mishandling of Exceptional Conditions error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a10_error_handling_summary(scan_result.get("a10_error_handling_summary", {}))
    if owasp_map or owasp_assess:
        try:
            attach_owasp_metadata(scan_result)
        except OWASPMappingError as exc:
            console.print(f"[red]OWASP mapping error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_owasp_summary(scan_result.get("owasp_top10_summary", {}), scan_result.get("owasp_top10_mapped_items", []))
    if owasp_assess:
        try:
            attach_owasp_assessment(scan_result)
        except OWASPAssessmentRulesError as exc:
            console.print(f"[red]OWASP assessment error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_owasp_assessment_summary(scan_result.get("owasp_assessment_summary", {}), scan_result.get("owasp_category_results", []))
    if owasp_report:
        try:
            if not scan_result.get("owasp_assessment_summary", {}).get("enabled"):
                attach_owasp_metadata(scan_result)
                attach_owasp_assessment(scan_result)
            report_path = _generate_owasp_markdown_report(scan_result)
        except (OWASPMappingError, OWASPAssessmentRulesError) as exc:
            console.print(f"[red]OWASP report error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        console.print(f"[bold]OWASP Markdown report saved:[/bold] {report_path}")
    if json_report:
        report_path = save_json_report(
            scan_result=scan_result,
            scanner_name="VulScan",
            scanner_version=__version__,
            scan_start_time=scan_start_time,
            scan_end_time=scan_end_time,
            reports_dir=ENDPOINT_REPORTS_DIR,
        )
        console.print(f"[bold]JSON endpoint report saved:[/bold] {report_path}")
    if html_report:
        report_path = save_html_report(
            scan_result=scan_result,
            scanner_name="VulScan",
            scanner_version=__version__,
            scan_start_time=scan_start_time,
            scan_end_time=scan_end_time,
            reports_dir=ENDPOINT_REPORTS_DIR,
        )
        console.print(f"HTML endpoint report saved: {report_path}")


@app.command("validate")
def validate(
    targets_file: Annotated[
        Path | None,
        typer.Option("--targets-file", help="Local safe validation targets JSON file."),
    ] = None,
    url: Annotated[
        str | None,
        typer.Option("--url", help="Optional single URL to validate."),
    ] = None,
    candidate_type: Annotated[
        str,
        typer.Option("--candidate-type", help="Candidate type for --url."),
    ] = "manual",
    parameter: Annotated[
        str | None,
        typer.Option("--parameter", help="Optional query parameter for parameter-specific checks."),
    ] = None,
    bug_bounty_scope: Annotated[
        Path | None,
        typer.Option("--scope-file", "--bug-bounty-scope", help="Path to a local Program Scope JSON file. Legacy option name is retained for compatibility."),
    ] = None,
    enforce_scope: Annotated[
        bool,
        typer.Option("--enforce-scope", help="Skip out-of-scope targets before making requests."),
    ] = False,
    request_delay: Annotated[
        float,
        typer.Option("--request-delay", help="Seconds to wait between safe validation requests."),
    ] = 1.0,
    max_requests_per_minute: Annotated[
        int,
        typer.Option("--max-requests-per-minute", help="Maximum safe validation requests per minute."),
    ] = 20,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="Per-request timeout in seconds."),
    ] = 5.0,
    max_validation_requests: Annotated[
        int,
        typer.Option("--max-validation-requests", help="Maximum safe validation requests for this run."),
    ] = 100,
    checks: Annotated[
        str | None,
        typer.Option("--checks", help="Comma-separated safe checks to run."),
    ] = None,
    safe_active_confirm: Annotated[
        bool,
        typer.Option("--safe-active-confirm/--no-safe-active-confirm", help="Required acknowledgement for safe authorised validation."),
    ] = True,
    json_report: Annotated[
        bool,
        typer.Option("--json", help="Save validation results to a JSON report in reports/validation."),
    ] = False,
    html_report: Annotated[
        bool,
        typer.Option("--html", help="Save validation results to an HTML report in reports/validation."),
    ] = False,
    owasp_assess: Annotated[
        bool,
        typer.Option(
            "--owasp-assess",
            help="Build OWASP Assessment Engine category results from validation evidence.",
        ),
    ] = False,
    a04_checks: Annotated[
        bool,
        typer.Option(
            "--a04-checks",
            help="Run safe A04 Cryptographic Failures and transport security evidence checks on validation targets.",
        ),
    ] = False,
    a01_checks: Annotated[
        bool,
        typer.Option(
            "--a01-checks",
            help="Run safe A01 Broken Access Control candidate discovery and manual validation planning.",
        ),
    ] = False,
    a08_checks: Annotated[
        bool,
        typer.Option(
            "--a08-checks",
            help="Run safe A08 Software/Data Integrity indicator checks from validation target metadata.",
        ),
    ] = False,
    a05_checks: Annotated[
        bool,
        typer.Option(
            "--a05-checks",
            help="Run safe A05 Injection candidate and reflection analysis.",
        ),
    ] = False,
    safe_reflection: Annotated[
        bool,
        typer.Option(
            "--safe-reflection",
            help="Run limited harmless marker reflection observation for selected GET parameters.",
        ),
    ] = False,
    max_reflection_checks: Annotated[
        int,
        typer.Option(
            "--max-reflection-checks",
            min=0,
            help="Maximum harmless reflection observations when --safe-reflection is enabled.",
        ),
    ] = 10,
    a07_checks: Annotated[
        bool,
        typer.Option(
            "--a07-checks",
            help="Run safe A07 Authentication Failures and session indicator checks on validation targets.",
        ),
    ] = False,
    a10_checks: Annotated[
        bool,
        typer.Option(
            "--a10-checks",
            help="Run safe A10 Mishandling of Exceptional Conditions error-handling checks on validation observations.",
        ),
    ] = False,
    save_db: Annotated[
        bool,
        typer.Option("--save-db", help="Accepted for workflow consistency; validation reports are file-based in Version 18.4."),
    ] = False,
) -> None:
    """Run limited non-destructive safe active validation checks."""
    console.print(Panel.fit(f"VulScan version {__version__}", style="bold cyan"))
    console.print("[bold]Safe Active Validation[/bold]")
    console.print("[yellow]Safety:[/yellow] Indicator only. Manual validation required. No exploitability confirmed.")
    targets: list[dict[str, Any]] = []
    try:
        if targets_file is not None:
            targets.extend(load_validation_targets(targets_file))
        if url:
            targets.append({"url": url, "candidate_type": candidate_type, "parameter": parameter or "", "source": "cli"})
        if not targets:
            console.print("[red]No validation targets were provided. Use --targets-file or --url.[/red]")
            raise typer.Exit(code=1)
        validation_payload = run_safe_active_validation(
            targets=targets,
            scope_file=bug_bounty_scope,
            enforce_scope=enforce_scope,
            checks=[item.strip() for item in checks.split(",") if item.strip()] if checks else None,
            request_delay=request_delay,
            max_requests_per_minute=max_requests_per_minute,
            timeout=timeout,
            max_validation_requests=max_validation_requests,
            safe_active_confirm=safe_active_confirm,
        )
    except (BugBountyScopeError, SafeActiveValidationError) as exc:
        console.print(f"[red]Safe validation error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    summary = validation_payload["safe_active_validation"]
    _print_safe_validation_summary(summary)
    _print_safe_validation_results(validation_payload["safe_active_validation_results"])
    _print_safe_validation_skipped(validation_payload["safe_active_validation_skipped"])
    _print_findings(validation_payload["findings"])
    if save_db:
        console.print("[yellow]--save-db was accepted, but Version 18.4 stores safe validation output in reports only.[/yellow]")

    scan_start_time = datetime.now().astimezone()
    scan_end_time = datetime.now().astimezone()
    scan_result = {
        "host": "safe-active-validation",
        "resolved_ip": "",
        "scan_mode": "safe-active-validation",
        "duration_seconds": 0,
        "open_ports": [],
        "findings": validation_payload["findings"],
        "safe_active_validation": summary,
        "safe_active_validation_results": validation_payload["safe_active_validation_results"],
        "safe_active_validation_skipped": validation_payload["safe_active_validation_skipped"],
        "demo_mode": False,
        "demo_notice": "",
    }
    if a01_checks:
        try:
            attach_a01_access_control(scan_result)
        except A01RulesError as exc:
            console.print(f"[red]A01 Broken Access Control error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a01_access_control_summary(scan_result.get("a01_access_control_summary", {}))
    if a08_checks:
        try:
            attach_a08_integrity(scan_result)
        except A08RulesError as exc:
            console.print(f"[red]A08 Software/Data Integrity error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a08_integrity_summary(scan_result.get("a08_integrity_summary", {}))
    if a04_checks:
        try:
            attach_a04_crypto(scan_result, collect_tls=False)
        except A04RulesError as exc:
            console.print(f"[red]A04 Cryptographic Failures error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a04_crypto_summary(scan_result.get("a04_crypto_summary", {}))
    if a05_checks:
        try:
            attach_a05_injection(scan_result, safe_reflection=safe_reflection, max_reflection_checks=max_reflection_checks, request_delay=request_delay)
        except A05RulesError as exc:
            console.print(f"[red]A05 Injection error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a05_injection_summary(scan_result.get("a05_injection_summary", {}))
    if a07_checks:
        try:
            attach_a07_authentication(scan_result)
        except A07RulesError as exc:
            console.print(f"[red]A07 Authentication Failures error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a07_authentication_summary(scan_result.get("a07_authentication_summary", {}))
    if a10_checks:
        try:
            attach_a10_error_handling(scan_result)
        except A10RulesError as exc:
            console.print(f"[red]A10 Mishandling of Exceptional Conditions error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_a10_error_handling_summary(scan_result.get("a10_error_handling_summary", {}))
    if owasp_assess:
        try:
            attach_owasp_metadata(scan_result)
            attach_owasp_assessment(scan_result)
        except (OWASPMappingError, OWASPAssessmentRulesError) as exc:
            console.print(f"[red]OWASP assessment error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _print_owasp_summary(scan_result.get("owasp_top10_summary", {}), scan_result.get("owasp_top10_mapped_items", []))
        _print_owasp_assessment_summary(scan_result.get("owasp_assessment_summary", {}), scan_result.get("owasp_category_results", []))
    if json_report:
        report_path = save_json_report(scan_result=scan_result, scanner_name="VulScan", scanner_version=__version__, scan_start_time=scan_start_time, scan_end_time=scan_end_time, reports_dir=VALIDATION_REPORTS_DIR)
        console.print(f"[bold]JSON validation report saved:[/bold] {report_path}")
    if html_report:
        report_path = save_html_report(scan_result=scan_result, scanner_name="VulScan", scanner_version=__version__, scan_start_time=scan_start_time, scan_end_time=scan_end_time, reports_dir=VALIDATION_REPORTS_DIR)
        console.print(f"HTML validation report saved: {report_path}")


@app.command()
def history(
    target: Annotated[
        str,
        typer.Option(
            "--target",
            "-t",
            help="Target to show scan history for.",
        ),
    ],
    limit: Annotated[
        int,
        typer.Option(
            "--limit",
            "-l",
            min=1,
            help="Maximum number of history rows to display.",
        ),
    ] = 10,
) -> None:
    """Show saved scan history for a target."""
    database_path = get_database_path()
    console.print(f"[bold]Database path:[/bold] {database_path}")
    console.print(f"[bold]Target:[/bold] {target}")

    if not database_exists():
        console.print(
            "[yellow]No scan history database exists yet. Run a scan with --save-db to create data\\vulscan.db.[/yellow]"
        )
        return

    missing_tables = get_missing_required_tables()
    if missing_tables:
        missing = ", ".join(sorted(missing_tables))
        console.print(
            f"[yellow]Scan history database is missing required tables ({missing}). Run a scan with --save-db to initialise data\\vulscan.db.[/yellow]"
        )
        return

    rows = get_scan_history(target, limit=limit)
    if not rows:
        console.print(f"[yellow]No scan history found for target:[/yellow] {target}")
        return

    console.print(f"[bold]Scans shown:[/bold] {len(rows)}")

    table = Table(title=f"Scan History: {target}")
    table.add_column("Scan Date/Time")
    table.add_column("Target")
    table.add_column("Resolved IP")
    table.add_column("Duration", justify="right")
    table.add_column("Open Ports", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Highest Risk", justify="right")
    table.add_column("Risk Label")

    for row in rows:
        table.add_row(
            str(row["scan_start_time"]),
            str(row["target"]),
            str(row["resolved_ip"]),
            str(row["duration_seconds"]),
            str(row["total_open_ports"]),
            str(row["total_findings"]),
            str(row["highest_risk_score"]),
            str(row["highest_risk_label"]),
        )

    console.print(table)
    summaries = get_latest_scan_finding_summaries(target)
    if summaries is None:
        return

    if sum(summaries["severity"].values()) == 0:
        console.print("[yellow]Latest scan has no findings.[/yellow]")
        return

    _print_count_summary("Latest Scan Severity Summary", summaries["severity"])
    _print_count_summary("Latest Scan Risk Label Summary", summaries["risk_label"])
    remediation_counts = get_remediation_summary(target)
    if sum(remediation_counts.values()) > 0:
        _print_count_summary("Latest Target Remediation Summary", remediation_counts)


@app.command()
def diff(
    target: Annotated[
        str,
        typer.Option(
            "--target",
            "-t",
            help="Target to compare the latest two saved scans for.",
        ),
    ],
) -> None:
    """Compare the latest two saved scans for a target."""
    result = compare_latest_two_scans(target)

    console.print(f"[bold]Database path:[/bold] {result['database_path']}")
    console.print(f"[bold]Target:[/bold] {target}")

    if result["status"] != "ok":
        if result["status"] == "missing_tables":
            missing = ", ".join(result.get("missing_tables", []))
            console.print(f"[yellow]{result['message']} Missing tables: {missing}[/yellow]")
        else:
            console.print(f"[yellow]{result['message']}[/yellow]")
        return

    previous_scan = result["previous_scan"]
    latest_scan = result["latest_scan"]
    console.print(f"[bold]Previous scan date/time:[/bold] {previous_scan['scan_start_time']}")
    console.print(f"[bold]Latest scan date/time:[/bold] {latest_scan['scan_start_time']}")
    console.print(f"[bold]Previous total findings:[/bold] {result['previous_total_findings']}")
    console.print(f"[bold]Latest total findings:[/bold] {result['latest_total_findings']}")
    console.print(f"[bold]Previous total risk score:[/bold] {result['previous_total_risk_score']}")
    console.print(f"[bold]Latest total risk score:[/bold] {result['latest_total_risk_score']}")
    console.print(f"[bold]Risk trend:[/bold] {result['risk_trend']}")

    summary = Table(title="Scan Diff Summary")
    summary.add_column("Category")
    summary.add_column("Count", justify="right")
    summary.add_row("New findings", str(len(result["new_findings"])))
    summary.add_row("Fixed findings", str(len(result["fixed_findings"])))
    summary.add_row("Unchanged findings", str(len(result["unchanged_findings"])))
    summary.add_row("Changed risk findings", str(len(result["changed_risk_findings"])))
    console.print(summary)

    if (
        not result["new_findings"]
        and not result["fixed_findings"]
        and not result["changed_risk_findings"]
    ):
        console.print("[green]No changes were detected between the latest two scans.[/green]")

    _print_diff_findings("New Findings", result["new_findings"])
    _print_diff_findings("Fixed Findings", result["fixed_findings"])
    _print_diff_findings("Changed Risk Findings", result["changed_risk_findings"])


@app.command()
def assets(
    target: Annotated[
        str | None,
        typer.Option(
            "--target",
            "-t",
            help="Optional target to show asset details for.",
        ),
    ] = None,
) -> None:
    """Show saved asset inventory."""
    console.print(f"[bold]Database path:[/bold] {get_database_path()}")
    if target:
        console.print(f"[bold]Target:[/bold] {target}")

    if not database_exists():
        console.print(
            "[yellow]No asset inventory database exists yet. Run a scan with --save-db first.[/yellow]"
        )
        return

    missing_tables = get_missing_required_tables()
    if missing_tables:
        missing = ", ".join(sorted(missing_tables))
        console.print(
            f"[yellow]Scan history database is missing required tables ({missing}). Run a scan with --save-db first.[/yellow]"
        )
        return

    rows = get_assets(target=target)
    if not rows and target:
        console.print(f"[yellow]No asset record exists for target:[/yellow] {target}")
        return
    if not rows:
        console.print("[yellow]No saved assets are available. Run a scan with --save-db first.[/yellow]")
        return

    _print_assets_table(rows)
    if target:
        services = get_asset_services(str(rows[0]["asset_id"]))
        if services:
            _print_asset_services_table(services)
        else:
            console.print("[green]Detected services:[/green] None recorded for this asset.")


@remediation_app.command("list")
def remediation_list(
    target: Annotated[
        str,
        typer.Option(
            "--target",
            "-t",
            help="Target to list remediation status for.",
        ),
    ],
) -> None:
    """List remediation status records for a target."""
    console.print(f"[bold]Database path:[/bold] {get_database_path()}")
    console.print(f"[bold]Target:[/bold] {target}")

    if not database_exists():
        console.print(
            "[yellow]No scan history database exists yet. Run a scan with --save-db first.[/yellow]"
        )
        return

    missing_tables = get_missing_required_tables()
    if missing_tables:
        missing = ", ".join(sorted(missing_tables))
        console.print(
            f"[yellow]Scan history database is missing required tables ({missing}). Run a scan with --save-db first.[/yellow]"
        )
        return

    rows = get_remediation_list(target)
    if not rows:
        console.print(f"[yellow]No remediation records found for target:[/yellow] {target}")
        return

    table = Table(title=f"Remediation Status: {target}")
    table.add_column("Fingerprint")
    table.add_column("Finding ID")
    table.add_column("Title")
    table.add_column("Status")
    table.add_column("Owner")
    table.add_column("Last Seen")
    table.add_column("Risk Label")
    table.add_column("Host")
    table.add_column("Port", justify="right")
    table.add_column("Service")

    for row in rows:
        table.add_row(
            str(row.get("fingerprint_short") or ""),
            str(row.get("finding_id") or ""),
            str(row.get("title") or ""),
            str(row.get("status") or ""),
            str(row.get("owner") or ""),
            str(row.get("last_seen") or ""),
            str(row.get("risk_label") or ""),
            str(row.get("affected_host") or ""),
            str(row.get("affected_port") or ""),
            str(row.get("service") or ""),
        )
    console.print(table)


@remediation_app.command("update")
def remediation_update(
    fingerprint: Annotated[
        str,
        typer.Option(
            "--fingerprint",
            "-f",
            help="Full or unique short remediation fingerprint.",
        ),
    ],
    status: Annotated[
        str,
        typer.Option(
            "--status",
            "-s",
            help="New remediation status.",
        ),
    ],
    owner: Annotated[
        str | None,
        typer.Option(
            "--owner",
            "-o",
            help="Optional remediation owner.",
        ),
    ] = None,
    note: Annotated[
        str | None,
        typer.Option(
            "--note",
            "-n",
            help="Optional remediation note.",
        ),
    ] = None,
) -> None:
    """Update a remediation status record."""
    result = update_remediation_status(
        fingerprint=fingerprint,
        status=status,
        owner=owner,
        note=note,
    )

    if result["status"] == "updated":
        console.print(f"[green]{result['message']}[/green]")
        return

    if result["status"] == "invalid_status":
        console.print(f"[red]{result['message']}[/red]")
        raise typer.Exit(code=1)

    console.print(f"[yellow]{result['message']}[/yellow]")


@remediation_app.command("summary")
def remediation_summary(
    target: Annotated[
        str,
        typer.Option(
            "--target",
            "-t",
            help="Target to summarize remediation status for.",
        ),
    ],
) -> None:
    """Show remediation status counts for a target."""
    console.print(f"[bold]Database path:[/bold] {get_database_path()}")
    console.print(f"[bold]Target:[/bold] {target}")

    if not database_exists():
        console.print(
            "[yellow]No scan history database exists yet. Run a scan with --save-db first.[/yellow]"
        )
        return

    missing_tables = get_missing_required_tables()
    if missing_tables:
        missing = ", ".join(sorted(missing_tables))
        console.print(
            f"[yellow]Scan history database is missing required tables ({missing}). Run a scan with --save-db first.[/yellow]"
        )
        return

    counts = get_remediation_summary(target)
    if sum(counts.values()) == 0:
        console.print(f"[yellow]No remediation records found for target:[/yellow] {target}")
        return

    _print_count_summary("Remediation Summary", counts)


@export_app.command("assets")
def export_assets_command(
    format_name: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Export format: csv or json.",
        ),
    ] = "csv",
) -> None:
    """Export saved asset inventory."""
    _print_export_result(export_assets(format_name))


@export_app.command("history")
def export_history_command(
    target: Annotated[
        str | None,
        typer.Option(
            "--target",
            "-t",
            help="Optional target to export history for.",
        ),
    ] = None,
    format_name: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Export format: csv or json.",
        ),
    ] = "csv",
) -> None:
    """Export saved scan history."""
    _print_export_result(export_history(format_name=format_name, target=target))


@export_app.command("findings")
def export_findings_command(
    target: Annotated[
        str | None,
        typer.Option(
            "--target",
            "-t",
            help="Optional target to export findings for.",
        ),
    ] = None,
    format_name: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Export format: csv or json.",
        ),
    ] = "csv",
) -> None:
    """Export saved findings."""
    _print_export_result(export_findings(format_name=format_name, target=target))


@export_app.command("prioritisation")
def export_prioritisation_command(
    target: Annotated[
        str | None,
        typer.Option(
            "--target",
            "-t",
            help="Optional target to export prioritisation data for.",
        ),
    ] = None,
    format_name: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Export format: csv or json.",
        ),
    ] = "csv",
) -> None:
    """Export saved prioritisation dashboard fields."""
    _print_export_result(export_prioritisation(format_name=format_name, target=target))


@export_app.command("remediation")
def export_remediation_command(
    target: Annotated[
        str | None,
        typer.Option(
            "--target",
            "-t",
            help="Optional target to export remediation records for.",
        ),
    ] = None,
    format_name: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Export format: csv or json.",
        ),
    ] = "csv",
) -> None:
    """Export saved remediation status records."""
    _print_export_result(export_remediation(format_name=format_name, target=target))


def _print_findings(findings: list[dict[str, Any]]) -> None:
    if not findings:
        console.print("[green]Findings:[/green] None found.")
        return

    source_order = [
        "port_scan",
        "http_audit",
        "tls_audit",
        "web_crawler",
        "web_header_audit",
        "web_cookie_audit",
        "web_form_audit",
        "web_scope",
        "web_rate_limit",
        "web_robots",
        "web_sitemap",
        "web_passive_summary",
        "bug_bounty_scope",
        "bug_bounty_recon",
        "vuln_intel",
        "asset_criticality",
        "prioritisation_report",
        "ssh_audit",
        "package_audit",
        "ssh_hardening",
        "linux_config_audit",
        "windows_audit",
        "windows_demo",
        "windows_security_audit",
    ]
    grouped: dict[str, list[dict[str, Any]]] = {source: [] for source in source_order}
    grouped["other"] = []
    for finding in findings:
        source = str(finding.get("source") or "other")
        if source not in grouped:
            source = "other"
        grouped[source].append(finding)

    for source in source_order + ["other"]:
        source_findings = grouped.get(source, [])
        if not source_findings:
            continue
        table = Table(title=f"Findings - {source}")
        table.add_column("Risk", justify="right")
        table.add_column("Risk Label")
        table.add_column("Severity")
        table.add_column("Title")
        table.add_column("Category")
        table.add_column("Affected")
        table.add_column("Evidence")
        table.add_column("Recommendation")

        for finding in source_findings:
            table.add_row(
                str(finding["risk_score"]),
                finding["risk_label"],
                finding["severity"],
                finding["title"],
                finding["category"],
                _affected_summary(finding),
                finding["evidence"],
                finding["recommendation"],
            )

        console.print(table)


def _print_asset_context(asset_context: dict[str, Any]) -> None:
    if not asset_context or not asset_context.get("enabled"):
        return

    table = Table(title="Asset Context")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Target", asset_context.get("target")),
        ("Criticality", asset_context.get("criticality")),
        ("Source", asset_context.get("criticality_source")),
        ("Environment", asset_context.get("environment")),
        ("Business owner", asset_context.get("business_owner")),
        ("Tags", ", ".join(asset_context.get("tags") or [])),
    ]
    for label, value in rows:
        table.add_row(label, "" if value is None else str(value))
    console.print(table)


def _print_bug_bounty_scope_summary(scope_summary: dict[str, Any]) -> None:
    if not scope_summary or not scope_summary.get("enabled"):
        return

    table = Table(title="Program Scope")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Program", scope_summary.get("program_name")),
        ("Program ID", scope_summary.get("program_id")),
        ("Platform", scope_summary.get("platform")),
        ("Scope version", scope_summary.get("scope_version")),
        ("Target", scope_summary.get("target")),
        ("In scope", str(bool(scope_summary.get("target_in_scope")))),
        ("Reason", scope_summary.get("scope_decision_reason")),
        ("Matched rule", scope_summary.get("matched_rule")),
    ]
    for label, value in rows:
        table.add_row(label, "" if value is None else str(value))
    console.print(table)


def _print_bug_bounty_recon_summary(summary: dict[str, Any]) -> None:
    table = Table(title="Recon Intelligence Summary")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Program", summary.get("program_name") or ""),
        ("Input targets", summary.get("input_targets_count")),
        ("Normalised targets", summary.get("normalised_targets_count")),
        ("Probe candidates", summary.get("probe_candidates_count")),
        ("Probed", summary.get("probed_count")),
        ("Live", summary.get("live_count")),
        ("Errors", summary.get("error_count")),
        ("Skipped", summary.get("skipped_count")),
        ("Technologies", ", ".join(summary.get("technologies_observed") or [])),
    ]
    for label, value in rows:
        table.add_row(label, "" if value is None else str(value))
    console.print(table)


def _print_bug_bounty_recon_results(results: list[dict[str, Any]]) -> None:
    if not results:
        console.print("[yellow]Recon results:[/yellow] No targets were probed.")
        return
    table = Table(title="Recon Results")
    table.add_column("Probe URL")
    table.add_column("Status")
    table.add_column("Title")
    table.add_column("Server")
    table.add_column("Tech")
    table.add_column("Time", justify="right")
    for result in results:
        technologies = ", ".join(str(hint.get("name") or "") for hint in result.get("technology_hints", []) if hint.get("name"))
        table.add_row(
            str(result.get("probe_url") or ""),
            str(result.get("status_code") or result.get("error_code") or ""),
            str(result.get("page_title") or "")[:60],
            str(result.get("server_header") or "")[:40],
            technologies[:50],
            f"{result.get('response_time_ms') or 0} ms",
        )
    console.print(table)


def _print_bug_bounty_recon_skipped(skipped: list[dict[str, Any]]) -> None:
    if not skipped:
        return
    table = Table(title="Skipped Recon Targets")
    table.add_column("Target")
    table.add_column("Probe URL")
    table.add_column("Reason")
    table.add_column("Scope Reason")
    for item in skipped:
        table.add_row(
            str(item.get("target") or ""),
            str(item.get("probe_url") or ""),
            str(item.get("reason") or ""),
            str(item.get("scope_reason") or ""),
        )
    console.print(table)


def _print_endpoint_discovery_summary(summary: dict[str, Any]) -> None:
    table = Table(title="Endpoint Discovery Summary")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Program", summary.get("program_name") or ""),
        ("Input URLs", summary.get("input_urls_count")),
        ("Normalised URLs", summary.get("normalised_urls_count")),
        ("Deduplicated URLs", summary.get("deduplicated_urls_count")),
        ("In scope", summary.get("in_scope_urls_count")),
        ("Out of scope", summary.get("out_of_scope_urls_count")),
        ("Skipped", summary.get("skipped_urls_count")),
        ("With parameters", summary.get("endpoints_with_parameters_count")),
        ("Interesting parameters", summary.get("interesting_parameters_count")),
        ("High interest", summary.get("high_interest_count")),
        ("Medium interest", summary.get("medium_interest_count")),
    ]
    for label, value in rows:
        table.add_row(label, "" if value is None else str(value))
    console.print(table)


def _print_endpoint_results(results: list[dict[str, Any]]) -> None:
    high_results = [item for item in results if item.get("candidate_label") == "High Interest"]
    if not high_results:
        console.print("[yellow]Top high-interest endpoints:[/yellow] None identified.")
        return
    table = Table(title="Top High-Interest Endpoints")
    table.add_column("URL")
    table.add_column("Category")
    table.add_column("Score", justify="right")
    table.add_column("Label")
    table.add_column("Reasons")
    for item in sorted(high_results, key=lambda value: int(value.get("candidate_score") or 0), reverse=True)[:10]:
        table.add_row(
            str(item.get("normalised_url") or ""),
            str(item.get("endpoint_category") or ""),
            str(item.get("candidate_score") or 0),
            str(item.get("candidate_label") or ""),
            ", ".join(item.get("candidate_reasons") or [])[:80],
        )
    console.print(table)


def _print_parameter_results(results: list[dict[str, Any]]) -> None:
    if not results:
        console.print("[yellow]Interesting parameters:[/yellow] None identified.")
        return
    table = Table(title="Interesting Parameters")
    table.add_column("Path")
    table.add_column("Parameter")
    table.add_column("Type")
    table.add_column("Potential Issue")
    table.add_column("Confidence")
    for item in results[:20]:
        table.add_row(
            str(item.get("path") or item.get("url") or ""),
            str(item.get("parameter_name") or ""),
            str(item.get("parameter_type") or ""),
            str(item.get("potential_issue") or ""),
            str(item.get("confidence") or ""),
        )
    console.print(table)


def _print_endpoint_skipped(skipped: list[dict[str, Any]]) -> None:
    if not skipped:
        return
    table = Table(title="Skipped Out-of-Scope URLs")
    table.add_column("URL")
    table.add_column("Reason")
    table.add_column("Scope Reason")
    for item in skipped[:20]:
        table.add_row(
            str(item.get("original_url") or ""),
            str(item.get("reason") or ""),
            str(item.get("scope_reason") or ""),
        )
    console.print(table)


def _print_submission_record(record: dict[str, Any]) -> None:
    table = Table(title="Submission Record")
    table.add_column("Field")
    table.add_column("Value")
    for key in (
        "submission_id",
        "report_id",
        "finding_title",
        "program_name",
        "platform",
        "status",
        "severity_submitted",
        "severity_accepted",
        "bounty_amount",
        "bounty_currency",
        "next_follow_up_date",
        "updated_at",
    ):
        table.add_row(key, str(record.get(key) or ""))
    console.print(table)
    if record.get("notes"):
        console.print(f"[bold]Notes:[/bold] {record.get('notes')}")
    if record.get("safe_notes_redacted"):
        console.print("[yellow]One or more note values were redacted before storage.[/yellow]")


def _print_submissions(records: list[dict[str, Any]]) -> None:
    table = Table(title="Submission and Retest Tracking")
    table.add_column("Submission ID", no_wrap=True)
    table.add_column("Report")
    table.add_column("Program")
    table.add_column("Platform")
    table.add_column("Status")
    table.add_column("Bounty")
    table.add_column("Updated")
    for record in records:
        bounty = " ".join(str(record.get(key) or "") for key in ("bounty_amount", "bounty_currency")).strip()
        table.add_row(
            str(record.get("submission_id") or ""),
            str(record.get("report_id") or ""),
            str(record.get("program_name") or ""),
            str(record.get("platform") or ""),
            str(record.get("status") or ""),
            bounty,
            str(record.get("updated_at") or ""),
        )
    console.print(table)


def _print_submission_timeline(events: list[dict[str, Any]]) -> None:
    if not events:
        return
    table = Table(title="Submission Timeline")
    table.add_column("Time")
    table.add_column("Event")
    table.add_column("Status")
    table.add_column("Note")
    for event in events:
        status = f"{event.get('old_status') or ''} -> {event.get('new_status') or ''}".strip(" ->")
        table.add_row(str(event.get("created_at") or ""), str(event.get("event_type") or ""), status, str(event.get("note") or "")[:80])
    console.print(table)


def _print_retests(records: list[dict[str, Any]]) -> None:
    table = Table(title="Retest Records")
    table.add_column("Retest ID", no_wrap=True)
    table.add_column("Submission ID", no_wrap=True)
    table.add_column("Status")
    table.add_column("Result")
    table.add_column("Evidence")
    table.add_column("Updated")
    for record in records:
        table.add_row(
            str(record.get("retest_id") or ""),
            str(record.get("submission_id") or ""),
            str(record.get("status") or ""),
            str(record.get("retest_result") or ""),
            str(record.get("evidence_id") or ""),
            str(record.get("updated_at") or ""),
        )
    console.print(table)


def _load_metrics_or_exit(range_name: str, start_date: str | None, end_date: str | None, program_name: str | None) -> dict[str, Any]:
    try:
        return build_bug_intelligence_metrics(
            range_name=range_name,
            start_date=start_date,
            end_date=end_date,
            program_name=program_name,
        )
    except MetricsDateRangeError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc


def _print_metrics_summary(metrics: dict[str, Any]) -> None:
    console.print(Panel.fit("Bug Intelligence Metrics", style="bold cyan"))
    table = Table(title="Summary")
    table.add_column("Metric")
    table.add_column("Value")
    rows = [
        ("Evidence records", metrics.get("total_evidence_records")),
        ("Reports created", metrics.get("total_reports_created")),
        ("Submissions", metrics.get("total_submissions")),
        ("Accepted", metrics.get("total_accepted")),
        ("Duplicates", metrics.get("total_duplicates")),
        ("Resolved", metrics.get("total_resolved")),
        ("Retests passed", metrics.get("retest_passed_count")),
        ("Acceptance rate", f"{metrics.get('acceptance_rate', 0)}%"),
        ("Duplicate rate", f"{metrics.get('duplicate_rate', 0)}%"),
        ("Total bounty", _format_currency_map(metrics.get("total_bounty_by_currency") or {})),
        ("Quality score", f"{(metrics.get('quality_indicators') or {}).get('score', 0)} - {(metrics.get('quality_indicators') or {}).get('label', '')}"),
    ]
    for label, value in rows:
        table.add_row(label, str(value if value is not None else ""))
    console.print(table)


def _format_currency_map(values: dict[str, Any]) -> str:
    if not values:
        return "0"
    return ", ".join(f"{currency} {amount:g}" if isinstance(amount, (int, float)) else f"{currency} {amount}" for currency, amount in values.items())


def _duplicate_cli_item(
    *,
    url: str | None,
    issue_type: str,
    parameter: str | None,
    source: str | None,
    host: str | None,
    path: str | None,
) -> dict[str, Any]:
    params = [part.strip() for part in (parameter or "").split(",") if part.strip()]
    return {
        "url": url,
        "host": host,
        "path": path,
        "issue_type": issue_type,
        "parameter_names": params,
        "source": source or "cli",
    }


def _print_fingerprint(fingerprint: dict[str, Any]) -> None:
    table = Table(title="Finding Fingerprint")
    table.add_column("Field")
    table.add_column("Value")
    for key in (
        "fingerprint_id",
        "fingerprint_short",
        "fingerprint_version",
        "host",
        "path_normalised",
        "issue_type",
        "parameter_names",
        "source",
    ):
        table.add_row(key, str(fingerprint.get(key) or ""))
    console.print(table)


def _print_duplicate_result(result: dict[str, Any]) -> None:
    table = Table(title="Duplicate Detection Result")
    table.add_column("Field")
    table.add_column("Value")
    for key in ("duplicate_status", "duplicate_confidence", "duplicate_group_id", "duplicate_reason"):
        table.add_row(key, str(result.get(key) or ""))
    refs = result.get("existing_item_references") or []
    if refs:
        table.add_row("existing_item_references", ", ".join(str(ref.get("fingerprint_short") or ref.get("fingerprint_id")) for ref in refs))
    console.print(table)


def _print_duplicate_summary(summary: dict[str, Any]) -> None:
    table = Table(title="Duplicate Detection Summary")
    table.add_column("Metric")
    table.add_column("Value")
    for key in (
        "total_fingerprints",
        "unique_findings",
        "exact_duplicates",
        "likely_duplicates",
        "related_findings",
        "duplicate_groups_count",
    ):
        table.add_row(key, str(summary.get(key, 0)))
    console.print(table)


def _print_duplicate_groups(groups: list[dict[str, Any]]) -> None:
    table = Table(title="Duplicate Groups")
    table.add_column("Group ID", no_wrap=True)
    table.add_column("Status")
    table.add_column("Confidence")
    table.add_column("Title")
    table.add_column("Members")
    table.add_column("Updated")
    for group in groups:
        table.add_row(
            str(group.get("duplicate_group_id") or ""),
            str(group.get("duplicate_status") or ""),
            str(group.get("confidence") or ""),
            str(group.get("title") or ""),
            str(group.get("member_count") or len(group.get("members") or [])),
            str(group.get("updated_at") or ""),
        )
    console.print(table)


def _print_duplicate_group_members(members: list[dict[str, Any]]) -> None:
    table = Table(title="Duplicate Group Members")
    table.add_column("Fingerprint")
    table.add_column("Relationship")
    table.add_column("Confidence")
    table.add_column("Item")
    table.add_column("Reason")
    for member in members:
        table.add_row(
            str(member.get("fingerprint_id") or ""),
            str(member.get("relationship") or ""),
            str(member.get("confidence") or ""),
            str(member.get("title") or member.get("item_id") or ""),
            str(member.get("reason") or ""),
        )
    console.print(table)


def _print_owasp_summary(summary: dict[str, Any], mapped_items: list[dict[str, Any]]) -> None:
    if not summary or not summary.get("enabled"):
        return
    table = Table(title="OWASP Top 10 Indicator Summary")
    table.add_column("Field")
    table.add_column("Value")
    highest = ", ".join(
        f"{item.get('owasp_id')} ({item.get('count')})"
        for item in summary.get("highest_signal_categories", [])
    )
    rows = [
        ("Version", summary.get("version")),
        ("Mapped findings", summary.get("mapped_findings_count")),
        ("Unmapped findings", summary.get("unmapped_findings_count")),
        ("Mapped endpoints", summary.get("mapped_endpoint_candidates_count")),
        ("Mapped parameters", summary.get("mapped_parameter_candidates_count")),
        ("Manual validation required", summary.get("manual_validation_required_count")),
        ("Top categories", highest),
        ("Coverage gaps", len(summary.get("coverage_gaps") or [])),
    ]
    for label, value in rows:
        table.add_row(label, "" if value is None else str(value))
    console.print(table)

    category_counts = summary.get("category_counts") or {}
    if category_counts:
        category_table = Table(title="OWASP Category Counts")
        category_table.add_column("Category")
        category_table.add_column("Count", justify="right")
        for category_id, count in category_counts.items():
            if int(count or 0) > 0:
                category_table.add_row(str(category_id), str(count))
        console.print(category_table)

    gaps = summary.get("coverage_gaps") or []
    if gaps:
        gap_table = Table(title="OWASP Coverage Gaps")
        gap_table.add_column("Category")
        gap_table.add_column("Note")
        for gap in gaps[:10]:
            gap_table.add_row(str(gap.get("owasp_id") or ""), "No indicator does not mean no vulnerability.")
        console.print(gap_table)


def _print_owasp_assessment_summary(summary: dict[str, Any], category_results: list[dict[str, Any]]) -> None:
    if not summary or not summary.get("enabled"):
        return
    table = Table(title="OWASP Assessment Engine Summary")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("OWASP version", summary.get("owasp_version")),
        ("Evidence items", summary.get("total_evidence_items")),
        ("Confirmed findings", summary.get("confirmed_findings_count")),
        ("Strong indicators", summary.get("strong_indicators_count")),
        ("Weak indicators", summary.get("weak_indicators_count")),
        ("Manual validation required", summary.get("manual_validation_required_count")),
        ("Coverage gaps", summary.get("coverage_gaps_count")),
        ("Assessment quality", f"{summary.get('assessment_quality_score', 0)} - {summary.get('assessment_quality_label', 'Limited')}"),
    ]
    for label, value in rows:
        table.add_row(label, "" if value is None else str(value))
    console.print(table)

    if category_results:
        category_table = Table(title="OWASP Category Results")
        category_table.add_column("Category")
        category_table.add_column("Status")
        category_table.add_column("Coverage")
        category_table.add_column("Evidence", justify="right")
        category_table.add_column("Confidence")
        for result in category_results:
            category_table.add_row(
                f"{result.get('owasp_id')} {result.get('name')}",
                str(result.get("assessment_status") or ""),
                str(result.get("coverage_status") or ""),
                str(result.get("evidence_count") or 0),
                str(result.get("highest_confidence") or "Low"),
            )
        console.print(category_table)


def _print_auth_profile_summary(profile: dict[str, Any]) -> None:
    table = Table(title="Session Profile Summary")
    table.add_column("Field")
    table.add_column("Value")
    for key in ("profile_name", "target_base_url", "auth_type", "role_label", "redaction_status", "cookie_names", "header_names", "allowed_hosts", "allowed_paths", "blocked_paths"):
        value = profile.get(key)
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)
        table.add_row(key.replace("_", " ").title(), str(value or ""))
    console.print(table)


def _print_auth_context(context: dict[str, Any]) -> None:
    _print_auth_profile_summary(context.get("session_profile") or {})
    for warning in context.get("warnings") or []:
        console.print(f"[yellow]Warning:[/yellow] {warning}")
    console.print("[yellow]Authenticated Web Assessment context is redacted and local-only. Raw auth material is not printed.[/yellow]")


def _print_auth_endpoint_classification(summary: dict[str, Any]) -> None:
    if not summary or not summary.get("enabled"):
        return
    table = Table(title="Auth-Required Endpoint Classification")
    table.add_column("Field")
    table.add_column("Value")
    for key in ("total_endpoints", "auth_required_likely_count", "public_likely_count", "unknown_count", "role_label"):
        table.add_row(key.replace("_", " ").title(), str(summary.get(key, "")))
    console.print(table)


def _print_authenticated_crawl_summary(summary: dict[str, Any]) -> None:
    if not summary:
        return
    table = Table(title="Authenticated Crawl Summary")
    table.add_column("Field")
    table.add_column("Value")
    for key in (
        "crawl_id",
        "target_base_url",
        "profile_name",
        "role_label",
        "pages_crawled",
        "endpoints_discovered",
        "auth_required_endpoints_count",
        "blocked_by_boundary_count",
        "skipped_destructive_count",
        "skipped_out_of_scope_count",
        "session_expiry_indicators_count",
        "redaction_applied",
    ):
        table.add_row(key.replace("_", " ").title(), str(summary.get(key, "")))
    console.print(table)


def _print_authenticated_crawl_rows(results: list[dict[str, Any]], skipped: list[dict[str, Any]], events: list[dict[str, Any]]) -> None:
    if results:
        table = Table(title="Authenticated Crawl Results")
        for column in ("URL", "Status", "Title", "Auth Required", "Session Expiry", "Category"):
            table.add_column(column)
        for row in results[:20]:
            table.add_row(
                str(row.get("url") or ""),
                str(row.get("status_code") or ""),
                str(row.get("page_title") or row.get("title") or "")[:80],
                str(row.get("auth_required_likely") or False),
                str(row.get("session_expiry_indicator") or False),
                str(row.get("endpoint_category") or ""),
            )
        console.print(table)
    if skipped:
        table = Table(title="Authenticated Crawl Skipped")
        for column in ("URL", "Reason", "Rule"):
            table.add_column(column)
        for row in skipped[:20]:
            table.add_row(str(row.get("url") or ""), str(row.get("reason") or ""), str(row.get("matched_rule") or ""))
        console.print(table)
    if events:
        table = Table(title="Session Boundary Events")
        for column in ("URL", "Event", "Reason", "Action"):
            table.add_column(column)
        for row in events[:20]:
            table.add_row(str(row.get("url") or ""), str(row.get("event_type") or ""), str(row.get("reason") or ""), str(row.get("action_taken") or ""))
        console.print(table)


def _generate_owasp_markdown_report(scan_result: dict[str, Any]) -> Path:
    report = scan_result.get("owasp_assessment_report")
    if not isinstance(report, dict) or not report:
        attach_owasp_assessment(scan_result)
        report = scan_result.get("owasp_assessment_report", {})
    report_path = save_markdown_report(report)
    scan_result["owasp_markdown_report_path"] = str(report_path)
    scan_result.setdefault("owasp_assessment_report", report)
    scan_result["owasp_assessment_report"]["markdown_report_path"] = str(report_path)
    return report_path


def _print_a04_crypto_summary(summary: dict[str, Any]) -> None:
    if not summary or not summary.get("enabled"):
        return
    table = Table(title="A04 Cryptographic Failures Summary")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Evidence items", summary.get("total_evidence_items")),
        ("Strong indicators", summary.get("strong_indicators_count")),
        ("Weak indicators", summary.get("weak_indicators_count")),
        ("Informational", summary.get("informational_count")),
        ("Manual validation required", summary.get("manual_validation_required_count")),
        ("HTTP URLs", summary.get("http_urls_count")),
        ("HTTPS URLs", summary.get("https_urls_count")),
        ("Insecure cookies", summary.get("insecure_cookie_count")),
        ("HSTS issues", summary.get("hsts_issue_count")),
        ("Mixed content indicators", summary.get("mixed_content_indicator_count")),
        ("TLS metadata available", summary.get("tls_metadata_available")),
        ("Highest confidence", summary.get("highest_confidence")),
    ]
    for label, value in rows:
        table.add_row(label, "" if value is None else str(value))
    console.print(table)


def _print_a07_authentication_summary(summary: dict[str, Any]) -> None:
    if not summary or not summary.get("enabled"):
        return
    table = Table(title="A07 Authentication Failures Summary")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Evidence items", summary.get("total_evidence_items")),
        ("Strong indicators", summary.get("strong_indicators_count")),
        ("Weak indicators", summary.get("weak_indicators_count")),
        ("Informational", summary.get("informational_count")),
        ("Manual validation required", summary.get("manual_validation_required_count")),
        ("Auth endpoints", summary.get("auth_endpoint_count")),
        ("Login forms", summary.get("login_form_count")),
        ("Password reset endpoints", summary.get("password_reset_endpoint_count")),
        ("Session cookie indicators", summary.get("session_cookie_indicator_count")),
        ("Remember-me indicators", summary.get("remember_me_indicator_count")),
        ("Rate-limit indicators", summary.get("rate_limit_indicator_count")),
        ("Protocol surface indicators", summary.get("protocol_surface_indicator_count")),
        ("Highest confidence", summary.get("highest_confidence")),
    ]
    for label, value in rows:
        table.add_row(label, "" if value is None else str(value))
    console.print(table)


def _print_a05_injection_summary(summary: dict[str, Any]) -> None:
    if not summary or not summary.get("enabled"):
        return
    table = Table(title="A05 Injection Candidate Summary")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Evidence items", summary.get("total_evidence_items")),
        ("Strong indicators", summary.get("strong_indicators_count")),
        ("Weak indicators", summary.get("weak_indicators_count")),
        ("Informational", summary.get("informational_count")),
        ("Manual validation required", summary.get("manual_validation_required_count")),
        ("Parameter candidates", summary.get("parameter_candidate_count")),
        ("Form input candidates", summary.get("form_input_candidate_count")),
        ("API input candidates", summary.get("api_input_candidate_count")),
        ("Reflections observed", summary.get("reflection_observed_count")),
        ("Highest confidence", summary.get("highest_confidence")),
    ]
    for label, value in rows:
        table.add_row(label, "" if value is None else str(value))
    console.print(table)


def _print_a01_access_control_summary(summary: dict[str, Any]) -> None:
    if not summary.get("enabled"):
        return
    table = Table(title="A01 Broken Access Control Candidate Summary")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Total candidates", str(summary.get("total_evidence_items", 0)))
    table.add_row("High interest", str(summary.get("high_interest_count", 0)))
    table.add_row("Medium interest", str(summary.get("medium_interest_count", 0)))
    table.add_row("Object-level authorization candidates", str(summary.get("object_id_candidate_count", 0)))
    table.add_row("Function-level authorization candidates", str(summary.get("function_level_candidate_count", 0)))
    table.add_row("Tenant boundary candidates", str(summary.get("tenant_boundary_candidate_count", 0)))
    table.add_row("Sensitive resource candidates", str(summary.get("sensitive_resource_candidate_count", 0)))
    table.add_row("Role/permission indicators", str(summary.get("role_permission_indicator_count", 0)))
    table.add_row("Manual validation required", str(summary.get("manual_validation_required_count", 0)))
    table.add_row("Highest indicator confidence", str(summary.get("highest_confidence", "Low")))
    console.print(table)
    console.print("[yellow]A01 safety:[/yellow] candidate discovery only; manual validation required; no auth bypass automation, cross-account testing, or state-changing requests performed.")


def _print_a03_supply_chain_summary(summary: dict[str, Any]) -> None:
    if not summary or not summary.get("enabled"):
        return
    table = Table(title="A03 Software Supply Chain Summary")
    table.add_column("Metric")
    table.add_column("Value")
    rows = [
        ("Evidence items", summary.get("total_evidence_items", 0)),
        ("Strong indicators", summary.get("strong_indicators_count", 0)),
        ("Weak indicators", summary.get("weak_indicators_count", 0)),
        ("Component hints", summary.get("component_hint_count", 0)),
        ("Version exposures", summary.get("version_exposure_count", 0)),
        ("Dependency metadata exposures", summary.get("dependency_metadata_exposure_count", 0)),
        ("SBOM components", summary.get("sbom_component_count", 0)),
        ("CVE matches", summary.get("cve_match_count", 0)),
        ("Source map indicators", summary.get("source_map_indicator_count", 0)),
        ("Third-party scripts", summary.get("third_party_script_count", 0)),
        ("Manual validation required", summary.get("manual_validation_required_count", 0)),
        ("Highest indicator confidence", summary.get("highest_confidence", "Low")),
    ]
    for label, value in rows:
        table.add_row(label, "" if value is None else str(value))
    console.print(table)
    console.print("[yellow]A03 safety:[/yellow] evidence-based component review only; no dependency confusion testing, external registry fetching, or exploit code used.")


def _print_a08_integrity_summary(summary: dict[str, Any]) -> None:
    if not summary or not summary.get("enabled"):
        return
    table = Table(title="A08 Software/Data Integrity Candidate Summary")
    table.add_column("Metric")
    table.add_column("Value")
    rows = [
        ("Total candidates", summary.get("total_evidence_items", 0)),
        ("High interest", summary.get("high_interest_count", 0)),
        ("Medium interest", summary.get("medium_interest_count", 0)),
        ("Upload workflow candidates", summary.get("upload_candidate_count", 0)),
        ("Import/export candidates", summary.get("import_export_candidate_count", 0)),
        ("Webhook/callback candidates", summary.get("webhook_callback_candidate_count", 0)),
        ("Update workflow candidates", summary.get("update_workflow_candidate_count", 0)),
        ("Subresource Integrity evidence", summary.get("sri_indicator_count", 0)),
        ("Trusted-data boundary indicators", summary.get("trusted_data_boundary_candidate_count", 0)),
        ("Deserialisation/data handling candidates", summary.get("deserialisation_candidate_count", 0)),
        ("Manual validation required", summary.get("manual_validation_required_count", 0)),
        ("Highest indicator confidence", summary.get("highest_confidence", "Low")),
    ]
    for label, value in rows:
        table.add_row(label, "" if value is None else str(value))
    console.print(table)
    console.print("[yellow]A08 safety:[/yellow] integrity indicators only; no uploads, form submissions, webhooks, update calls, or bypass testing performed.")


def _build_a03_vuln_intel(use_cve_feed: bool, cve_feed: Path | None) -> dict[str, Any]:
    if not use_cve_feed or cve_feed is None:
        return {}
    return {"cve_feed": load_cve_feed(cve_feed)}


def _print_a10_error_handling_summary(summary: dict[str, Any]) -> None:
    if not summary or not summary.get("enabled"):
        return
    table = Table(title="A10 Error Handling Summary")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Evidence items", summary.get("total_evidence_items")),
        ("Strong indicators", summary.get("strong_indicators_count")),
        ("Weak indicators", summary.get("weak_indicators_count")),
        ("Informational", summary.get("informational_count")),
        ("Manual validation required", summary.get("manual_validation_required_count")),
        ("Stack traces", summary.get("stack_trace_count")),
        ("Database errors", summary.get("database_error_count")),
        ("Framework errors", summary.get("framework_error_count")),
        ("Debug pages", summary.get("debug_page_count")),
        ("5xx observations", summary.get("status_5xx_count")),
        ("Fail-safe reviews", summary.get("fail_safe_review_count")),
        ("Sensitive error content", summary.get("sensitive_error_content_count")),
        ("Highest confidence", summary.get("highest_confidence")),
    ]
    for label, value in rows:
        table.add_row(label, "" if value is None else str(value))
    console.print(table)


def _print_safe_validation_summary(summary: dict[str, Any]) -> None:
    table = Table(title="Safe Active Validation Summary")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Input targets", summary.get("input_targets_count")),
        ("In scope", summary.get("in_scope_targets_count")),
        ("Out of scope", summary.get("out_of_scope_targets_count")),
        ("Checks run", summary.get("checks_run")),
        ("Checks skipped", summary.get("checks_skipped")),
        ("Indicators found", summary.get("indicators_found")),
        ("Request count", summary.get("request_count")),
        ("Rate limit applied", summary.get("rate_limit_applied")),
    ]
    for label, value in rows:
        table.add_row(label, "" if value is None else str(value))
    console.print(table)


def _print_safe_validation_results(results: list[dict[str, Any]]) -> None:
    if not results:
        console.print("[yellow]Safe validation results:[/yellow] No checks were run.")
        return
    table = Table(title="Safe Validation Results")
    table.add_column("URL")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Indicator")
    table.add_column("Evidence")
    for item in results:
        table.add_row(
            str(item.get("url") or ""),
            str(item.get("check_name") or ""),
            str(item.get("status") or ""),
            str(bool(item.get("indicator_found"))),
            str(item.get("evidence_summary") or "")[:120],
        )
    console.print(table)


def _print_safe_validation_skipped(skipped: list[dict[str, Any]]) -> None:
    if not skipped:
        return
    table = Table(title="Skipped Validation Targets")
    table.add_column("URL")
    table.add_column("Candidate")
    table.add_column("Reason")
    table.add_column("Scope Reason")
    for item in skipped:
        table.add_row(str(item.get("url") or ""), str(item.get("candidate_type") or ""), str(item.get("reason") or ""), str(item.get("scope_reason") or ""))
    console.print(table)


def _print_prioritisation(
    summary: dict[str, Any],
    prioritised_findings: list[dict[str, Any]],
) -> None:
    if not summary or not summary.get("enabled"):
        return

    summary_table = Table(title="Vulnerability Prioritisation Summary")
    summary_table.add_column("Field")
    summary_table.add_column("Value")
    rows = [
        ("Asset criticality enabled", summary.get("asset_criticality_enabled")),
        ("Asset criticality", summary.get("asset_criticality")),
        ("Asset criticality source", summary.get("asset_criticality_source")),
        ("Fix First", summary.get("fix_first_count")),
        ("Fix Soon", summary.get("fix_soon_count")),
        ("Schedule", summary.get("schedule_count")),
        ("Monitor", summary.get("monitor_count")),
    ]
    for label, value in rows:
        summary_table.add_row(label, "" if value is None else str(value))
    console.print(summary_table)

    if not prioritised_findings:
        return

    table = Table(title="Vulnerability Prioritisation")
    table.add_column("Priority", justify="right")
    table.add_column("Label")
    table.add_column("Asset")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Source")
    table.add_column("Reasons")
    for finding in prioritised_findings:
        table.add_row(
            str(finding.get("priority_score") or 0),
            str(finding.get("priority_label") or ""),
            str(finding.get("asset_criticality") or ""),
            str(finding.get("severity") or ""),
            str(finding.get("title") or ""),
            str(finding.get("source") or ""),
            "; ".join(str(reason) for reason in finding.get("priority_reasons") or []),
        )
    console.print(table)


def _print_fix_first_dashboard(
    dashboard: dict[str, Any],
    top_findings: list[dict[str, Any]],
) -> None:
    if not dashboard or not dashboard.get("enabled"):
        return

    table = Table(title="Fix-First Dashboard")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Total prioritised findings", dashboard.get("total_prioritised_findings")),
        ("Fix First", dashboard.get("fix_first_count")),
        ("Fix Soon", dashboard.get("fix_soon_count")),
        ("Monitor", dashboard.get("monitor_count")),
        ("Informational", dashboard.get("informational_count")),
        (
            "Highest priority finding",
            f"{dashboard.get('highest_priority_score')} - {dashboard.get('highest_priority_title') or 'n/a'}",
        ),
        ("High CVSS", dashboard.get("high_cvss_count")),
        ("High EPSS", dashboard.get("high_epss_count")),
        ("Exploit metadata", dashboard.get("exploitable_metadata_count")),
        ("Critical asset findings", dashboard.get("critical_asset_findings_count")),
    ]
    for label, value in rows:
        table.add_row(label, "" if value is None else str(value))
    console.print(table)

    if not top_findings:
        console.print("[green]Top Fix-First Findings:[/green] No prioritised findings available.")
        return

    top_table = Table(title="Top Fix-First Findings")
    top_table.add_column("Rank", justify="right")
    top_table.add_column("Priority")
    top_table.add_column("Score", justify="right")
    top_table.add_column("Title")
    top_table.add_column("Severity")
    top_table.add_column("Source")
    top_table.add_column("Asset")
    top_table.add_column("CVSS")
    top_table.add_column("EPSS")
    top_table.add_column("Exploit")
    top_table.add_column("Action")
    for finding in top_findings:
        top_table.add_row(
            str(finding.get("rank") or ""),
            str(finding.get("priority_label") or ""),
            str(finding.get("priority_score") or 0),
            str(finding.get("title") or ""),
            str(finding.get("severity") or ""),
            str(finding.get("source") or ""),
            str(finding.get("asset_criticality") or ""),
            "" if finding.get("cvss_score") in {None, ""} else str(finding.get("cvss_score")),
            "" if finding.get("epss_score") in {None, ""} else str(finding.get("epss_score")),
            str(finding.get("exploit_available") or False),
            str(finding.get("recommended_action") or "")[:80],
        )
    console.print(top_table)


def _print_prioritisation_trends(
    trends: dict[str, Any],
    details: dict[str, Any],
) -> None:
    if not trends or not trends.get("enabled"):
        return

    table = Table(title="Prioritisation Trends")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Status", trends.get("status")),
        ("Previous scan time", trends.get("previous_scan_time") or "n/a"),
        ("Risk trend", trends.get("risk_trend_label")),
        ("New findings", trends.get("new_findings_count")),
        ("Resolved findings", trends.get("resolved_findings_count")),
        ("Priority increased", trends.get("priority_increased_count")),
        ("Priority decreased", trends.get("priority_decreased_count")),
        ("New Fix First", trends.get("fix_first_new_count")),
        ("Resolved Fix First", trends.get("fix_first_resolved_count")),
        ("Persisting Fix First", trends.get("fix_first_persisting_count")),
        ("Average priority delta", trends.get("average_priority_delta")),
        ("Highest priority delta", trends.get("highest_priority_delta")),
    ]
    for label, value in rows:
        table.add_row(label, "" if value is None else str(value))
    console.print(table)

    _print_trend_detail_table("New Fix First Findings", details.get("fix_first_new", []))
    _print_trend_detail_table("Resolved Fix First Findings", details.get("fix_first_resolved", []))
    _print_trend_detail_table("Priority Increased Findings", details.get("priority_increased", []))


def _print_trend_detail_table(title: str, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    table = Table(title=title)
    table.add_column("Title")
    table.add_column("Source")
    table.add_column("Previous")
    table.add_column("Current")
    table.add_column("Delta")
    table.add_column("Reason")
    for item in rows[:10]:
        table.add_row(
            str(item.get("title") or ""),
            str(item.get("source") or ""),
            "" if item.get("previous_priority_score") is None else str(item.get("previous_priority_score")),
            "" if item.get("current_priority_score") is None else str(item.get("current_priority_score")),
            "" if item.get("score_delta") is None else str(item.get("score_delta")),
            str(item.get("reason_summary") or ""),
        )
    console.print(table)


def _print_vulnerability_intelligence(summary: dict[str, Any]) -> None:
    if not summary:
        return

    table = Table(title="Vulnerability Intelligence Summary")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Enabled", summary.get("enabled")),
        ("Ruleset", f"{summary.get('ruleset_name') or ''} {summary.get('ruleset_version') or ''}".strip()),
        ("Rules loaded", summary.get("rules_loaded")),
        ("Inventory items checked", summary.get("inventory_items_checked")),
        ("Matches found", summary.get("matches_found")),
        ("CVE matches", summary.get("cve_matches_count")),
        ("Version rules loaded", summary.get("version_rules_loaded")),
        ("Version matches found", summary.get("version_matches_found")),
        ("Unknown version count", summary.get("unknown_version_count")),
        ("Insufficient evidence count", summary.get("insufficient_evidence_count")),
        ("Confirmed version matches", summary.get("confirmed_version_match_count")),
        ("Exploit available count", summary.get("exploit_available_count")),
        ("Highest CVSS", summary.get("highest_cvss_score")),
        ("Highest EPSS", summary.get("highest_epss_score")),
        ("Highest intel risk", summary.get("highest_intel_risk_label")),
        ("CVE feed enabled", summary.get("cve_feed_enabled")),
        ("CVE feed", f"{summary.get('cve_feed_name') or ''} {summary.get('cve_feed_version') or ''}".strip()),
        ("CVE feed items loaded", summary.get("cve_feed_items_loaded")),
        ("CVE feed matches found", summary.get("cve_feed_matches_found")),
        ("CVE feed insufficient evidence", summary.get("cve_feed_insufficient_evidence_count")),
        ("CVE feed unknown version", summary.get("cve_feed_unknown_version_count")),
        ("CVE feed highest CVSS", summary.get("cve_feed_highest_cvss")),
        ("CVE feed exploit available", summary.get("cve_feed_exploit_available_count")),
        ("EPSS enabled", summary.get("epss_enabled")),
        ("EPSS records loaded", summary.get("epss_records_loaded")),
        ("EPSS invalid records", summary.get("epss_invalid_records")),
        ("EPSS enriched matches", summary.get("epss_matches_enriched")),
        ("EPSS missing count", summary.get("epss_missing_for_cve_count")),
        ("Highest EPSS score", summary.get("highest_epss_score")),
        ("Highest EPSS percentile", summary.get("highest_epss_percentile")),
        ("High EPSS count", summary.get("high_epss_count")),
        ("Medium EPSS count", summary.get("medium_epss_count")),
        ("Low EPSS count", summary.get("low_epss_count")),
        ("Exploit metadata enabled", summary.get("exploit_metadata_enabled")),
        ("Exploit metadata feed", f"{summary.get('exploit_metadata_feed_name') or ''} {summary.get('exploit_metadata_feed_version') or ''}".strip()),
        ("Exploit metadata records loaded", summary.get("exploit_metadata_records_loaded")),
        ("Exploit metadata invalid records", summary.get("exploit_metadata_invalid_records")),
        ("Exploit metadata unsafe skipped", summary.get("exploit_metadata_unsafe_records_skipped")),
        ("Exploit metadata enriched matches", summary.get("exploit_metadata_matches_enriched")),
        ("Active exploitation reported", summary.get("active_exploitation_reported_count")),
        ("Exploit maturity counts", _format_summary_list(summary.get("exploit_maturity_counts"))),
        ("Limitations", _format_summary_list(summary.get("limitations"))),
    ]
    for label, value in rows:
        table.add_row(label, "" if value is None else str(value))
    console.print(table)

    matches = list(summary.get("matches") or [])
    if matches:
        matches_table = Table(title="Vulnerability Intelligence Matches")
        matches_table.add_column("Rule ID")
        matches_table.add_column("Title")
        matches_table.add_column("Product")
        matches_table.add_column("Version")
        matches_table.add_column("Condition")
        matches_table.add_column("Status")
        matches_table.add_column("Confidence")
        matches_table.add_column("CVE")
        matches_table.add_column("CVSS")
        matches_table.add_column("Fixed Version")
        for match in matches:
            item = match.get("matched_item") or {}
            condition = match.get("version_condition") or {}
            matches_table.add_row(
                str(match.get("rule_id") or ""),
                str(match.get("title") or ""),
                str(item.get("product") or item.get("service_name") or ""),
                str(item.get("version") or ""),
                str(condition.get("display") or ""),
                str(match.get("match_status") or ""),
                str(match.get("match_confidence") or match.get("confidence") or ""),
                str(match.get("cve") or ""),
                "" if match.get("cvss_score") is None else str(match.get("cvss_score")),
                str(match.get("fixed_version") or ""),
            )
        console.print(matches_table)

    cve_feed_matches = list(summary.get("cve_feed_matches") or [])
    if not cve_feed_matches:
        return

    cve_table = Table(title="Local CVE Feed Matches")
    cve_table.add_column("CVE")
    cve_table.add_column("Title")
    cve_table.add_column("Product")
    cve_table.add_column("Version")
    cve_table.add_column("Affected Condition")
    cve_table.add_column("Fixed Version")
    cve_table.add_column("CVSS")
    cve_table.add_column("EPSS")
    cve_table.add_column("EPSS Percentile")
    cve_table.add_column("Severity")
    cve_table.add_column("Confidence")
    cve_table.add_column("Exploit Available")
    cve_table.add_column("Maturity")
    cve_table.add_column("Active Reported")
    for match in cve_feed_matches:
        condition = match.get("affected_condition") or {}
        cve_table.add_row(
            str(match.get("cve") or ""),
            str(match.get("title") or ""),
            str(match.get("product") or ""),
            str(match.get("version") or ""),
            str(condition.get("display") or ""),
            str(match.get("fixed_version") or ""),
            "" if match.get("cvss_score") is None else str(match.get("cvss_score")),
            "" if match.get("epss_score") is None else str(match.get("epss_score")),
            "" if match.get("epss_percentile") is None else str(match.get("epss_percentile")),
            str(match.get("severity") or ""),
            str(match.get("match_confidence") or ""),
            str(match.get("exploit_available") or False),
            str(match.get("exploit_maturity") or ""),
            str(match.get("active_exploitation_reported") or False),
        )
    console.print(cve_table)


def _print_web_dast_report(summary: dict[str, Any], sections: list[dict[str, Any]]) -> None:
    if not summary.get("enabled"):
        return

    console.print(Panel.fit("Web DAST Passive Report", style="bold cyan"))

    overview = Table(title="1. Overview")
    overview.add_column("Field")
    overview.add_column("Value")
    overview_rows = [
        ("Start URL", str(summary.get("start_url") or "")),
        ("Mode", str(summary.get("mode") or "passive")),
        ("Pages crawled", str(summary.get("pages_crawled") or 0)),
        ("Total requests", str(summary.get("total_requests") or 0)),
        ("Total web findings", str(summary.get("total_web_findings") or 0)),
        (
            "Highest web risk",
            f"{summary.get('highest_web_risk_score') or 0} ({summary.get('highest_web_risk_label') or 'Informational'})",
        ),
        ("Passive risk rating", str(summary.get("passive_risk_rating") or "None")),
    ]
    for label, value in overview_rows:
        overview.add_row(label, value)
    console.print(overview)

    section_map = {str(section.get("section_id")): section for section in sections}
    section_table = Table(title="2-9. Passive Web Sections")
    section_table.add_column("Section")
    section_table.add_column("Status")
    section_table.add_column("Key metrics")
    section_table.add_column("Findings", justify="right")
    for section_id, title in [
        ("web_scope", "2. Scope"),
        ("web_politeness", "3. Politeness"),
        ("web_robots", "4. Robots.txt"),
        ("web_sitemap", "5. Sitemap"),
        ("web_crawler", "6. Crawl"),
        ("web_headers", "7. Headers"),
        ("web_cookies", "8. Cookies"),
        ("web_forms", "9. Forms"),
    ]:
        section = section_map.get(section_id, {})
        section_table.add_row(
            title,
            str(section.get("status") or "skipped"),
            _format_web_section_metrics(section.get("key_metrics") or {}),
            str(section.get("findings_count") or 0),
        )
    console.print(section_table)

    next_steps = Table(title="10. Recommended Next Steps")
    next_steps.add_column("Step")
    for step in summary.get("recommended_next_steps") or []:
        next_steps.add_row(str(step))
    console.print(next_steps)


def _format_web_section_metrics(metrics: dict[str, Any]) -> str:
    if not metrics:
        return "None"
    parts: list[str] = []
    for key, value in metrics.items():
        label = str(key).replace("_", " ")
        if isinstance(value, list):
            rendered = ", ".join(str(item) for item in value) if value else "None"
        else:
            rendered = str(value)
        parts.append(f"{label}: {rendered}")
    return "; ".join(parts)


def _print_web_scan_summary(summary: dict[str, Any]) -> None:
    table = Table(title="Web DAST Crawler")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Start URL", str(summary.get("start_url") or "")),
        ("Allowed host", str(summary.get("allowed_host") or "")),
        ("Pages crawled", str(summary.get("pages_crawled") or 0)),
        ("Forms discovered", str(summary.get("forms_discovered") or 0)),
        ("Password forms", str(summary.get("password_forms_discovered") or 0)),
        ("File upload forms", str(summary.get("file_upload_forms_discovered") or 0)),
        ("External links", str(summary.get("unique_external_links") or 0)),
        ("Duration", f"{summary.get('duration_seconds') or 0} seconds"),
    ]
    for label, value in rows:
        table.add_row(label, value)
    console.print(table)


def _print_web_scope_summary(summary: dict[str, Any]) -> None:
    if not summary.get("enabled"):
        return
    table = Table(title="Web DAST Scope")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Start host", str(summary.get("start_host") or "")),
        ("Same-host only", str(summary.get("same_host_only"))),
        ("Include subdomains", str(summary.get("include_subdomains"))),
        ("Allowed hosts", _format_summary_list(summary.get("allowed_hosts"))),
        ("Denied hosts", _format_summary_list(summary.get("denied_hosts"))),
        ("Allowed paths", _format_summary_list(summary.get("allowed_paths"))),
        ("Denied paths", _format_summary_list(summary.get("denied_paths"))),
        ("Skipped external hosts", str(summary.get("skipped_external_hosts_count") or 0)),
        ("Skipped denied hosts", str(summary.get("skipped_denied_hosts_count") or 0)),
        ("Skipped denied paths", str(summary.get("skipped_denied_paths_count") or 0)),
        ("Skipped not allowed paths", str(summary.get("skipped_not_allowed_paths_count") or 0)),
        ("Skipped static files", str(summary.get("skipped_static_files_count") or 0)),
        ("Skipped unsupported schemes", str(summary.get("skipped_unsupported_schemes_count") or 0)),
        ("Skipped duplicates", str(summary.get("skipped_duplicates_count") or 0)),
        ("Skipped depth limit", str(summary.get("skipped_depth_limit_count") or 0)),
        ("Skipped page limit", str(summary.get("skipped_page_limit_count") or 0)),
        ("Skipped by robots", str(summary.get("skipped_by_robots_count") or 0)),
        ("Total skipped URLs", str(summary.get("total_skipped_urls") or 0)),
    ]
    for label, value in rows:
        table.add_row(label, value)
    console.print(table)


def _print_web_politeness_summary(summary: dict[str, Any]) -> None:
    if not summary.get("enabled"):
        return
    table = Table(title="Web DAST Politeness")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Request delay", f"{summary.get('request_delay_seconds') or 0} seconds"),
        ("Max requests per minute", str(summary.get("max_requests_per_minute") or 0)),
        ("Total requests", str(summary.get("total_requests") or 0)),
        ("Retries attempted", str(summary.get("retries_attempted") or 0)),
        ("Throttled requests", str(summary.get("throttled_requests") or 0)),
        ("Request errors", str(summary.get("request_errors") or 0)),
        ("Max errors reached", str(summary.get("max_errors_reached"))),
        ("Total sleep time", f"{summary.get('total_sleep_time_seconds') or 0} seconds"),
        ("Retry-After events", str(summary.get("retry_after_events") or 0)),
    ]
    for label, value in rows:
        table.add_row(label, value)
    console.print(table)


def _print_web_robots_summary(summary: dict[str, Any]) -> None:
    if not summary.get("enabled"):
        return
    table = Table(title="Robots.txt Awareness")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Robots URL", str(summary.get("robots_url") or "")),
        ("Found", str(summary.get("robots_found"))),
        ("Fetch status", str(summary.get("fetch_status") or "")),
        ("HTTP status", str(summary.get("http_status_code") or 0)),
        ("Respect robots", str(summary.get("respect_robots"))),
        ("User-agent", str(summary.get("robots_user_agent") or "")),
        ("Disallow rules", str(summary.get("disallow_rules_count") or 0)),
        ("Allow rules", str(summary.get("allow_rules_count") or 0)),
        ("Crawl-delay", "" if summary.get("crawl_delay") is None else str(summary.get("crawl_delay"))),
        ("Sitemaps", str(len(summary.get("sitemap_urls") or []))),
        ("URLs skipped by robots", str(summary.get("urls_skipped_by_robots") or 0)),
        ("Limitations", "; ".join(str(item) for item in summary.get("robots_limitations") or [])),
    ]
    for label, value in rows:
        table.add_row(label, value)
    console.print(table)


def _effective_web_crawl(*, crawl: bool, headers: bool, cookies: bool, forms: bool) -> bool:
    if not headers and not cookies and not forms:
        return crawl
    args = {arg.lower() for arg in sys.argv[1:]}
    if "--crawl" in args:
        return True
    if "--no-crawl" in args:
        return False
    return False


def _any_explicit_web_module_flag() -> bool:
    args = {arg.lower() for arg in sys.argv[1:]}
    return bool(args & {"--crawl", "--no-crawl", "--headers", "--cookies", "--forms", "--robots", "--sitemap"})


def _print_web_header_summary(summary: dict[str, Any]) -> None:
    if not summary.get("enabled"):
        return
    table = Table(title="Web Header Audit Summary")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Pages checked", str(summary.get("pages_checked") or 0)),
        ("Missing headers", str(sum((summary.get("missing_header_counts") or {}).values()))),
        ("Disclosure headers", str(sum((summary.get("disclosure_header_counts") or {}).values()))),
        ("Cookie issues", str(summary.get("cookie_issues_count") or 0)),
        ("Findings", str(summary.get("findings_count") or 0)),
    ]
    for label, value in rows:
        table.add_row(label, value)
    console.print(table)


def _print_web_cookie_summary(summary: dict[str, Any]) -> None:
    if not summary.get("enabled"):
        return
    table = Table(title="Web Cookie Audit Summary")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Pages checked", str(summary.get("pages_checked") or 0)),
        ("Cookies observed", str(summary.get("cookies_observed") or 0)),
        ("Missing Secure", str(summary.get("cookies_missing_secure") or 0)),
        ("Missing HttpOnly", str(summary.get("cookies_missing_httponly") or 0)),
        ("Missing SameSite", str(summary.get("cookies_missing_samesite") or 0)),
        ("SameSite=None without Secure", str(summary.get("samesite_none_without_secure") or 0)),
        ("Persistent cookie issues", str(summary.get("persistent_cookie_issues") or 0)),
        ("Findings", str(summary.get("findings_count") or 0)),
    ]
    for label, value in rows:
        table.add_row(label, value)
    console.print(table)


def _print_web_sitemap_summary(summary: dict[str, Any]) -> None:
    if not summary.get("enabled"):
        return
    table = Table(title="Web Sitemap Discovery")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Enabled", str(summary.get("enabled"))),
        ("Sitemap files fetched", str(summary.get("sitemap_urls_fetched") or 0)),
        ("Sitemap indexes found", str(summary.get("sitemap_indexes_found") or 0)),
        ("URL entries found", str(summary.get("url_entries_found") or 0)),
        ("In-scope URLs", str(summary.get("in_scope_urls") or 0)),
        ("Out-of-scope URLs", str(summary.get("out_of_scope_urls") or 0)),
        ("URLs added to crawl", str(summary.get("urls_added_to_crawl") or 0)),
        ("Failed sitemaps", str(summary.get("sitemap_urls_failed") or 0)),
        ("Limitations", "; ".join(str(item) for item in summary.get("limitations") or [])),
    ]
    for label, value in rows:
        table.add_row(label, value)
    console.print(table)


def _print_web_passive_summary(summary: dict[str, Any]) -> None:
    if not summary.get("enabled"):
        return
    table = Table(title="Web Passive Risk Summary")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Start URL", str(summary.get("start_url") or "")),
        ("Pages crawled", str(summary.get("pages_crawled") or 0)),
        ("Forms discovered", str(summary.get("forms_discovered") or 0)),
        ("Login forms", str(summary.get("login_forms") or 0)),
        ("Upload forms", str(summary.get("upload_forms") or 0)),
        ("Cookies observed", str(summary.get("cookies_observed") or 0)),
        ("Cookie issues", str(summary.get("cookie_issues") or 0)),
        ("Missing security headers", str(summary.get("missing_security_headers") or 0)),
        ("External links", str(summary.get("external_links") or 0)),
        ("Total web findings", str(summary.get("total_web_findings") or 0)),
        (
            "Highest web risk",
            f"{summary.get('highest_web_risk_score') or 0} ({summary.get('highest_web_risk_label') or 'Informational'})",
        ),
        ("Passive risk rating", str(summary.get("passive_risk_rating") or "None")),
        ("Recommended next steps", "; ".join(str(step) for step in summary.get("recommended_next_steps") or [])),
    ]
    for label, value in rows:
        table.add_row(label, value)
    console.print(table)


def _print_web_form_summary(summary: dict[str, Any]) -> None:
    if not summary.get("enabled"):
        return
    table = Table(title="Web Form Discovery Summary")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Forms discovered", str(summary.get("forms_discovered") or 0)),
        ("Login forms", str(summary.get("login_forms") or 0)),
        ("Upload forms", str(summary.get("upload_forms") or 0)),
        ("Missing CSRF indicators", str(summary.get("forms_missing_csrf_indicator") or 0)),
        ("Submit to HTTP", str(summary.get("forms_submitting_to_http") or 0)),
        ("External actions", str(summary.get("external_form_actions") or 0)),
        ("Findings", str(summary.get("findings_count") or 0)),
    ]
    for label, value in rows:
        table.add_row(label, value)
    console.print(table)


def _print_ssh_audit_summary(summary: dict[str, Any]) -> None:
    if not summary.get("enabled"):
        return

    table = Table(title="Credentialed SSH Audit Summary")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Status", summary.get("status")),
        ("Error code", summary.get("error_code")),
        ("Error message", summary.get("error_message")),
        ("Authenticated", summary.get("authenticated")),
        ("Username", summary.get("username_used")),
        ("Auth method", summary.get("auth_method")),
        ("Audit profile", summary.get("audit_profile")),
        ("Profile description", summary.get("profile_description")),
        ("Enabled checks", _format_summary_list(summary.get("checks_enabled"))),
        ("Profile-skipped checks", _format_summary_list(summary.get("profile_checks_skipped"))),
        ("Checks planned", summary.get("checks_planned")),
        ("Checks completed", summary.get("checks_completed")),
        ("Checks failed", summary.get("checks_failed")),
        ("Checks skipped", summary.get("checks_skipped")),
        ("Partial failures", summary.get("partial_failures")),
        ("Connection timeout seconds", summary.get("connection_timeout_seconds")),
        ("Command timeout seconds", summary.get("command_timeout_seconds")),
        ("Audit timeout seconds", summary.get("audit_timeout_seconds")),
        ("Total SSH audit duration seconds", summary.get("total_duration_seconds")),
        ("Timed out commands", summary.get("timed_out_commands")),
        ("Slowest command", summary.get("slowest_command_name")),
        ("Slowest command duration seconds", summary.get("slowest_command_duration_seconds")),
        ("OS family", summary.get("os_family")),
        ("Hostname", summary.get("hostname")),
        ("Package manager", summary.get("package_manager")),
        ("Package update count", summary.get("package_update_count")),
        ("SSH hardening checked", summary.get("ssh_hardening_checked")),
        ("Linux config audit checked", summary.get("linux_config_audit_checked")),
        ("Total SSH findings", summary.get("total_ssh_findings")),
        (
            "Highest SSH risk",
            f"{summary.get('highest_ssh_risk_score')} ({summary.get('highest_ssh_risk_label')})",
        ),
    ]
    for label, value in rows:
        table.add_row(label, "" if value is None else str(value))
    console.print(table)
    performance_table = Table(title="Windows Audit Performance")
    performance_table.add_column("Field")
    performance_table.add_column("Value")
    performance_rows = [
        ("Connection timeout", summary.get("connection_timeout_seconds")),
        ("Command timeout", summary.get("command_timeout_seconds")),
        ("Audit timeout", summary.get("audit_timeout_seconds")),
        ("Total duration", summary.get("total_duration_seconds")),
        ("Sections completed", summary.get("sections_completed")),
        ("Sections failed", summary.get("sections_failed")),
        ("Sections skipped", summary.get("sections_skipped")),
        ("Checks completed", summary.get("checks_completed")),
        ("Checks failed", summary.get("checks_failed")),
        ("Checks skipped", summary.get("checks_skipped")),
        ("Timed out commands", summary.get("timed_out_commands")),
        (
            "Slowest command",
            f"{summary.get('slowest_command_name') or ''} {summary.get('slowest_command_duration_seconds') or 0}s".strip(),
        ),
        ("Status", summary.get("status")),
    ]
    for label, value in performance_rows:
        performance_table.add_row(label, "" if value is None else str(value))
    console.print(performance_table)
    console.print(
        "[bold]SSH audit performance:[/bold] "
        f"{summary.get('checks_completed', 0)} checks completed, "
        f"{summary.get('checks_skipped', 0)} checks skipped, "
        f"{summary.get('timed_out_commands', 0)} command(s) timed out, "
        f"{summary.get('total_duration_seconds') or 0} seconds total."
    )
    console.print(
        "[yellow]Authenticated SSH audit uses read-only commands and depends on the permissions of the provided account. Results should be reviewed in operational context.[/yellow]"
    )
    if summary.get("performance_notes"):
        console.print(f"[yellow]Performance notes:[/yellow] {_format_summary_list(summary.get('performance_notes'))}")


def _print_windows_audit_summary(summary: dict[str, Any]) -> None:
    if not summary.get("enabled"):
        return

    if summary.get("demo_mode"):
        console.print("[yellow]DEMO MODE: No real target was scanned.[/yellow]")
        if summary.get("demo_notice"):
            console.print(f"[yellow]{summary.get('demo_notice')}[/yellow]")

    sections = list(summary.get("windows_audit_sections") or [])
    if sections:
        section_table = Table(title="Windows Audit Sections")
        section_table.add_column("Section")
        section_table.add_column("Status")
        section_table.add_column("Completed", justify="right")
        section_table.add_column("Failed", justify="right")
        section_table.add_column("Skipped", justify="right")
        section_table.add_column("Findings", justify="right")
        section_table.add_column("Duration", justify="right")
        for section in sections:
            section_table.add_row(
                str(section.get("section_name") or section.get("section_id") or ""),
                str(section.get("status") or ""),
                str(section.get("checks_completed") or 0),
                str(section.get("checks_failed") or 0),
                str(section.get("checks_skipped") or 0),
                str(len(section.get("findings") or [])),
                f"{float(section.get('duration_seconds') or 0.0):.3f}s",
            )
        console.print(section_table)

    table = Table(title="Windows SMB/WinRM Audit Summary")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Windows audit profile", summary.get("windows_audit_profile")),
        ("Profile description", summary.get("profile_description")),
        ("Enabled sections", _format_profile_sections(summary, summary.get("profile_enabled_sections"))),
        ("Skipped sections", _format_profile_sections(summary, summary.get("profile_skipped_sections"))),
        ("Manual overrides", _format_profile_sections(summary, summary.get("profile_manual_overrides"))),
        ("Audit timeout", summary.get("audit_timeout_seconds")),
        ("Status", summary.get("status")),
        ("Auth method", summary.get("auth_method")),
        ("Username", summary.get("username_used")),
        ("Domain", summary.get("domain")),
        ("SMB reachable", summary.get("smb_reachable")),
        ("WinRM HTTP reachable", summary.get("winrm_http_reachable")),
        ("WinRM HTTPS reachable", summary.get("winrm_https_reachable")),
        ("RDP reachable", summary.get("rdp_reachable")),
        ("WinRM authentication attempted", summary.get("winrm_auth_attempted")),
        ("WinRM authentication status", summary.get("winrm_auth_status")),
        ("WinRM endpoint used", summary.get("winrm_endpoint_used")),
        ("WinRM transport", summary.get("winrm_transport")),
        ("Safe validation command", summary.get("safe_validation_command")),
        ("Validation result summary", summary.get("validation_result_summary")),
        ("Windows host info collected", summary.get("windows_host_info_collected")),
        ("Windows host info status", summary.get("windows_host_info_status")),
        ("Windows security status checked", summary.get("windows_security_status_checked")),
        ("Windows security status", summary.get("windows_security_status_status")),
        ("Windows policy status checked", summary.get("windows_policy_status_checked")),
        ("Windows policy status", summary.get("windows_policy_status_status")),
        ("Windows registry audit checked", summary.get("windows_registry_audit_checked")),
        ("Windows registry audit status", summary.get("windows_registry_audit_status")),
        ("Findings count", summary.get("findings_count")),
        (
            "Highest Windows risk",
            f"{summary.get('highest_windows_risk_score')} ({summary.get('highest_windows_risk_label')})",
        ),
    ]
    for label, value in rows:
        table.add_row(label, "" if value is None else str(value))
    console.print(table)
    host_info = summary.get("windows_host_info") or {}
    if summary.get("windows_host_info_collected") and host_info:
        host_table = Table(title="Windows Host Information")
        host_table.add_column("Field")
        host_table.add_column("Value")
        host_rows = [
            ("Hostname", host_info.get("hostname")),
            ("Current identity", host_info.get("current_identity")),
            ("OS caption", host_info.get("os_caption")),
            ("OS version/build", f"{host_info.get('os_version') or ''} / {host_info.get('os_build') or ''}".strip(" /")),
            ("Architecture", host_info.get("os_architecture")),
            ("Domain", host_info.get("domain")),
            ("Workgroup", host_info.get("workgroup")),
            ("PowerShell version", host_info.get("powershell_version")),
            ("Last boot time", host_info.get("last_boot_time")),
            ("Timezone", host_info.get("timezone_display_name") or host_info.get("timezone_id")),
        ]
        for label, value in host_rows:
            host_table.add_row(label, "" if value is None else str(value))
        console.print(host_table)
    security_status = summary.get("windows_security_status") or {}
    if summary.get("windows_security_status_checked") and security_status:
        firewall_profiles = list(security_status.get("firewall_profiles") or [])
        defender_service = security_status.get("defender_service") or {}
        defender_status = security_status.get("defender_status") or {}
        disabled_profiles = sum(
            1 for profile in firewall_profiles if str(profile.get("enabled") or "").lower() == "false"
        )
        security_table = Table(title="Windows Security Status")
        security_table.add_column("Field")
        security_table.add_column("Value")
        security_rows = [
            ("Firewall profiles checked", len(firewall_profiles)),
            ("Disabled firewall profiles", disabled_profiles),
            ("Defender service status", defender_service.get("status")),
            ("Defender real-time protection", defender_status.get("real_time_protection_enabled")),
            ("Defender status available", bool(any(defender_status.values()))),
            ("Antivirus signature last updated", defender_status.get("antivirus_signature_last_updated")),
            ("Antispyware signature last updated", defender_status.get("antispyware_signature_last_updated")),
        ]
        for label, value in security_rows:
            security_table.add_row(label, "" if value is None else str(value))
        console.print(security_table)
        limitations = security_status.get("security_status_limitations")
        if limitations:
            console.print(f"[yellow]Windows security status limitations:[/yellow] {_format_summary_list(limitations)}")
    policy_status = summary.get("windows_policy_status") or {}
    if summary.get("windows_policy_status_checked") and policy_status:
        policy_table = Table(title="Windows Local Security Policy Indicators")
        policy_table.add_column("Field")
        policy_table.add_column("Value")
        policy_rows = [
            ("Minimum password length", policy_status.get("minimum_password_length")),
            ("Maximum password age", policy_status.get("maximum_password_age_days")),
            ("Password history length", policy_status.get("password_history_length")),
            ("Lockout threshold", policy_status.get("lockout_threshold")),
            ("Lockout duration", policy_status.get("lockout_duration_minutes")),
            ("Lockout observation window", policy_status.get("lockout_observation_window_minutes")),
            ("Computer role", policy_status.get("computer_role")),
            ("Domain policy context note", policy_status.get("domain_policy_context_note")),
            ("Limitations", _format_summary_list(policy_status.get("limitations"))),
        ]
        for label, value in policy_rows:
            policy_table.add_row(label, "" if value is None else str(value))
        console.print(policy_table)
    registry_audit = summary.get("windows_registry_audit") or {}
    if (summary.get("windows_registry_audit_checked") or summary.get("windows_registry_audit_status") == "failed") and registry_audit:
        registry_table = Table(title="Windows Registry Audit")
        registry_table.add_column("Field")
        registry_table.add_column("Value")
        registry_rows = [
            ("Template name", registry_audit.get("template_name")),
            ("Checks executed", registry_audit.get("checks_executed")),
            ("Passed", registry_audit.get("checks_passed")),
            ("Findings", registry_audit.get("checks_with_findings")),
            ("Failed/errors", registry_audit.get("checks_failed")),
            ("Limitations", _format_summary_list(registry_audit.get("limitations"))),
        ]
        for label, value in registry_rows:
            registry_table.add_row(label, "" if value is None else str(value))
        console.print(registry_table)
    limitations = summary.get("limitations")
    if limitations:
        console.print(f"[yellow]Windows audit limitations:[/yellow] {_format_summary_list(limitations)}")
    console.print(
        "[yellow]Windows audit uses safe reachability checks, one WinRM authentication validation command when requested, and optional read-only host information, security status, local policy, and exact template-based registry indicator commands. It does not enumerate shares, exploit, brute force, dump credentials, change registry values, change policy, or modify systems.[/yellow]"
    )


def _ssh_progress_callback(message: str) -> None:
    console.print(f"- {message}")


def _windows_progress_callback(message: str) -> None:
    console.print(f"- {message}")


def _build_asset_criticality_finding(asset_context: dict[str, Any]) -> Any:
    criticality = str(asset_context.get("criticality") or "unknown")
    if criticality == "unknown":
        return create_finding(
            title="Asset Criticality Unknown",
            severity="Informational",
            category="Prioritisation",
            evidence="No asset criticality mapping was found for the target.",
            confidence="High",
            impact="Unknown asset criticality may reduce prioritisation accuracy.",
            recommendation="Add the asset to the asset criticality context file or provide --asset-criticality.",
            verification="Review the configured local asset criticality context.",
            limitation="Unknown criticality may reduce prioritisation accuracy.",
            source="asset_criticality",
            affected_host=str(asset_context.get("target") or ""),
        )
    return create_finding(
        title="Asset Criticality Applied",
        severity="Informational",
        category="Prioritisation",
        evidence="Asset criticality was resolved and applied to prioritisation.",
        confidence="High",
        impact="Asset criticality can improve fix-first remediation ranking when reviewed with scan evidence.",
        recommendation="Maintain accurate asset criticality values to improve fix-first ranking.",
        verification="Review the Asset Context section and local asset criticality source.",
        limitation="Asset criticality is a local context input and should be reviewed regularly.",
        source="asset_criticality",
        affected_host=str(asset_context.get("target") or ""),
        evidence_details={
            "criticality": criticality,
            "criticality_source": asset_context.get("criticality_source"),
            "environment": asset_context.get("environment"),
        },
    )


def _apply_asset_fields_to_findings(
    findings: list[dict[str, Any]],
    asset_context: dict[str, Any],
) -> None:
    if not asset_context or not asset_context.get("enabled"):
        return
    for finding in findings:
        finding.setdefault("asset_criticality", asset_context.get("criticality") or "unknown")
        finding.setdefault("asset_environment", asset_context.get("environment") or "")
        finding.setdefault("asset_business_owner", asset_context.get("business_owner") or "")
        finding.setdefault("asset_tags", list(asset_context.get("tags") or []))


def _has_dashboard_finding(findings: list[dict[str, Any]]) -> bool:
    return any(str(finding.get("source") or "") == "prioritisation_report" for finding in findings)


def _has_trend_finding(findings: list[dict[str, Any]]) -> bool:
    return any(str(finding.get("source") or "") == "prioritisation_trends" for finding in findings)


def _apply_dashboard_export_fields(
    findings: list[dict[str, Any]],
    top_findings: list[dict[str, Any]],
    prioritised_findings: list[dict[str, Any]],
) -> None:
    by_title_source = {
        (str(item.get("title") or ""), str(item.get("source") or "")): item
        for item in prioritised_findings
    }
    ranks = {
        (str(item.get("title") or ""), str(item.get("source") or "")): item.get("rank")
        for item in top_findings
    }
    top_by_key = {
        (str(item.get("title") or ""), str(item.get("source") or "")): item
        for item in top_findings
    }
    for finding in findings:
        key = (str(finding.get("title") or ""), str(finding.get("source") or ""))
        prioritised = by_title_source.get(key)
        if not prioritised:
            continue
        top_item = top_by_key.get(key, {})
        finding["priority_score"] = prioritised.get("priority_score")
        finding["priority_label"] = top_item.get("priority_label") or _dashboard_label_for_export(prioritised)
        finding["recommended_action"] = top_item.get("recommended_action") or prioritised.get("recommendation") or prioritised.get("recommended_action") or finding.get("recommendation") or ""
        finding["sla_hint"] = top_item.get("sla_hint") or _sla_hint_for_export(prioritised)
        finding["fix_first_rank"] = ranks.get(key)


def _apply_trends_to_dashboard(scan_result: dict[str, Any]) -> None:
    dashboard = scan_result.get("fix_first_dashboard") or {}
    trends = scan_result.get("prioritisation_trends") or {}
    if not dashboard.get("enabled") or not trends.get("enabled"):
        return
    dashboard["risk_trend_label"] = trends.get("risk_trend_label") or "Unknown"
    dashboard["new_fix_first_count"] = trends.get("fix_first_new_count", 0)
    dashboard["resolved_fix_first_count"] = trends.get("fix_first_resolved_count", 0)
    dashboard["persisting_fix_first_count"] = trends.get("fix_first_persisting_count", 0)
    dashboard["average_priority_delta"] = trends.get("average_priority_delta", 0)
    dashboard["highest_priority_delta"] = trends.get("highest_priority_delta", 0)
    action = _trend_recommended_action(str(trends.get("risk_trend_label") or "Unknown"))
    actions = list(dashboard.get("top_recommended_actions") or [])
    if action and action not in actions:
        actions.insert(0, action)
    dashboard["top_recommended_actions"] = actions


def _trend_recommended_action(label: str) -> str:
    if label == "Worsened":
        return "Review new or increased-priority findings immediately."
    if label == "Improved":
        return "Confirm remediation evidence and continue monitoring."
    if label == "Stable":
        return "Focus on persisting Fix First and Fix Soon findings."
    if label == "Baseline":
        return "Use this scan as the baseline for future trend comparisons."
    return ""


def _apply_trend_export_fields(
    findings: list[dict[str, Any]],
    trend_details: dict[str, Any],
    target: str,
) -> None:
    by_key: dict[str, dict[str, Any]] = {}
    for bucket in (
        "new_findings",
        "priority_increased",
        "priority_decreased",
        "fix_first_new",
        "fix_first_persisting",
    ):
        for item in trend_details.get(bucket) or []:
            stable_key = str(item.get("stable_key") or "")
            if stable_key and stable_key not in by_key:
                by_key[stable_key] = item
    for finding in findings:
        stable_key = build_finding_stable_key(finding, target)
        item = by_key.get(stable_key)
        if not item:
            continue
        finding["trend_status"] = item.get("trend_status")
        finding["previous_priority_score"] = item.get("previous_priority_score")
        finding["current_priority_score"] = item.get("current_priority_score")
        finding["score_delta"] = item.get("score_delta")
        finding["previous_priority_label"] = item.get("previous_priority_label")
        finding["current_priority_label"] = item.get("current_priority_label")


def _sla_hint_for_export(finding: dict[str, Any]) -> str:
    label = str(finding.get("priority_label") or "")
    if label == "Fix First":
        return "Review within 24-72 hours; customise to local policy."
    if label in {"Fix Soon", "Schedule"}:
        return "Review within 7-14 days; customise to local policy."
    return "Review during the next routine security cycle."


def _dashboard_label_for_export(finding: dict[str, Any]) -> str:
    if str(finding.get("severity") or "") == "Informational":
        return "Informational"
    label = str(finding.get("priority_label") or "")
    if label == "Fix First":
        return "Fix First"
    if label in {"Fix Soon", "Schedule"}:
        return "Fix Soon"
    return "Monitor"


def _print_credentialed_audit_modules(credentialed_audits: list[dict[str, Any]]) -> None:
    if not credentialed_audits:
        return

    table = Table(title="Credentialed Audit Modules")
    table.add_column("Module")
    table.add_column("Source")
    table.add_column("Status")
    table.add_column("Profile")
    table.add_column("Completed", justify="right")
    table.add_column("Failed", justify="right")
    table.add_column("Skipped", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Duration", justify="right")
    for audit in credentialed_audits:
        table.add_row(
            str(audit.get("module_name") or ""),
            str(audit.get("source") or ""),
            str(audit.get("status") or ""),
            str(audit.get("profile") or ""),
            str(audit.get("checks_completed") or 0),
            str(audit.get("checks_failed") or 0),
            str(audit.get("checks_skipped") or 0),
            str(len(audit.get("findings") or [])),
            str(audit.get("duration_seconds") or 0),
        )
    console.print(table)


def _affected_summary(finding: dict[str, Any]) -> str:
    if finding.get("affected_url"):
        return str(finding["affected_url"])
    host = finding.get("affected_host")
    port = finding.get("affected_port")
    if host and port:
        return f"{host}:{port}"
    if host:
        return str(host)
    if port:
        return f"port {port}"
    return "n/a"


def _is_ssh_related_finding(finding: dict[str, Any]) -> bool:
    return str(finding.get("source") or "") in {
        "ssh_audit",
        "package_audit",
        "ssh_hardening",
        "linux_config_audit",
    }


def _is_windows_related_finding(finding: dict[str, Any]) -> bool:
    return str(finding.get("source") or "") in {
        "windows_audit",
        "windows_security_audit",
        "windows_policy_audit",
        "windows_registry_audit",
    }


def _build_ssh_audit_summary(
    scan_result: dict[str, Any],
    username: str,
    auth_method: str,
    ssh_port: int,
    audit_profile: Any,
) -> dict[str, Any]:
    ssh_audit = scan_result.get("ssh_audit", {})
    credentialed_audit = _first_credentialed_audit(scan_result, "ssh_audit")
    if credentialed_audit:
        ssh_audit = _ssh_audit_from_credentialed(ssh_audit, credentialed_audit)
    ssh_findings = scan_result.get("ssh_findings", [])
    highest = max(ssh_findings, key=lambda item: int(item.get("risk_score") or 0), default={})
    raw_status = str(ssh_audit.get("status") or "")
    authenticated = bool(ssh_audit.get("authenticated"))
    if raw_status in {"completed", "success"}:
        status = "success"
    elif raw_status == "partial" or authenticated:
        status = "partial"
    elif raw_status in {"not_run", "skipped"}:
        status = "skipped"
    else:
        status = "failed"

    return {
        "enabled": True,
        "status": status,
        "error_code": ssh_audit.get("error_code"),
        "error_message": ssh_audit.get("error_message"),
        "target": scan_result.get("host"),
        "ssh_port": ssh_port,
        "authenticated": authenticated,
        "username_used": username,
        "auth_method": auth_method,
        "audit_profile": audit_profile.name,
        "profile_description": audit_profile.description,
        "checks_enabled": list(audit_profile.checks_enabled),
        "profile_checks_skipped": list(audit_profile.checks_skipped),
        "checks_planned": int(ssh_audit.get("checks_planned") or 0),
        "checks_completed": int(ssh_audit.get("checks_completed") or 0),
        "checks_failed": int(ssh_audit.get("checks_failed") or 0),
        "checks_skipped": int(ssh_audit.get("checks_skipped") or 0),
        "partial_failures": int(ssh_audit.get("partial_failures") or 0),
        "command_timeout_seconds": ssh_audit.get("command_timeout_seconds"),
        "connection_timeout_seconds": ssh_audit.get("connection_timeout_seconds"),
        "audit_timeout_seconds": ssh_audit.get("audit_timeout_seconds"),
        "total_duration_seconds": ssh_audit.get("total_duration_seconds"),
        "timed_out_commands": int(ssh_audit.get("timed_out_commands") or 0),
        "slowest_command_name": ssh_audit.get("slowest_command_name"),
        "slowest_command_duration_seconds": ssh_audit.get("slowest_command_duration_seconds"),
        "performance_notes": list(ssh_audit.get("performance_notes") or []),
        "os_family": ssh_audit.get("os_family"),
        "hostname": ssh_audit.get("hostname"),
        "kernel_summary": ssh_audit.get("kernel_summary"),
        "package_manager": ssh_audit.get("package_manager"),
        "package_update_count": ssh_audit.get("package_update_count"),
        "ssh_hardening_checked": bool(ssh_audit.get("ssh_hardening_checked")),
        "linux_config_audit_checked": bool(ssh_audit.get("linux_config_audit_checked")),
        "total_ssh_findings": len(ssh_findings),
        "highest_ssh_risk_score": int(highest.get("risk_score") or 0),
        "highest_ssh_risk_label": str(highest.get("risk_label") or "Informational"),
        "limitations": (
            "Authenticated SSH audit uses read-only commands and depends on the permissions of the provided account. "
            "Results should be reviewed in operational context."
        ),
    }


def _build_windows_audit_summary(scan_result: dict[str, Any]) -> dict[str, Any]:
    windows_audit = scan_result.get("windows_audit", {})
    windows_findings = scan_result.get("windows_findings", [])
    base_summary = dict(windows_audit.get("summary") or {})
    highest = max(windows_findings, key=lambda item: int(item.get("risk_score") or 0), default={})
    base_summary.update(
        {
            "enabled": True,
            "status": windows_audit.get("status") or base_summary.get("status") or "skipped",
            "target": scan_result.get("host"),
            "findings_count": len(windows_findings),
            "highest_windows_risk_score": int(highest.get("risk_score") or 0),
            "highest_windows_risk_label": str(highest.get("risk_label") or "Informational"),
            "windows_audit_sections": list(scan_result.get("windows_audit_sections") or []),
        }
    )
    return redact_nested(base_summary)


def _windows_profile_summary_fields(
    *,
    profile_plan: dict[str, Any],
    audit_timeout_seconds: float,
) -> dict[str, Any]:
    return {
        "windows_audit_profile": profile_plan.get("profile_name") or "standard",
        "profile_description": profile_plan.get("profile_description") or "",
        "profile_enabled_sections": list(profile_plan.get("profile_enabled_sections") or []),
        "profile_skipped_sections": list(profile_plan.get("profile_skipped_sections") or []),
        "profile_manual_overrides": list(profile_plan.get("profile_manual_overrides") or []),
        "profile_default_timeout_seconds": float(profile_plan.get("profile_default_timeout_seconds") or 0.0),
        "profile_effective_audit_timeout_seconds": float(audit_timeout_seconds),
        "profile_section_labels": dict(profile_plan.get("section_labels") or {}),
        "profile_section_enabled_by_profile": dict(profile_plan.get("enabled_by_profile") or {}),
        "profile_section_enabled_by_manual_flag": dict(profile_plan.get("enabled_by_manual_flag") or {}),
        "profile_section_skipped_reasons": dict(profile_plan.get("skipped_reasons") or {}),
    }


def _build_credentialed_audits(
    *,
    ssh_result: dict[str, Any],
    ssh_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    credentialed_audit = dict(ssh_result.get("credentialed_audit") or {})
    if not credentialed_audit:
        return []
    credentialed_audit["findings"] = list(ssh_findings)
    credentialed_audit["checks_completed"] = int(ssh_result.get("checks_completed") or 0)
    credentialed_audit["checks_failed"] = int(ssh_result.get("checks_failed") or 0)
    credentialed_audit["checks_skipped"] = int(ssh_result.get("checks_skipped") or 0)
    credentialed_audit["duration_seconds"] = ssh_result.get("total_duration_seconds") or credentialed_audit.get("duration_seconds") or 0
    performance = dict(credentialed_audit.get("performance") or {})
    performance["total_duration_seconds"] = ssh_result.get("total_duration_seconds")
    credentialed_audit["performance"] = performance
    return [credentialed_audit]


def _build_windows_credentialed_audits(
    *,
    windows_result: dict[str, Any],
    windows_findings: list[dict[str, Any]],
    windows_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    credentialed_audit = dict(windows_result.get("credentialed_audit") or {})
    if not credentialed_audit:
        return []
    credentialed_audit["findings"] = list(windows_findings)
    credentialed_audit["checks_completed"] = int(windows_summary.get("checks_completed") or 0)
    credentialed_audit["checks_failed"] = int(windows_summary.get("checks_failed") or 0)
    credentialed_audit["checks_skipped"] = int(windows_summary.get("checks_skipped") or 0)
    credentialed_summary = dict(windows_summary)
    host_info = dict(windows_summary.get("windows_host_info") or {})
    security_status = dict(windows_summary.get("windows_security_status") or {})
    policy_status = dict(windows_summary.get("windows_policy_status") or {})
    registry_audit = dict(windows_summary.get("windows_registry_audit") or {})
    firewall_profiles = list(security_status.get("firewall_profiles") or [])
    defender_status = dict(security_status.get("defender_status") or {})
    credentialed_summary.update(
        {
            "hostname": host_info.get("hostname") or "",
            "os_caption": host_info.get("os_caption") or "",
            "os_version": host_info.get("os_version") or "",
            "os_build": host_info.get("os_build") or "",
            "domain_or_workgroup": host_info.get("domain") or host_info.get("workgroup") or "",
            "powershell_version": host_info.get("powershell_version") or "",
            "firewall_profiles_checked": len(firewall_profiles),
            "defender_status_available": any(defender_status.values()),
            "defender_realtime_enabled": defender_status.get("real_time_protection_enabled") or "",
            "firewall_disabled_profiles_count": sum(
                1 for profile in firewall_profiles if str(profile.get("enabled") or "").lower() == "false"
            ),
            "minimum_password_length": policy_status.get("minimum_password_length"),
            "maximum_password_age_days": policy_status.get("maximum_password_age_days"),
            "password_history_length": policy_status.get("password_history_length"),
            "lockout_threshold": policy_status.get("lockout_threshold"),
            "registry_template_name": registry_audit.get("template_name") or "",
            "registry_checks_executed": registry_audit.get("checks_executed") or 0,
            "registry_checks_with_findings": registry_audit.get("checks_with_findings") or 0,
        }
    )
    credentialed_audit["summary"] = redact_nested(credentialed_summary)
    performance = dict(credentialed_audit.get("performance") or {})
    performance.update(
        {
            "connection_timeout_seconds": windows_summary.get("connection_timeout_seconds"),
            "command_timeout_seconds": windows_summary.get("command_timeout_seconds"),
            "audit_timeout_seconds": windows_summary.get("audit_timeout_seconds"),
            "total_duration_seconds": windows_summary.get("total_duration_seconds"),
            "timed_out_commands": windows_summary.get("timed_out_commands"),
            "slowest_command_name": windows_summary.get("slowest_command_name"),
            "slowest_command_duration_seconds": windows_summary.get("slowest_command_duration_seconds"),
        }
    )
    credentialed_audit["performance"] = redact_nested(performance)
    metadata = dict(credentialed_audit.get("metadata") or {})
    metadata["windows_host_info"] = host_info
    metadata["windows_security_status"] = security_status
    metadata["windows_policy_status"] = policy_status
    metadata["windows_registry_audit"] = registry_audit
    credentialed_audit["metadata"] = redact_nested(metadata)
    return [redact_nested(credentialed_audit)]


def _first_credentialed_audit(scan_result: dict[str, Any], source: str) -> dict[str, Any]:
    for audit in scan_result.get("credentialed_audits", []) or []:
        if str(audit.get("source") or "") == source:
            return audit
    return {}


def _ssh_audit_from_credentialed(
    ssh_audit: dict[str, Any],
    credentialed_audit: dict[str, Any],
) -> dict[str, Any]:
    merged = dict(ssh_audit)
    performance = credentialed_audit.get("performance") or {}
    summary = credentialed_audit.get("summary") or {}
    metadata = credentialed_audit.get("metadata") or {}
    first_error = (credentialed_audit.get("errors") or [{}])[0]
    merged.update(
        {
            "status": credentialed_audit.get("status"),
            "authenticated": credentialed_audit.get("authenticated"),
            "error_code": first_error.get("error_code") or merged.get("error_code"),
            "error_message": first_error.get("message") or merged.get("error_message"),
            "audit_profile": credentialed_audit.get("profile") or merged.get("audit_profile"),
            "checks_planned": credentialed_audit.get("checks_planned"),
            "checks_completed": credentialed_audit.get("checks_completed"),
            "checks_failed": credentialed_audit.get("checks_failed"),
            "checks_skipped": credentialed_audit.get("checks_skipped"),
            "connection_timeout_seconds": performance.get("connection_timeout_seconds"),
            "command_timeout_seconds": performance.get("command_timeout_seconds"),
            "audit_timeout_seconds": performance.get("audit_timeout_seconds"),
            "total_duration_seconds": performance.get("total_duration_seconds") or credentialed_audit.get("duration_seconds"),
            "timed_out_commands": performance.get("timed_out_commands"),
            "slowest_command_name": performance.get("slowest_command_name"),
            "slowest_command_duration_seconds": performance.get("slowest_command_duration_seconds"),
            "performance_notes": performance.get("performance_notes") or [],
            "package_manager": summary.get("package_manager"),
            "package_update_count": summary.get("package_update_count"),
            "ssh_hardening_checked": summary.get("ssh_hardening_checked"),
            "linux_config_audit_checked": summary.get("linux_config_audit_checked"),
            "os_family": metadata.get("os_family"),
            "hostname": metadata.get("hostname"),
            "kernel_summary": metadata.get("kernel_summary"),
        }
    )
    return merged


def _format_summary_list(value: Any) -> str:
    if not value:
        return "None"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value)


def _format_profile_sections(summary: dict[str, Any], value: Any) -> str:
    if not value:
        return "None"
    labels = dict(summary.get("profile_section_labels") or {})
    if isinstance(value, list):
        return ", ".join(str(labels.get(str(item), item)) for item in value)
    return str(labels.get(str(value), value))


def _print_count_summary(title: str, counts: dict[str, int]) -> None:
    table = Table(title=title)
    table.add_column("Label")
    table.add_column("Count", justify="right")
    for label, count in counts.items():
        table.add_row(label, str(count))
    console.print(table)


def _print_diff_findings(title: str, findings: list[dict[str, Any]]) -> None:
    if not findings:
        return

    table = Table(title=title)
    table.add_column("Finding ID")
    table.add_column("Title")
    table.add_column("Severity")
    table.add_column("Risk", justify="right")
    table.add_column("Risk Label")
    table.add_column("Affected Host")
    table.add_column("Port", justify="right")
    table.add_column("Service")
    table.add_column("Source")

    for finding in findings:
        table.add_row(
            str(finding.get("finding_id") or ""),
            str(finding.get("title") or ""),
            str(finding.get("severity") or ""),
            str(finding.get("risk_score") or 0),
            str(finding.get("risk_label") or ""),
            str(finding.get("affected_host") or ""),
            str(finding.get("affected_port") or ""),
            str(finding.get("service") or ""),
            str(finding.get("source") or ""),
        )

    console.print(table)


def _print_assets_table(assets: list[dict[str, Any]]) -> None:
    table = Table(title="Assets")
    table.add_column("Asset ID")
    table.add_column("Target")
    table.add_column("Resolved IP")
    table.add_column("First Seen")
    table.add_column("Last Seen")
    table.add_column("Scans", justify="right")
    table.add_column("Open Ports", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Highest Risk")
    table.add_column("Exposure Summary")

    for asset in assets:
        table.add_row(
            str(asset.get("asset_id_short") or ""),
            str(asset.get("target") or ""),
            str(asset.get("resolved_ip") or ""),
            str(asset.get("first_seen") or ""),
            str(asset.get("last_seen") or ""),
            str(asset.get("total_scans") or 0),
            str(asset.get("last_open_port_count") or 0),
            str(asset.get("last_finding_count") or 0),
            str(asset.get("highest_risk_label") or ""),
            str(asset.get("exposure_summary") or ""),
        )
    console.print(table)


def _print_asset_services_table(services: list[dict[str, Any]]) -> None:
    table = Table(title="Detected Services")
    table.add_column("Port", justify="right")
    table.add_column("Protocol")
    table.add_column("Service")
    table.add_column("Status")
    table.add_column("First Seen")
    table.add_column("Last Seen")
    table.add_column("Last Recommendation")

    for service in services:
        table.add_row(
            str(service.get("port") or ""),
            str(service.get("protocol") or ""),
            str(service.get("service") or ""),
            str(service.get("status") or ""),
            str(service.get("first_seen") or ""),
            str(service.get("last_seen") or ""),
            str(service.get("last_recommendation") or ""),
        )
    console.print(table)


def _print_export_result(result: dict[str, Any]) -> None:
    if result["status"] == "exported":
        console.print(f"[bold]Export type:[/bold] {result['export_type']}")
        console.print(f"[bold]Format:[/bold] {result['format']}")
        console.print(f"[bold]Records exported:[/bold] {result['record_count']}")
        console.print(f"[bold]Saved file:[/bold] {result['path']}")
        return

    if result["status"] == "unsupported_format":
        console.print(f"[red]{result['message']}[/red]")
        raise typer.Exit(code=1)

    console.print(f"[yellow]{result['message']}[/yellow]")


if __name__ == "__main__":
    app()
