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
from scanner.assets import get_asset_services, get_assets
from scanner.asset_criticality import (
    DEFAULT_ASSET_CRITICALITY_PATH,
    disabled_asset_context,
    load_asset_criticality_context,
    resolve_asset_criticality,
)
from scanner.finding import assign_sequential_finding_ids, create_finding, create_port_exposure_findings
from scanner.cve_feed import DEFAULT_CVE_FEED_PATH
from scanner.epss_importer import DEFAULT_EPSS_PATH
from scanner.exploit_metadata import DEFAULT_EXPLOIT_METADATA_PATH
from scanner.database import database_exists, get_missing_required_tables
from scanner.diff import compare_latest_two_scans
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
app.add_typer(remediation_app, name="remediation")
app.add_typer(export_app, name="export")
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
    console.print("[yellow]Version 16.0 API is for local development only and does not expose credentialed scans.[/yellow]")
    run_api_server(host=host, port=port, reload=reload)


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
) -> None:
    """Run a defensive TCP connect scan against an authorised target."""
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
        findings = [] if windows_demo else create_port_exposure_findings(scan_result["open_ports"])
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
        "scan_start_time": scan_start_time.isoformat(timespec="seconds"),
        "scan_end_time": scan_end_time.isoformat(timespec="seconds"),
    }

    _print_web_dast_report(scan_result["web_dast_summary"], scan_result["web_dast_sections"])
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
