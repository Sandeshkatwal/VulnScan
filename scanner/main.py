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
from scanner.assets import get_asset_services, get_assets
from scanner.finding import assign_sequential_finding_ids, create_port_exposure_findings
from scanner.database import database_exists, get_missing_required_tables
from scanner.diff import compare_latest_two_scans
from scanner.evidence import redact_nested
from scanner.exporter import (
    export_assets,
    export_findings,
    export_history,
    export_remediation,
)
from scanner.history import (
    get_database_path,
    get_latest_scan_finding_summaries,
    get_scan_history,
    save_scan_result,
)
from scanner.http_audit import audit_http_services
from scanner.port_scan import PortScanError, scan_tcp_ports
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report
from scanner.remediation import (
    enrich_findings_with_remediation,
    get_remediation_list,
    get_remediation_summary,
    update_remediation_status,
)
from scanner.ssh_audit import (
    SshAuditConfigurationError,
    audit_ssh_host,
    validate_ssh_audit_options,
)
from scanner.tls_audit import audit_tls_services
from scanner.web_crawler import DEFAULT_USER_AGENT, crawl_web
from scanner.web_cookie_audit import audit_web_cookies
from scanner.web_header_audit import audit_web_headers
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
) -> None:
    """Run a defensive TCP connect scan against an authorised target."""
    if windows_demo and ssh_audit:
        console.print("[red]Windows demo mode cannot be combined with --ssh-audit because demo mode must not connect to any host.[/red]")
        raise typer.Exit(code=1)

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
        scan_result["credentialed_audits"] = []
        scan_result["ssh_findings"] = []
        scan_result["windows_findings"] = []
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
    user_agent: Annotated[
        str,
        typer.Option(
            "--user-agent",
            help="User-Agent header for safe crawler requests.",
        ),
    ] = DEFAULT_USER_AGENT,
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
        scan_start_time = datetime.now().astimezone()
        crawl_requested = _effective_web_crawl(crawl=crawl, headers=headers, cookies=cookies)
        web_result = crawl_web(
            start_url=url,
            crawl=crawl_requested,
            max_pages=max_pages,
            max_depth=max_depth,
            timeout=timeout,
            user_agent=user_agent,
        )
        web_header_result = (
            audit_web_headers(web_result.get("crawled_pages", []))
            if headers
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
            if headers or cookies
            else {
                "enabled": False,
                "status": "skipped",
                "web_cookie_summary": {"enabled": False, "status": "skipped"},
                "web_cookie_results": [],
                "findings": [],
            }
        )
        all_web_findings = (
            list(web_result.get("findings", []))
            + list(web_header_result.get("findings", []))
            + list(web_cookie_result.get("findings", []))
        )
        web_findings = assign_sequential_finding_ids(all_web_findings)
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
        "crawled_pages": web_result["crawled_pages"],
        "discovered_forms": web_result["discovered_forms"],
        "web_findings": web_findings,
        "demo_mode": False,
        "demo_notice": "",
        "scan_start_time": scan_start_time.isoformat(timespec="seconds"),
        "scan_end_time": scan_end_time.isoformat(timespec="seconds"),
    }

    _print_web_scan_summary(summary)
    if headers:
        _print_web_header_summary(scan_result["web_header_summary"])
    if headers or cookies:
        _print_web_cookie_summary(scan_result["web_cookie_summary"])
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


def _effective_web_crawl(*, crawl: bool, headers: bool, cookies: bool) -> bool:
    if not headers and not cookies:
        return crawl
    args = {arg.lower() for arg in sys.argv[1:]}
    if "--crawl" in args:
        return True
    if "--no-crawl" in args:
        return False
    return False


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
