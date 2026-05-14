"""Command-line entry point for VulScan."""

from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from scanner import __version__
from scanner.assets import get_asset_services, get_assets
from scanner.finding import assign_sequential_finding_ids, create_port_exposure_findings
from scanner.database import database_exists, get_missing_required_tables
from scanner.diff import compare_latest_two_scans
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
    save_db: Annotated[
        bool,
        typer.Option(
            "--save-db",
            help="Save scan results to the local SQLite history database.",
        ),
    ] = False,
) -> None:
    """Run a defensive TCP connect scan against an authorised target."""
    try:
        validate_ssh_audit_options(
            ssh_audit=ssh_audit,
            ssh_user=ssh_user,
            ssh_password=ssh_password,
            ssh_key=ssh_key,
        )
    except SshAuditConfigurationError as exc:
        console.print(f"[red]SSH audit configuration error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(Panel.fit(f"VulScan version {__version__}", style="bold cyan"))
    console.print(f"[bold]Target:[/bold] {target}")
    console.print(f"[bold]Scan mode:[/bold] {mode}")
    console.print(
        "[yellow]Safe usage warning:[/yellow] Only scan systems you own or have explicit permission to assess."
    )

    try:
        scan_start_time = datetime.now().astimezone()
        scan_result = scan_tcp_ports(target)
        scan_result["scan_mode"] = mode
        scan_result["http_findings"] = []
        scan_result["tls_findings"] = []
        scan_result["ssh_audit"] = {"enabled": False, "status": "not_run", "findings": []}
        scan_result["ssh_audit_summary"] = {"enabled": False, "status": "skipped"}
        scan_result["ssh_findings"] = []
        findings = create_port_exposure_findings(scan_result["open_ports"])
        if http_audit:
            http_findings = audit_http_services(scan_result["open_ports"])
            findings.extend(http_findings)
        if tls_audit:
            tls_findings = audit_tls_services(scan_result["open_ports"])
            findings.extend(tls_findings)
        if ssh_audit:
            ssh_result = audit_ssh_host(
                host=scan_result["host"],
                resolved_ip=scan_result["resolved_ip"],
                username=str(ssh_user),
                password=ssh_password,
                key_path=ssh_key,
                port=ssh_port,
                open_ports=scan_result["open_ports"],
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
        if ssh_audit:
            scan_result["ssh_audit"]["findings"] = scan_result["ssh_findings"]
            scan_result["ssh_audit_summary"] = _build_ssh_audit_summary(
                scan_result=scan_result,
                username=str(ssh_user),
                auth_method="key" if ssh_key is not None else "password",
                ssh_port=ssh_port,
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
        "ssh_audit",
        "package_audit",
        "ssh_hardening",
        "linux_config_audit",
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


def _print_ssh_audit_summary(summary: dict[str, Any]) -> None:
    if not summary.get("enabled"):
        return

    table = Table(title="Credentialed SSH Audit Summary")
    table.add_column("Field")
    table.add_column("Value")
    rows = [
        ("Status", summary.get("status")),
        ("Authenticated", summary.get("authenticated")),
        ("Username", summary.get("username_used")),
        ("Auth method", summary.get("auth_method")),
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
    console.print(
        "[yellow]Authenticated SSH audit uses read-only commands and depends on the permissions of the provided account. Results should be reviewed in operational context.[/yellow]"
    )


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


def _build_ssh_audit_summary(
    scan_result: dict[str, Any],
    username: str,
    auth_method: str,
    ssh_port: int,
) -> dict[str, Any]:
    ssh_audit = scan_result.get("ssh_audit", {})
    ssh_findings = scan_result.get("ssh_findings", [])
    highest = max(ssh_findings, key=lambda item: int(item.get("risk_score") or 0), default={})
    raw_status = str(ssh_audit.get("status") or "")
    authenticated = bool(ssh_audit.get("authenticated"))
    if raw_status == "completed":
        status = "success"
    elif authenticated:
        status = "partial"
    elif raw_status in {"not_run", "skipped"}:
        status = "skipped"
    else:
        status = "failed"

    return {
        "enabled": True,
        "status": status,
        "target": scan_result.get("host"),
        "ssh_port": ssh_port,
        "authenticated": authenticated,
        "username_used": username,
        "auth_method": auth_method,
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
