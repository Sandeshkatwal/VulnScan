"""Command-line entry point for VulScan."""

from datetime import datetime
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from scanner import __version__
from scanner.http_audit import audit_http_services
from scanner.port_scan import PortScanError, scan_tcp_ports
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report
from scanner.tls_audit import audit_tls_services


app = typer.Typer(
    help="VulScan defensive vulnerability scanner.",
    no_args_is_help=True,
)
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
) -> None:
    """Run a defensive TCP connect scan against an authorised target."""
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
        if http_audit:
            scan_result["http_findings"] = audit_http_services(scan_result["open_ports"])
        if tls_audit:
            scan_result["tls_findings"] = audit_tls_services(scan_result["open_ports"])
        scan_end_time = datetime.now().astimezone()
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

    if http_audit:
        _print_http_findings(scan_result["http_findings"])

    if tls_audit:
        _print_tls_findings(scan_result["tls_findings"])

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


def _print_http_findings(findings: list[dict[str, Any]]) -> None:
    if not findings:
        console.print("[green]HTTP audit findings:[/green] None found.")
        return

    table = Table(title="HTTP Audit Findings")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("URL")
    table.add_column("Evidence")
    table.add_column("Recommendation")

    for finding in findings:
        table.add_row(
            finding["severity"],
            finding["title"],
            finding["affected_url"],
            finding["evidence"],
            finding["recommendation"],
        )

    console.print(table)


def _print_tls_findings(findings: list[dict[str, Any]]) -> None:
    if not findings:
        console.print("[green]TLS audit findings:[/green] None found.")
        return

    table = Table(title="TLS Certificate Findings")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Host")
    table.add_column("Port", justify="right")
    table.add_column("Evidence")
    table.add_column("Recommendation")

    for finding in findings:
        table.add_row(
            finding["severity"],
            finding["title"],
            finding["affected_host"],
            str(finding["affected_port"]),
            finding["evidence"],
            finding["recommendation"],
        )

    console.print(table)


if __name__ == "__main__":
    app()
