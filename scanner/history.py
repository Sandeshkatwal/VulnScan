"""Scan history persistence for VulScan."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from scanner import __version__
from scanner.database import get_connection, init_db


def save_scan_result(scan_result: dict[str, Any]) -> str:
    """Save a completed scan result to the local SQLite database."""
    init_db()
    scan_id = str(scan_result.get("scan_id") or uuid4())
    findings = scan_result.get("findings", [])
    open_ports = scan_result.get("open_ports", [])
    highest_risk_score = max((int(finding.get("risk_score", 0)) for finding in findings), default=0)
    highest_risk_label = _highest_risk_label(findings)
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO scans (
                scan_id, target, resolved_ip, scanner_version, scan_mode,
                scan_start_time, scan_end_time, duration_seconds,
                total_open_ports, total_findings, highest_risk_score,
                highest_risk_label, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                scan_result["host"],
                scan_result["resolved_ip"],
                __version__,
                scan_result["scan_mode"],
                scan_result.get("scan_start_time", ""),
                scan_result.get("scan_end_time", ""),
                scan_result["duration_seconds"],
                len(open_ports),
                len(findings),
                highest_risk_score,
                highest_risk_label,
                created_at,
            ),
        )

        connection.executemany(
            """
            INSERT INTO open_ports (
                scan_id, host, resolved_ip, port, protocol, service,
                status, confidence, evidence, recommendation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    scan_id,
                    port_result.get("host"),
                    port_result.get("resolved_ip"),
                    port_result.get("port"),
                    port_result.get("protocol"),
                    port_result.get("service"),
                    port_result.get("status"),
                    port_result.get("confidence"),
                    port_result.get("evidence"),
                    port_result.get("recommendation"),
                )
                for port_result in open_ports
            ],
        )

        connection.executemany(
            """
            INSERT INTO findings (
                scan_id, finding_id, title, severity, category,
                affected_host, affected_port, affected_url, service,
                evidence, confidence, impact, recommendation, verification,
                limitation, source, risk_score, risk_label, fix_priority,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    scan_id,
                    finding.get("id"),
                    finding.get("title"),
                    finding.get("severity"),
                    finding.get("category"),
                    finding.get("affected_host"),
                    finding.get("affected_port"),
                    finding.get("affected_url"),
                    finding.get("service"),
                    finding.get("evidence"),
                    finding.get("confidence"),
                    finding.get("impact"),
                    finding.get("recommendation"),
                    finding.get("verification"),
                    finding.get("limitation"),
                    finding.get("source"),
                    finding.get("risk_score"),
                    finding.get("risk_label"),
                    finding.get("fix_priority"),
                    finding.get("created_at"),
                )
                for finding in findings
            ],
        )

    return scan_id


def get_scan_history(target: str) -> list[dict[str, Any]]:
    """Return scan history rows for a target."""
    init_db()
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT scan_start_time, target, resolved_ip, duration_seconds,
                   total_open_ports, total_findings, highest_risk_score,
                   highest_risk_label
            FROM scans
            WHERE target = ?
            ORDER BY scan_start_time DESC, id DESC
            """,
            (target,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_latest_scan(target: str) -> dict[str, Any] | None:
    """Return the latest scan row for a target, if present."""
    init_db()
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT scan_start_time, target, resolved_ip, duration_seconds,
                   total_open_ports, total_findings, highest_risk_score,
                   highest_risk_label
            FROM scans
            WHERE target = ?
            ORDER BY scan_start_time DESC, id DESC
            LIMIT 1
            """,
            (target,),
        ).fetchone()
    return dict(row) if row else None


def _highest_risk_label(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "Informational"
    highest = max(findings, key=lambda finding: int(finding.get("risk_score", 0)))
    return str(highest.get("risk_label", "Informational"))
