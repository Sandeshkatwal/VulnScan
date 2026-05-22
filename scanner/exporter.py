"""CSV and JSON export helpers for VulScan SQLite data."""

from __future__ import annotations

import csv
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from scanner.evidence import redact_nested
from scanner.database import init_db


DB_PATH = Path("data") / "vulscan.db"
EXPORTS_DIR = Path("exports")
SUPPORTED_FORMATS = {"csv", "json"}

ASSET_FIELDS = [
    "asset_id",
    "target",
    "resolved_ip",
    "hostname",
    "first_seen",
    "last_seen",
    "total_scans",
    "last_open_port_count",
    "last_finding_count",
    "highest_risk_score",
    "highest_risk_label",
    "exposure_summary",
]

HISTORY_FIELDS = [
    "scan_id",
    "target",
    "resolved_ip",
    "scanner_version",
    "scan_mode",
    "scan_start_time",
    "scan_end_time",
    "duration_seconds",
    "total_open_ports",
    "total_findings",
    "highest_risk_score",
    "highest_risk_label",
    "created_at",
]

FINDING_FIELDS = [
    "scan_id",
    "finding_id",
    "title",
    "severity",
    "category",
    "affected_host",
    "affected_port",
    "affected_url",
    "service",
    "evidence",
    "confidence",
    "impact",
    "recommendation",
    "verification",
    "limitation",
    "source",
    "risk_score",
    "risk_label",
    "fix_priority",
    "asset_criticality",
    "asset_environment",
    "asset_business_owner",
    "asset_tags",
    "priority_score",
    "priority_label",
    "recommended_action",
    "sla_hint",
    "fix_first_rank",
    "created_at",
]

PRIORITISATION_FIELDS = [
    "scan_id",
    "finding_id",
    "title",
    "severity",
    "source",
    "risk_score",
    "risk_label",
    "priority_score",
    "priority_label",
    "asset_criticality",
    "recommended_action",
    "sla_hint",
    "fix_first_rank",
    "created_at",
]

REMEDIATION_FIELDS = [
    "finding_fingerprint",
    "finding_id",
    "target",
    "title",
    "status",
    "owner",
    "note",
    "first_seen",
    "last_seen",
    "updated_at",
]


def export_assets(format_name: str) -> dict[str, Any]:
    """Export asset inventory records."""
    return _export_rows(
        export_type="assets",
        table_name="assets",
        fields=ASSET_FIELDS,
        query=f"""
            SELECT {", ".join(ASSET_FIELDS)}
            FROM assets
            ORDER BY last_seen DESC, target ASC
        """,
        parameters=(),
        format_name=format_name,
    )


def export_history(format_name: str, target: str | None = None) -> dict[str, Any]:
    """Export scan history records."""
    where_clause = "WHERE target = ?" if target else ""
    parameters: tuple[Any, ...] = (target,) if target else ()
    return _export_rows(
        export_type="history",
        table_name="scans",
        fields=HISTORY_FIELDS,
        query=f"""
            SELECT {", ".join(HISTORY_FIELDS)}
            FROM scans
            {where_clause}
            ORDER BY scan_start_time DESC, id DESC
        """,
        parameters=parameters,
        format_name=format_name,
        target=target,
    )


def export_findings(format_name: str, target: str | None = None) -> dict[str, Any]:
    """Export finding records."""
    if target:
        query = f"""
            SELECT f.{", f.".join(FINDING_FIELDS)}
            FROM findings f
            INNER JOIN scans s ON s.scan_id = f.scan_id
            WHERE s.target = ?
            ORDER BY f.risk_score DESC, f.created_at DESC
        """
        parameters: tuple[Any, ...] = (target,)
    else:
        query = f"""
            SELECT {", ".join(FINDING_FIELDS)}
            FROM findings
            ORDER BY risk_score DESC, created_at DESC
        """
        parameters = ()

    return _export_rows(
        export_type="findings",
        table_name="findings",
        fields=FINDING_FIELDS,
        query=query,
        parameters=parameters,
        format_name=format_name,
        target=target,
    )


def export_prioritisation(format_name: str, target: str | None = None) -> dict[str, Any]:
    """Export saved prioritisation fields for findings."""
    if target:
        query = f"""
            SELECT f.{", f.".join(PRIORITISATION_FIELDS)}
            FROM findings f
            INNER JOIN scans s ON s.scan_id = f.scan_id
            WHERE s.target = ? AND f.priority_score IS NOT NULL
            ORDER BY f.priority_score DESC, f.fix_first_rank ASC, f.created_at DESC
        """
        parameters: tuple[Any, ...] = (target,)
    else:
        query = f"""
            SELECT {", ".join(PRIORITISATION_FIELDS)}
            FROM findings
            WHERE priority_score IS NOT NULL
            ORDER BY priority_score DESC, fix_first_rank ASC, created_at DESC
        """
        parameters = ()

    return _export_rows(
        export_type="prioritisation",
        table_name="findings",
        fields=PRIORITISATION_FIELDS,
        query=query,
        parameters=parameters,
        format_name=format_name,
        target=target,
    )


def export_remediation(format_name: str, target: str | None = None) -> dict[str, Any]:
    """Export remediation status records."""
    where_clause = "WHERE target = ?" if target else ""
    parameters: tuple[Any, ...] = (target,) if target else ()
    return _export_rows(
        export_type="remediation",
        table_name="remediation_status",
        fields=REMEDIATION_FIELDS,
        query=f"""
            SELECT {", ".join(REMEDIATION_FIELDS)}
            FROM remediation_status
            {where_clause}
            ORDER BY updated_at DESC, title ASC
        """,
        parameters=parameters,
        format_name=format_name,
        target=target,
    )


def _export_rows(
    export_type: str,
    table_name: str,
    fields: list[str],
    query: str,
    parameters: tuple[Any, ...],
    format_name: str,
    target: str | None = None,
) -> dict[str, Any]:
    normalized_format = format_name.strip().lower()
    if normalized_format not in SUPPORTED_FORMATS:
        return {
            "status": "unsupported_format",
            "message": "Supported formats are csv and json.",
        }

    if not DB_PATH.exists():
        return {
            "status": "missing_database",
            "message": "No local SQLite database exists. Run a scan with --save-db first.",
        }
    init_db(DB_PATH)

    if not _table_exists(table_name):
        return {
            "status": "missing_table",
            "message": f"Table '{table_name}' does not exist. Run a scan with --save-db first.",
        }

    rows = [redact_nested(row) for row in _fetch_rows(query, parameters)]
    if not rows:
        return {
            "status": "no_records",
            "message": f"No {export_type} records were found to export.",
            "record_count": 0,
        }

    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    output_path = EXPORTS_DIR / _build_export_filename(export_type, normalized_format, target)
    if normalized_format == "csv":
        _write_csv(output_path, fields, rows)
    else:
        _write_json(output_path, rows)

    return {
        "status": "exported",
        "export_type": export_type,
        "format": normalized_format,
        "record_count": len(rows),
        "path": output_path,
    }


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def _table_exists(table_name: str) -> bool:
    with _connect() as connection:
        row = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table' AND name = ?
            """,
            (table_name,),
        ).fetchone()
    return row is not None


def _fetch_rows(query: str, parameters: tuple[Any, ...]) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [dict(row) for row in rows]


def _write_csv(output_path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    with output_path.open("w", newline="", encoding="utf-8") as file_handle:
        writer = csv.DictWriter(file_handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _write_json(output_path: Path, rows: list[dict[str, Any]]) -> None:
    output_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")


def _build_export_filename(export_type: str, format_name: str, target: str | None = None) -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    if target:
        return f"{export_type}_{_windows_safe_filename_part(target)}_{timestamp}.{format_name}"
    return f"{export_type}_{timestamp}.{format_name}"


def _windows_safe_filename_part(value: str) -> str:
    invalid = set('<>:"/\\|?*')
    cleaned = "".join("_" if character in invalid or character.isspace() else character for character in value)
    cleaned = cleaned.strip("._")
    return cleaned or "target"
