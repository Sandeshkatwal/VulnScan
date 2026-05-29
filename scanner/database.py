"""SQLite database helpers for VulScan scan history."""

from __future__ import annotations

import sqlite3
from pathlib import Path


DB_PATH = Path("data") / "vulscan.db"
REQUIRED_TABLES = {"scans", "open_ports", "findings"}


def database_exists(db_path: Path = DB_PATH) -> bool:
    """Return whether the local scan history database exists."""
    return db_path.exists()


def get_missing_required_tables(db_path: Path = DB_PATH) -> set[str]:
    """Return required VulScan tables missing from an existing database."""
    if not database_exists(db_path):
        return REQUIRED_TABLES.copy()

    with get_connection(db_path) as connection:
        rows = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            """
        ).fetchall()

    existing_tables = {str(row["name"]) for row in rows}
    return REQUIRED_TABLES - existing_tables


def database_has_required_tables(db_path: Path = DB_PATH) -> bool:
    """Return whether all required VulScan tables exist."""
    return not get_missing_required_tables(db_path)


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Return a SQLite connection and ensure the data directory exists."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_db(db_path: Path = DB_PATH) -> None:
    """Initialise VulScan database tables if they do not exist."""
    with get_connection(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE,
                target TEXT,
                resolved_ip TEXT,
                scanner_version TEXT,
                scan_mode TEXT,
                scan_start_time TEXT,
                scan_end_time TEXT,
                duration_seconds REAL,
                total_open_ports INTEGER,
                total_findings INTEGER,
                highest_risk_score INTEGER,
                highest_risk_label TEXT,
                scan_result_json TEXT NULL,
                created_at TEXT
            )
            """
        )
        _ensure_column(connection, "scans", "scan_result_json", "TEXT NULL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS open_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                host TEXT,
                resolved_ip TEXT,
                port INTEGER,
                protocol TEXT,
                service TEXT,
                status TEXT,
                confidence TEXT,
                evidence TEXT,
                recommendation TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                finding_id TEXT,
                title TEXT,
                severity TEXT,
                category TEXT,
                affected_host TEXT,
                affected_port INTEGER NULL,
                affected_url TEXT NULL,
                service TEXT NULL,
                evidence TEXT,
                confidence TEXT,
                impact TEXT,
                recommendation TEXT,
                verification TEXT,
                limitation TEXT,
                source TEXT,
                risk_score INTEGER,
                risk_label TEXT,
                fix_priority TEXT,
                asset_criticality TEXT NULL,
                asset_environment TEXT NULL,
                asset_business_owner TEXT NULL,
                asset_tags TEXT NULL,
                priority_score INTEGER NULL,
                priority_label TEXT NULL,
                recommended_action TEXT NULL,
                sla_hint TEXT NULL,
                fix_first_rank INTEGER NULL,
                trend_status TEXT NULL,
                previous_priority_score INTEGER NULL,
                current_priority_score INTEGER NULL,
                score_delta INTEGER NULL,
                previous_priority_label TEXT NULL,
                current_priority_label TEXT NULL,
                created_at TEXT
            )
            """
        )
        _ensure_column(connection, "findings", "asset_criticality", "TEXT NULL")
        _ensure_column(connection, "findings", "asset_environment", "TEXT NULL")
        _ensure_column(connection, "findings", "asset_business_owner", "TEXT NULL")
        _ensure_column(connection, "findings", "asset_tags", "TEXT NULL")
        _ensure_column(connection, "findings", "priority_score", "INTEGER NULL")
        _ensure_column(connection, "findings", "priority_label", "TEXT NULL")
        _ensure_column(connection, "findings", "recommended_action", "TEXT NULL")
        _ensure_column(connection, "findings", "sla_hint", "TEXT NULL")
        _ensure_column(connection, "findings", "fix_first_rank", "INTEGER NULL")
        _ensure_column(connection, "findings", "trend_status", "TEXT NULL")
        _ensure_column(connection, "findings", "previous_priority_score", "INTEGER NULL")
        _ensure_column(connection, "findings", "current_priority_score", "INTEGER NULL")
        _ensure_column(connection, "findings", "score_delta", "INTEGER NULL")
        _ensure_column(connection, "findings", "previous_priority_label", "TEXT NULL")
        _ensure_column(connection, "findings", "current_priority_label", "TEXT NULL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS remediation_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_fingerprint TEXT NOT NULL,
                finding_id TEXT NULL,
                target TEXT NULL,
                title TEXT NOT NULL,
                source TEXT NULL,
                category TEXT NULL,
                severity TEXT NULL,
                priority_label TEXT NULL,
                status TEXT NOT NULL,
                owner TEXT NULL,
                due_date TEXT NULL,
                note TEXT NULL,
                first_seen TEXT NULL,
                last_seen TEXT NULL,
                created_at TEXT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        _ensure_column(connection, "remediation_status", "source", "TEXT NULL")
        _ensure_column(connection, "remediation_status", "category", "TEXT NULL")
        _ensure_column(connection, "remediation_status", "severity", "TEXT NULL")
        _ensure_column(connection, "remediation_status", "priority_label", "TEXT NULL")
        _ensure_column(connection, "remediation_status", "due_date", "TEXT NULL")
        _ensure_column(connection, "remediation_status", "created_at", "TEXT NULL")
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_remediation_status_fingerprint
            ON remediation_status (finding_fingerprint)
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS remediation_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_fingerprint TEXT NOT NULL,
                old_status TEXT NULL,
                new_status TEXT NOT NULL,
                note TEXT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id TEXT UNIQUE,
                target TEXT NOT NULL,
                resolved_ip TEXT NULL,
                hostname TEXT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                total_scans INTEGER DEFAULT 0,
                last_open_port_count INTEGER DEFAULT 0,
                last_finding_count INTEGER DEFAULT 0,
                highest_risk_score INTEGER DEFAULT 0,
                highest_risk_label TEXT NULL,
                exposure_summary TEXT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_target
            ON assets (target)
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS asset_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                service TEXT NULL,
                status TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                last_evidence TEXT NULL,
                last_recommendation TEXT NULL,
                UNIQUE(asset_id, port, protocol)
            )
            """
        )
        init_api_jobs_table(connection)


def init_api_jobs_table(connection: sqlite3.Connection | None = None, db_path: Path = DB_PATH) -> None:
    """Initialise persistent API job storage if it does not exist."""
    if connection is None:
        with get_connection(db_path) as managed_connection:
            init_api_jobs_table(managed_connection, db_path=db_path)
        return
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS api_jobs (
            job_id TEXT PRIMARY KEY,
            scan_id TEXT,
            target TEXT,
            status TEXT,
            created_at TEXT,
            started_at TEXT,
            completed_at TEXT,
            duration_seconds REAL,
            request_json TEXT,
            result_summary_json TEXT,
            result_path TEXT,
            html_report_path TEXT,
            error_message TEXT,
            safe_error_code TEXT,
            updated_at TEXT
        )
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_api_jobs_created_at
        ON api_jobs (created_at)
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_api_jobs_status
        ON api_jobs (status)
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_api_jobs_target
        ON api_jobs (target)
        """
    )


def _ensure_column(
    connection: sqlite3.Connection,
    table_name: str,
    column_name: str,
    column_definition: str,
) -> None:
    columns = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    existing = {str(column["name"]) for column in columns}
    if column_name not in existing:
        connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")
