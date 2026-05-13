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
                created_at TEXT
            )
            """
        )
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
                created_at TEXT
            )
            """
        )
