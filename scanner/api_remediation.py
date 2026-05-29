"""Tracking-only remediation API helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.database import DB_PATH, get_connection, init_db
from scanner.remediation import finding_fingerprint, short_fingerprint


API_TO_DB_STATUS = {
    "open": "Open",
    "in_progress": "In Progress",
    "fixed": "Fixed",
    "accepted_risk": "Accepted Risk",
    "false_positive": "False Positive",
}
DB_TO_API_STATUS = {value: key for key, value in API_TO_DB_STATUS.items()}
UNSAFE_NOTE_TOKENS = ("password", "token", "secret", "private_key", "api_key", "credential")
MAX_NOTE_LENGTH = 1000


def build_remediation_finding_key(finding: dict[str, Any], target: str | None = None) -> str:
    """Return the stable remediation key used by existing CLI tracking."""
    enriched = dict(finding)
    if target and not enriched.get("affected_host"):
        enriched["affected_host"] = target
    return finding_fingerprint(enriched)


def attach_finding_keys(findings: list[dict[str, Any]], target: str | None = None, db_path: Path | str = DB_PATH) -> list[dict[str, Any]]:
    """Attach remediation key/status fields to findings without creating records."""
    init_db(Path(db_path))
    with get_connection(Path(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT finding_fingerprint, status, owner, due_date, note, updated_at
            FROM remediation_status
            """
        ).fetchall()
    by_key = {str(row["finding_fingerprint"]): dict(row) for row in rows}

    for finding in findings:
        key = str(finding.get("remediation_fingerprint") or build_remediation_finding_key(finding, target))
        finding["finding_key"] = key
        finding["remediation_fingerprint"] = key
        finding["remediation_fingerprint_short"] = short_fingerprint(key)
        record = by_key.get(key)
        if record:
            finding["remediation_status"] = normalize_db_status(record.get("status"))
            finding["remediation_owner"] = record.get("owner")
            finding["remediation_due_date"] = record.get("due_date")
            finding["remediation_note"] = record.get("note")
            finding["remediation_updated_at"] = record.get("updated_at")
    return findings


def list_remediation_records(
    *,
    target: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    priority_label: str | None = None,
    db_path: Path | str = DB_PATH,
) -> list[dict[str, Any]]:
    init_db(Path(db_path))
    clauses: list[str] = []
    values: list[Any] = []
    if target:
        clauses.append("target = ?")
        values.append(target)
    if status:
        db_status = status_to_db(status)
        clauses.append("status = ?")
        values.append(db_status)
    if severity:
        clauses.append("LOWER(COALESCE(severity, '')) = LOWER(?)")
        values.append(severity)
    if source:
        clauses.append("LOWER(COALESCE(source, '')) = LOWER(?)")
        values.append(source)
    if priority_label:
        clauses.append("LOWER(COALESCE(priority_label, '')) = LOWER(?)")
        values.append(priority_label)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with get_connection(Path(db_path)) as connection:
        rows = connection.execute(
            f"""
            SELECT finding_fingerprint, finding_id, target, title, source, category,
                   severity, priority_label, status, owner, due_date, note,
                   first_seen, last_seen, created_at, updated_at
            FROM remediation_status
            {where}
            ORDER BY updated_at DESC, last_seen DESC, title ASC
            """,
            values,
        ).fetchall()
    return [_public_record(dict(row)) for row in rows]


def get_remediation_record(finding_key: str, db_path: Path | str = DB_PATH) -> dict[str, Any] | None:
    init_db(Path(db_path))
    full_key = _resolve_key(finding_key, db_path)
    if not full_key:
        return None
    with get_connection(Path(db_path)) as connection:
        row = connection.execute(
            """
            SELECT finding_fingerprint, finding_id, target, title, source, category,
                   severity, priority_label, status, owner, due_date, note,
                   first_seen, last_seen, created_at, updated_at
            FROM remediation_status
            WHERE finding_fingerprint = ?
            """,
            (full_key,),
        ).fetchone()
        history_rows = connection.execute(
            """
            SELECT old_status, new_status, note, updated_at
            FROM remediation_history
            WHERE finding_fingerprint = ?
            ORDER BY updated_at DESC, id DESC
            LIMIT 20
            """,
            (full_key,),
        ).fetchall()
    if row is None:
        return None
    record = _public_record(dict(row))
    record["history"] = [_public_history(dict(history)) for history in history_rows]
    return record


def update_remediation_record(
    finding_key: str,
    *,
    status: str,
    note: str | None = None,
    owner: str | None = None,
    due_date: str | None = None,
    db_path: Path | str = DB_PATH,
) -> dict[str, Any] | None:
    db_status = status_to_db(status)
    clean_note = validate_note(note)
    clean_owner = validate_text(owner, "owner", 255)
    clean_due_date = validate_due_date(due_date)
    init_db(Path(db_path))
    full_key = _resolve_key(finding_key, db_path)
    if not full_key:
        return None

    now = _now()
    with get_connection(Path(db_path)) as connection:
        row = connection.execute(
            "SELECT status FROM remediation_status WHERE finding_fingerprint = ?",
            (full_key,),
        ).fetchone()
        if row is None:
            return None
        old_status = str(row["status"])
        connection.execute(
            """
            UPDATE remediation_status
            SET status = ?, owner = COALESCE(?, owner),
                due_date = COALESCE(?, due_date),
                note = COALESCE(?, note), updated_at = ?
            WHERE finding_fingerprint = ?
            """,
            (db_status, clean_owner, clean_due_date, clean_note, now, full_key),
        )
        connection.execute(
            """
            INSERT INTO remediation_history (
                finding_fingerprint, old_status, new_status, note, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (full_key, old_status, db_status, clean_note, now),
        )
    return get_remediation_record(full_key, db_path)


def get_remediation_summary(db_path: Path | str = DB_PATH) -> dict[str, int]:
    init_db(Path(db_path))
    summary = {
        "open_count": 0,
        "in_progress_count": 0,
        "fixed_count": 0,
        "accepted_risk_count": 0,
        "false_positive_count": 0,
        "overdue_count": 0,
        "total_count": 0,
    }
    today = datetime.now(timezone.utc).date().isoformat()
    with get_connection(Path(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT status, COUNT(*) AS count
            FROM remediation_status
            GROUP BY status
            """
        ).fetchall()
        overdue = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM remediation_status
            WHERE due_date IS NOT NULL
              AND due_date < ?
              AND status NOT IN ('Fixed', 'Accepted Risk', 'False Positive')
            """,
            (today,),
        ).fetchone()
    for row in rows:
        api_status = normalize_db_status(row["status"])
        key = f"{api_status}_count"
        if key in summary:
            summary[key] = int(row["count"])
        summary["total_count"] += int(row["count"])
    summary["overdue_count"] = int(overdue["count"]) if overdue else 0
    return summary


def status_to_db(status: str) -> str:
    normalized = str(status or "").strip().lower()
    if normalized not in API_TO_DB_STATUS:
        raise ValueError("Invalid remediation status.")
    return API_TO_DB_STATUS[normalized]


def normalize_db_status(status: Any) -> str:
    return DB_TO_API_STATUS.get(str(status or ""), "open")


def validate_note(note: str | None) -> str | None:
    if note is None:
        return None
    value = str(note).strip()
    if len(value) > MAX_NOTE_LENGTH:
        raise ValueError("Remediation note must be 1000 characters or fewer.")
    lowered = value.lower()
    if any(token in lowered for token in UNSAFE_NOTE_TOKENS):
        raise ValueError("Remediation notes must not contain secrets or credential-like content.")
    return value


def validate_text(value: str | None, field_name: str, max_length: int) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    if len(cleaned) > max_length:
        raise ValueError(f"{field_name} must be {max_length} characters or fewer.")
    lowered = cleaned.lower()
    if any(token in lowered for token in UNSAFE_NOTE_TOKENS):
        raise ValueError(f"{field_name} must not contain secrets or credential-like content.")
    return cleaned


def validate_due_date(value: str | None) -> str | None:
    if value is None or str(value).strip() == "":
        return None
    cleaned = str(value).strip()
    try:
        datetime.fromisoformat(cleaned)
    except ValueError as exc:
        raise ValueError("due_date must be an ISO date or datetime.") from exc
    return cleaned


def _resolve_key(finding_key: str, db_path: Path | str) -> str | None:
    normalized = str(finding_key or "").strip().upper()
    if not normalized:
        return None
    with get_connection(Path(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT finding_fingerprint
            FROM remediation_status
            WHERE UPPER(finding_fingerprint) LIKE ?
            """,
            (f"{normalized}%",),
        ).fetchall()
    if len(rows) != 1:
        return None
    return str(rows[0]["finding_fingerprint"])


def _public_record(row: dict[str, Any]) -> dict[str, Any]:
    finding_key = str(row.get("finding_fingerprint") or "")
    return {
        "finding_key": finding_key,
        "finding_key_short": short_fingerprint(finding_key),
        "finding_id": row.get("finding_id"),
        "target": row.get("target"),
        "title": row.get("title"),
        "source": row.get("source"),
        "category": row.get("category"),
        "severity": row.get("severity"),
        "priority_label": row.get("priority_label"),
        "status": normalize_db_status(row.get("status")),
        "owner": row.get("owner"),
        "due_date": row.get("due_date"),
        "note": row.get("note"),
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
        "created_at": row.get("created_at") or row.get("first_seen"),
        "updated_at": row.get("updated_at"),
    }


def _public_history(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "old_status": normalize_db_status(row.get("old_status")),
        "new_status": normalize_db_status(row.get("new_status")),
        "note": row.get("note"),
        "updated_at": row.get("updated_at"),
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
