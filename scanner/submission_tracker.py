"""Local submission and retest tracking for Security Finding Reports."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.database import DB_PATH, get_connection, init_db
from scanner.evidence import redact_secrets


SUBMISSION_STATUSES = {
    "draft",
    "ready_for_review",
    "submitted",
    "triaged",
    "accepted",
    "duplicate",
    "informative",
    "not_applicable",
    "resolved",
    "paid",
    "closed",
}
RETEST_STATUSES = {
    "not_required",
    "retest_required",
    "retest_in_progress",
    "retest_passed",
    "retest_failed",
    "retest_blocked",
}
RETEST_RESULTS = {
    "",
    "issue_no_longer_reproducible",
    "issue_still_reproducible",
    "unable_to_test",
    "out_of_scope_now",
    "environment_unavailable",
}
TIMELINE_EVENT_TYPES = {
    "created",
    "status_changed",
    "note_added",
    "evidence_linked",
    "retest_requested",
    "retest_updated",
    "payment_updated",
    "closed",
}
MAX_NOTE_LENGTH = 2000
FORBIDDEN_PAYLOAD_FIELDS = {
    "api_key",
    "api_token",
    "token",
    "password",
    "session",
    "cookie",
    "authorization",
    "bearer",
    "jwt",
    "private_key",
    "platform_password",
    "platform_token",
    "platform_api_key",
}


class SubmissionTrackerError(ValueError):
    """Raised for local submission tracker validation errors."""


def create_submission(
    *,
    report_id: str | None = None,
    evidence_ids: list[str] | None = None,
    finding_title: str | None = None,
    program_name: str | None = None,
    platform: str | None = None,
    submission_url: str | None = None,
    external_reference: str | None = None,
    status: str = "draft",
    severity_submitted: str | None = None,
    notes: str | None = None,
    db_path: Path | str = DB_PATH,
    **extra: Any,
) -> dict[str, Any]:
    _reject_secret_fields(extra)
    normalized_status = _validate_status(status, SUBMISSION_STATUSES, "submission status")
    now = _now()
    submission_id = _new_id("sub")
    safe_notes, redacted = _safe_note(notes)
    record = {
        "submission_id": submission_id,
        "report_id": _safe_text(report_id, 255),
        "evidence_ids_json": json.dumps([_safe_text(item, 255) for item in evidence_ids or []]),
        "finding_title": _safe_text(finding_title, 500),
        "program_name": _safe_text(program_name, 255),
        "platform": _safe_text(platform or "manual", 100),
        "submission_url": _safe_text(submission_url, 1000),
        "external_reference": _safe_text(external_reference, 255),
        "status": normalized_status,
        "severity_submitted": _safe_text(severity_submitted, 50),
        "severity_accepted": None,
        "duplicate_of": None,
        "bounty_amount": None,
        "bounty_currency": None,
        "submitted_at": now if normalized_status == "submitted" else None,
        "triaged_at": now if normalized_status == "triaged" else None,
        "accepted_at": now if normalized_status == "accepted" else None,
        "resolved_at": now if normalized_status == "resolved" else None,
        "paid_at": now if normalized_status == "paid" else None,
        "next_follow_up_date": None,
        "notes": safe_notes,
        "safe_notes_redacted": int(redacted),
        "created_at": now,
        "updated_at": now,
    }
    init_db(Path(db_path))
    with get_connection(Path(db_path)) as connection:
        connection.execute(
            """
            INSERT INTO security_submissions (
                submission_id, report_id, evidence_ids_json, finding_title, program_name,
                platform, submission_url, external_reference, status, severity_submitted,
                severity_accepted, duplicate_of, bounty_amount, bounty_currency,
                submitted_at, triaged_at, accepted_at, resolved_at, paid_at,
                next_follow_up_date, notes, safe_notes_redacted, created_at, updated_at
            ) VALUES (
                :submission_id, :report_id, :evidence_ids_json, :finding_title, :program_name,
                :platform, :submission_url, :external_reference, :status, :severity_submitted,
                :severity_accepted, :duplicate_of, :bounty_amount, :bounty_currency,
                :submitted_at, :triaged_at, :accepted_at, :resolved_at, :paid_at,
                :next_follow_up_date, :notes, :safe_notes_redacted, :created_at, :updated_at
            )
            """,
            record,
        )
        _insert_event(connection, submission_id, "created", None, normalized_status, safe_notes, now)
    return get_submission(submission_id, db_path) or {}


def list_submissions(status: str | None = None, db_path: Path | str = DB_PATH) -> list[dict[str, Any]]:
    init_db(Path(db_path))
    clauses: list[str] = []
    values: list[Any] = []
    if status:
        clauses.append("status = ?")
        values.append(_validate_status(status, SUBMISSION_STATUSES, "submission status"))
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with get_connection(Path(db_path)) as connection:
        rows = connection.execute(
            f"""
            SELECT *
            FROM security_submissions
            {where}
            ORDER BY updated_at DESC, created_at DESC
            """,
            values,
        ).fetchall()
    return [_public_submission(dict(row)) for row in rows]


def get_submission(submission_id: str, db_path: Path | str = DB_PATH) -> dict[str, Any] | None:
    init_db(Path(db_path))
    with get_connection(Path(db_path)) as connection:
        row = connection.execute("SELECT * FROM security_submissions WHERE submission_id = ?", (submission_id,)).fetchone()
    return _public_submission(dict(row)) if row else None


def update_submission(submission_id: str, db_path: Path | str = DB_PATH, **updates: Any) -> dict[str, Any] | None:
    _reject_secret_fields(updates)
    allowed = {
        "report_id",
        "evidence_ids",
        "finding_title",
        "program_name",
        "platform",
        "submission_url",
        "external_reference",
        "severity_submitted",
        "severity_accepted",
        "duplicate_of",
        "next_follow_up_date",
        "notes",
    }
    clean: dict[str, Any] = {}
    redacted = None
    for key, value in updates.items():
        if key not in allowed or value is None:
            continue
        if key == "evidence_ids":
            clean["evidence_ids_json"] = json.dumps([_safe_text(item, 255) for item in value or []])
        elif key == "notes":
            clean["notes"], redacted = _safe_note(value)
            clean["safe_notes_redacted"] = int(redacted)
        else:
            clean[key] = _safe_text(value, 1000 if key == "submission_url" else 500)
    if not clean:
        return get_submission(submission_id, db_path)
    clean["updated_at"] = _now()
    assignments = ", ".join(f"{key} = :{key}" for key in clean)
    clean["submission_id"] = submission_id
    init_db(Path(db_path))
    with get_connection(Path(db_path)) as connection:
        existing = connection.execute("SELECT submission_id FROM security_submissions WHERE submission_id = ?", (submission_id,)).fetchone()
        if existing is None:
            return None
        connection.execute(f"UPDATE security_submissions SET {assignments} WHERE submission_id = :submission_id", clean)
        if "evidence_ids_json" in clean:
            _insert_event(connection, submission_id, "evidence_linked", None, None, "Evidence references updated.", clean["updated_at"])
        if "notes" in clean:
            _insert_event(connection, submission_id, "note_added", None, None, clean["notes"], clean["updated_at"])
    return get_submission(submission_id, db_path)


def update_submission_status(submission_id: str, status: str, note: str | None = None, db_path: Path | str = DB_PATH) -> dict[str, Any] | None:
    normalized = _validate_status(status, SUBMISSION_STATUSES, "submission status")
    safe_note, _ = _safe_note(note)
    now = _now()
    timestamp_field = {
        "submitted": "submitted_at",
        "triaged": "triaged_at",
        "accepted": "accepted_at",
        "resolved": "resolved_at",
        "paid": "paid_at",
    }.get(normalized)
    init_db(Path(db_path))
    with get_connection(Path(db_path)) as connection:
        row = connection.execute("SELECT status, notes FROM security_submissions WHERE submission_id = ?", (submission_id,)).fetchone()
        if row is None:
            return None
        old_status = str(row["status"] or "")
        fields = ["status = ?", "updated_at = ?"]
        values: list[Any] = [normalized, now]
        if safe_note:
            fields.append("notes = ?")
            values.append(safe_note)
        if timestamp_field:
            fields.append(f"{timestamp_field} = COALESCE({timestamp_field}, ?)")
            values.append(now)
        values.append(submission_id)
        connection.execute(f"UPDATE security_submissions SET {', '.join(fields)} WHERE submission_id = ?", values)
        event_type = "closed" if normalized == "closed" else "status_changed"
        _insert_event(connection, submission_id, event_type, old_status, normalized, safe_note, now)
    return get_submission(submission_id, db_path)


def add_submission_note(submission_id: str, note: str, db_path: Path | str = DB_PATH) -> dict[str, Any] | None:
    safe_note, redacted = _safe_note(note)
    now = _now()
    init_db(Path(db_path))
    with get_connection(Path(db_path)) as connection:
        row = connection.execute("SELECT notes FROM security_submissions WHERE submission_id = ?", (submission_id,)).fetchone()
        if row is None:
            return None
        existing = str(row["notes"] or "")
        combined = "\n".join(item for item in [existing, safe_note] if item).strip()
        if len(combined) > MAX_NOTE_LENGTH:
            combined = combined[-MAX_NOTE_LENGTH:]
        connection.execute(
            "UPDATE security_submissions SET notes = ?, safe_notes_redacted = ?, updated_at = ? WHERE submission_id = ?",
            (combined, int(redacted or "[REDACTED]" in combined), now, submission_id),
        )
        _insert_event(connection, submission_id, "note_added", None, None, safe_note, now)
    return get_submission(submission_id, db_path)


def update_payment(
    submission_id: str,
    *,
    bounty_amount: str | int | float | None = None,
    bounty_currency: str | None = None,
    status: str | None = None,
    db_path: Path | str = DB_PATH,
) -> dict[str, Any] | None:
    now = _now()
    clean_status = _validate_status(status, SUBMISSION_STATUSES, "submission status") if status else None
    init_db(Path(db_path))
    with get_connection(Path(db_path)) as connection:
        row = connection.execute("SELECT status FROM security_submissions WHERE submission_id = ?", (submission_id,)).fetchone()
        if row is None:
            return None
        old_status = str(row["status"] or "")
        connection.execute(
            """
            UPDATE security_submissions
            SET bounty_amount = COALESCE(?, bounty_amount),
                bounty_currency = COALESCE(?, bounty_currency),
                status = COALESCE(?, status),
                paid_at = CASE WHEN ? = 'paid' THEN COALESCE(paid_at, ?) ELSE paid_at END,
                updated_at = ?
            WHERE submission_id = ?
            """,
            (_safe_text(bounty_amount, 50), _safe_text(bounty_currency, 10), clean_status, clean_status, now, now, submission_id),
        )
        _insert_event(connection, submission_id, "payment_updated", old_status, clean_status or old_status, "Payment outcome updated.", now)
    return get_submission(submission_id, db_path)


def get_submission_timeline(submission_id: str, db_path: Path | str = DB_PATH) -> list[dict[str, Any]]:
    init_db(Path(db_path))
    with get_connection(Path(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT event_id, submission_id, event_type, old_status, new_status, note, created_at
            FROM security_submission_timeline
            WHERE submission_id = ?
            ORDER BY created_at ASC
            """,
            (submission_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def create_retest(
    *,
    submission_id: str,
    report_id: str | None = None,
    target: str | None = None,
    affected_url: str | None = None,
    status: str = "retest_required",
    retest_result: str | None = None,
    evidence_id: str | None = None,
    notes: str | None = None,
    db_path: Path | str = DB_PATH,
    **extra: Any,
) -> dict[str, Any]:
    _reject_secret_fields(extra)
    normalized = _validate_status(status, RETEST_STATUSES, "retest status")
    result = _validate_retest_result(retest_result)
    safe_notes, _ = _safe_note(notes)
    now = _now()
    retest_id = _new_id("retest")
    record = {
        "retest_id": retest_id,
        "submission_id": _safe_text(submission_id, 255),
        "report_id": _safe_text(report_id, 255),
        "target": _safe_text(target, 255),
        "affected_url": _safe_text(affected_url, 1000),
        "status": normalized,
        "requested_at": now if normalized in {"retest_required", "retest_in_progress"} else None,
        "retested_at": now if normalized in {"retest_passed", "retest_failed", "retest_blocked"} else None,
        "retest_result": result,
        "evidence_id": _safe_text(evidence_id, 255),
        "notes": safe_notes,
        "created_at": now,
        "updated_at": now,
    }
    init_db(Path(db_path))
    with get_connection(Path(db_path)) as connection:
        connection.execute(
            """
            INSERT INTO security_retests (
                retest_id, submission_id, report_id, target, affected_url, status,
                requested_at, retested_at, retest_result, evidence_id, notes, created_at, updated_at
            ) VALUES (
                :retest_id, :submission_id, :report_id, :target, :affected_url, :status,
                :requested_at, :retested_at, :retest_result, :evidence_id, :notes, :created_at, :updated_at
            )
            """,
            record,
        )
        _insert_event(connection, submission_id, "retest_requested", None, normalized, safe_notes, now)
    return get_retest(retest_id, db_path) or {}


def list_retests(submission_id: str | None = None, db_path: Path | str = DB_PATH) -> list[dict[str, Any]]:
    init_db(Path(db_path))
    values: list[Any] = []
    where = ""
    if submission_id:
        where = "WHERE submission_id = ?"
        values.append(submission_id)
    with get_connection(Path(db_path)) as connection:
        rows = connection.execute(f"SELECT * FROM security_retests {where} ORDER BY updated_at DESC", values).fetchall()
    return [dict(row) for row in rows]


def get_retest(retest_id: str, db_path: Path | str = DB_PATH) -> dict[str, Any] | None:
    init_db(Path(db_path))
    with get_connection(Path(db_path)) as connection:
        row = connection.execute("SELECT * FROM security_retests WHERE retest_id = ?", (retest_id,)).fetchone()
    return dict(row) if row else None


def update_retest(retest_id: str, db_path: Path | str = DB_PATH, **updates: Any) -> dict[str, Any] | None:
    _reject_secret_fields(updates)
    existing = get_retest(retest_id, db_path)
    if existing is None:
        return None
    clean: dict[str, Any] = {}
    for key in ("report_id", "target", "affected_url", "evidence_id"):
        if updates.get(key) is not None:
            clean[key] = _safe_text(updates[key], 1000 if key == "affected_url" else 255)
    if updates.get("status") is not None:
        clean["status"] = _validate_status(updates["status"], RETEST_STATUSES, "retest status")
        if clean["status"] in {"retest_passed", "retest_failed", "retest_blocked"}:
            clean["retested_at"] = updates.get("retested_at") or _now()
    if updates.get("retest_result") is not None:
        clean["retest_result"] = _validate_retest_result(updates.get("retest_result"))
    if updates.get("notes") is not None:
        clean["notes"], _ = _safe_note(updates.get("notes"))
    if not clean:
        return existing
    clean["updated_at"] = _now()
    clean["retest_id"] = retest_id
    assignments = ", ".join(f"{key} = :{key}" for key in clean)
    with get_connection(Path(db_path)) as connection:
        connection.execute(f"UPDATE security_retests SET {assignments} WHERE retest_id = :retest_id", clean)
        _insert_event(
            connection,
            str(existing.get("submission_id") or ""),
            "retest_updated",
            str(existing.get("status") or ""),
            str(clean.get("status") or existing.get("status") or ""),
            str(clean.get("notes") or "Retest updated."),
            clean["updated_at"],
        )
    return get_retest(retest_id, db_path)


def get_submission_summary(db_path: Path | str = DB_PATH) -> dict[str, Any]:
    init_db(Path(db_path))
    summary: dict[str, Any] = {
        "total_count": 0,
        "draft_count": 0,
        "submitted_count": 0,
        "triaged_count": 0,
        "accepted_count": 0,
        "duplicate_count": 0,
        "resolved_count": 0,
        "paid_count": 0,
        "retest_required_count": 0,
        "retest_passed_count": 0,
        "retest_failed_count": 0,
        "total_bounty_amount_by_currency": {},
    }
    with get_connection(Path(db_path)) as connection:
        status_rows = connection.execute("SELECT status, COUNT(*) AS count FROM security_submissions GROUP BY status").fetchall()
        retest_rows = connection.execute("SELECT status, COUNT(*) AS count FROM security_retests GROUP BY status").fetchall()
        bounty_rows = connection.execute(
            """
            SELECT bounty_currency, bounty_amount
            FROM security_submissions
            WHERE bounty_currency IS NOT NULL AND bounty_amount IS NOT NULL
            """
        ).fetchall()
    for row in status_rows:
        count = int(row["count"])
        status = str(row["status"] or "")
        summary["total_count"] += count
        key = f"{status}_count"
        if key in summary:
            summary[key] = count
    for row in retest_rows:
        key = f"{str(row['status'] or '')}_count"
        if key in summary:
            summary[key] = int(row["count"])
    totals: dict[str, float] = {}
    for row in bounty_rows:
        currency = str(row["bounty_currency"] or "").upper()
        try:
            amount = float(row["bounty_amount"])
        except (TypeError, ValueError):
            continue
        totals[currency] = totals.get(currency, 0.0) + amount
    summary["total_bounty_amount_by_currency"] = totals
    return summary


def _public_submission(row: dict[str, Any]) -> dict[str, Any]:
    row["evidence_ids"] = json.loads(row.pop("evidence_ids_json") or "[]")
    row["safe_notes_redacted"] = bool(row.get("safe_notes_redacted"))
    return row


def _insert_event(
    connection: Any,
    submission_id: str,
    event_type: str,
    old_status: str | None,
    new_status: str | None,
    note: str | None,
    created_at: str,
) -> None:
    if event_type not in TIMELINE_EVENT_TYPES:
        event_type = "note_added"
    safe_note, _ = _safe_note(note)
    connection.execute(
        """
        INSERT INTO security_submission_timeline (
            event_id, submission_id, event_type, old_status, new_status, note, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (_new_id("evt"), submission_id, event_type, old_status, new_status, safe_note, created_at),
    )


def _validate_status(status: Any, allowed: set[str], label: str) -> str:
    normalized = str(status or "").strip().lower()
    if normalized not in allowed:
        raise SubmissionTrackerError(f"Invalid {label}: {status}")
    return normalized


def _validate_retest_result(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized not in RETEST_RESULTS:
        raise SubmissionTrackerError(f"Invalid retest result: {value}")
    return normalized


def _safe_note(value: Any) -> tuple[str, bool]:
    if value is None:
        return "", False
    text = str(value).strip()
    if len(text) > MAX_NOTE_LENGTH:
        text = text[:MAX_NOTE_LENGTH]
    redacted, changed = redact_secrets(text)
    lowered = redacted.lower()
    for token in FORBIDDEN_PAYLOAD_FIELDS:
        redacted = redacted.replace(token, "[REDACTED]")
    return redacted, bool(changed or "[REDACTED]" in redacted or lowered != redacted.lower())


def _safe_text(value: Any, max_length: int) -> str:
    if value is None:
        return ""
    text, _ = redact_secrets(str(value).strip())
    return text[:max_length]


def _reject_secret_fields(payload: dict[str, Any]) -> None:
    lowered_keys = {str(key).lower() for key in payload}
    if lowered_keys & FORBIDDEN_PAYLOAD_FIELDS:
        raise SubmissionTrackerError("Platform credentials, API tokens, cookies, and secrets are not accepted.")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
