"""API helpers for local submission and retest tracking."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scanner.database import DB_PATH
from scanner.submission_tracker import (
    add_submission_note,
    create_retest,
    create_submission,
    get_retest,
    get_submission,
    get_submission_summary,
    get_submission_timeline,
    list_retests,
    list_submissions,
    update_payment,
    update_retest,
    update_submission,
    update_submission_status,
)


def api_list_submissions(status: str | None = None, db_path: Path | str = DB_PATH) -> dict[str, Any]:
    return {"submissions": list_submissions(status=status, db_path=db_path)}


def api_create_submission(payload: dict[str, Any], db_path: Path | str = DB_PATH) -> dict[str, Any]:
    return create_submission(db_path=db_path, **payload)


def api_get_submission(submission_id: str, db_path: Path | str = DB_PATH) -> dict[str, Any] | None:
    record = get_submission(submission_id, db_path=db_path)
    if record is not None:
        record["timeline"] = get_submission_timeline(submission_id, db_path=db_path)
        record["retests"] = list_retests(submission_id=submission_id, db_path=db_path)
    return record


def api_update_submission(submission_id: str, payload: dict[str, Any], db_path: Path | str = DB_PATH) -> dict[str, Any] | None:
    if "bounty_amount" in payload or "bounty_currency" in payload:
        updated = update_payment(
            submission_id,
            bounty_amount=payload.pop("bounty_amount", None),
            bounty_currency=payload.pop("bounty_currency", None),
            status=payload.pop("status", None),
            db_path=db_path,
        )
        if payload:
            return update_submission(submission_id, db_path=db_path, **payload)
        return updated
    if "status" in payload:
        status = payload.pop("status")
        note = payload.pop("note", None)
        updated = update_submission_status(submission_id, status, note=note, db_path=db_path)
        if payload:
            return update_submission(submission_id, db_path=db_path, **payload)
        return updated
    return update_submission(submission_id, db_path=db_path, **payload)


def api_list_retests(submission_id: str | None = None, db_path: Path | str = DB_PATH) -> dict[str, Any]:
    return {"retests": list_retests(submission_id=submission_id, db_path=db_path)}


def api_create_retest(payload: dict[str, Any], db_path: Path | str = DB_PATH) -> dict[str, Any]:
    return create_retest(db_path=db_path, **payload)


def api_get_retest(retest_id: str, db_path: Path | str = DB_PATH) -> dict[str, Any] | None:
    return get_retest(retest_id, db_path=db_path)


def api_update_retest(retest_id: str, payload: dict[str, Any], db_path: Path | str = DB_PATH) -> dict[str, Any] | None:
    return update_retest(retest_id, db_path=db_path, **payload)


def api_summary(db_path: Path | str = DB_PATH) -> dict[str, Any]:
    return get_submission_summary(db_path=db_path)


__all__ = [
    "add_submission_note",
    "api_create_retest",
    "api_create_submission",
    "api_get_retest",
    "api_get_submission",
    "api_list_retests",
    "api_list_submissions",
    "api_summary",
    "api_update_retest",
    "api_update_submission",
    "get_submission_timeline",
    "update_submission_status",
]
