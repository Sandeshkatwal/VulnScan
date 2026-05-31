"""Local Finding Fingerprinting and Duplicate Detection."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.database import DB_PATH, get_connection, init_db
from scanner.finding_fingerprint import build_finding_fingerprint


class DuplicateDetectionError(ValueError):
    """Raised for duplicate detection validation errors."""


def fingerprint_item(item: dict[str, Any], item_type: str = "candidate", db_path: Path | str = DB_PATH, store: bool = False) -> dict[str, Any]:
    fingerprint = build_finding_fingerprint(item, item_type=item_type)
    if store:
        store_fingerprint(fingerprint, db_path=db_path)
    return fingerprint


def check_duplicate(item: dict[str, Any], item_type: str = "candidate", db_path: Path | str = DB_PATH, store: bool = True) -> dict[str, Any]:
    fingerprint = build_finding_fingerprint(item, item_type=item_type)
    init_db(Path(db_path))
    with get_connection(Path(db_path)) as connection:
        existing = _existing_fingerprints(connection)
        result = _classify_duplicate(fingerprint, existing)
        if store:
            _store_fingerprint(connection, fingerprint)
            if result["duplicate_status"] != "unique":
                group_id = _ensure_group(connection, fingerprint, result)
                result["duplicate_group_id"] = group_id
                _insert_member(connection, group_id, fingerprint["fingerprint_id"], result["duplicate_status"], result["duplicate_confidence"], result["duplicate_reason"])
                for ref in result.get("existing_item_references", []):
                    if ref.get("fingerprint_id"):
                        _insert_member(connection, group_id, ref["fingerprint_id"], "primary", result["duplicate_confidence"], "Existing related fingerprint.")
            else:
                group_id = _ensure_group(connection, fingerprint, result)
                result["duplicate_group_id"] = group_id
                _insert_member(connection, group_id, fingerprint["fingerprint_id"], "unique", "Low", "Initial unique fingerprint.")
    return {"fingerprint": fingerprint, "duplicate_result": result}


def store_fingerprint(fingerprint: dict[str, Any], db_path: Path | str = DB_PATH) -> dict[str, Any]:
    init_db(Path(db_path))
    with get_connection(Path(db_path)) as connection:
        _store_fingerprint(connection, fingerprint)
    return fingerprint


def list_duplicate_groups(db_path: Path | str = DB_PATH) -> list[dict[str, Any]]:
    init_db(Path(db_path))
    with get_connection(Path(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT g.*, COUNT(m.fingerprint_id) AS member_count
            FROM duplicate_groups g
            LEFT JOIN duplicate_group_members m ON m.duplicate_group_id = g.duplicate_group_id
            GROUP BY g.duplicate_group_id
            ORDER BY g.updated_at DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def get_duplicate_group(group_id: str, db_path: Path | str = DB_PATH) -> dict[str, Any] | None:
    init_db(Path(db_path))
    with get_connection(Path(db_path)) as connection:
        group = connection.execute("SELECT * FROM duplicate_groups WHERE duplicate_group_id = ?", (group_id,)).fetchone()
        if group is None:
            return None
        members = connection.execute(
            """
            SELECT m.*, f.title, f.item_type, f.item_id, f.fingerprint_hash, f.host, f.path_normalised, f.issue_type
            FROM duplicate_group_members m
            LEFT JOIN finding_fingerprints f ON f.fingerprint_id = m.fingerprint_id
            WHERE m.duplicate_group_id = ?
            ORDER BY m.created_at ASC
            """,
            (group_id,),
        ).fetchall()
    result = dict(group)
    result["members"] = [dict(row) for row in members]
    return result


def get_fingerprint(fingerprint_id: str, db_path: Path | str = DB_PATH) -> dict[str, Any] | None:
    init_db(Path(db_path))
    with get_connection(Path(db_path)) as connection:
        row = connection.execute("SELECT * FROM finding_fingerprints WHERE fingerprint_id = ?", (fingerprint_id,)).fetchone()
    if row is None:
        return None
    return _public_fingerprint(dict(row))


def duplicate_summary(db_path: Path | str = DB_PATH) -> dict[str, Any]:
    init_db(Path(db_path))
    with get_connection(Path(db_path)) as connection:
        total = connection.execute("SELECT COUNT(*) AS count FROM finding_fingerprints").fetchone()
        groups = connection.execute("SELECT COUNT(*) AS count FROM duplicate_groups").fetchone()
        rows = connection.execute("SELECT duplicate_status, COUNT(*) AS count FROM duplicate_groups GROUP BY duplicate_status").fetchall()
    summary = {
        "enabled": True,
        "fingerprints_created": int(total["count"] if total else 0),
        "total_fingerprints": int(total["count"] if total else 0),
        "unique_findings": 0,
        "exact_duplicates": 0,
        "likely_duplicates": 0,
        "related_findings": 0,
        "duplicate_groups_count": int(groups["count"] if groups else 0),
        "limitations": ["Duplicate Detection is metadata-based and may need manual review."],
    }
    for row in rows:
        status = str(row["duplicate_status"] or "")
        count = int(row["count"])
        if status == "unique":
            summary["unique_findings"] = count
        elif status == "exact_duplicate":
            summary["exact_duplicates"] = count
        elif status == "likely_duplicate":
            summary["likely_duplicates"] = count
        elif status == "related":
            summary["related_findings"] = count
    return summary


def rebuild_from_submissions(db_path: Path | str = DB_PATH) -> dict[str, int]:
    init_db(Path(db_path))
    created = 0
    with get_connection(Path(db_path)) as connection:
        rows = connection.execute("SELECT * FROM security_submissions").fetchall()
    for row in rows:
        item = dict(row)
        item["title"] = item.get("finding_title")
        item["issue_type"] = "submission"
        check_duplicate(item, item_type="submission", db_path=db_path, store=True)
        created += 1
    return {"fingerprints_created": created}


def _classify_duplicate(fingerprint: dict[str, Any], existing: list[dict[str, Any]]) -> dict[str, Any]:
    refs: list[dict[str, Any]] = []
    for candidate in existing:
        if candidate["fingerprint_hash"] == fingerprint["fingerprint_hash"]:
            refs.append(_reference(candidate))
            return _result("exact_duplicate", "Exact", "Same stable fingerprint hash.", refs)

    incoming_params = set(fingerprint.get("parameter_names") or [])
    for candidate in existing:
        if (
            candidate.get("host") == fingerprint.get("host")
            and candidate.get("path_normalised") == fingerprint.get("path_normalised")
            and candidate.get("issue_type") == fingerprint.get("issue_type")
            and incoming_params.intersection(set(candidate.get("parameter_names") or []))
        ):
            refs.append(_reference(candidate))
            return _result("likely_duplicate", "High", "Same host, normalised path, issue type, and overlapping parameter names.", refs)

    for candidate in existing:
        if (
            candidate.get("host") == fingerprint.get("host")
            and candidate.get("issue_type") == fingerprint.get("issue_type")
            and (
                candidate.get("owasp_category")
                and candidate.get("owasp_category") == fingerprint.get("owasp_category")
                or candidate.get("source") == fingerprint.get("source")
            )
        ):
            refs.append(_reference(candidate))
            return _result("related", "Medium", "Same host and issue type with related OWASP category or source.", refs)
    return _result("unique", "Low", "No matching fingerprint found.", refs)


def _result(status: str, confidence: str, reason: str, refs: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "duplicate_status": status,
        "duplicate_confidence": confidence,
        "duplicate_reason": reason,
        "duplicate_group_id": "",
        "existing_item_references": refs,
    }


def _existing_fingerprints(connection: Any) -> list[dict[str, Any]]:
    rows = connection.execute("SELECT * FROM finding_fingerprints ORDER BY created_at ASC").fetchall()
    return [_public_fingerprint(dict(row)) for row in rows]


def _store_fingerprint(connection: Any, fingerprint: dict[str, Any]) -> None:
    now = _now()
    connection.execute(
        """
        INSERT OR IGNORE INTO finding_fingerprints (
            fingerprint_id, fingerprint_version, fingerprint_hash, item_type, item_id,
            title, target, host, path_normalised, parameter_names_json, issue_type,
            owasp_category, source, cve, data_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            fingerprint["fingerprint_id"],
            fingerprint["fingerprint_version"],
            fingerprint["fingerprint_hash"],
            fingerprint.get("item_type"),
            fingerprint.get("item_id"),
            fingerprint.get("title"),
            fingerprint.get("target_normalised"),
            fingerprint.get("host"),
            fingerprint.get("path_normalised"),
            json.dumps(fingerprint.get("parameter_names") or []),
            fingerprint.get("issue_type"),
            fingerprint.get("owasp_category"),
            fingerprint.get("source"),
            fingerprint.get("cve"),
            json.dumps(fingerprint.get("data") or {}, sort_keys=True),
            fingerprint.get("created_at") or now,
            now,
        ),
    )


def _public_fingerprint(row: dict[str, Any]) -> dict[str, Any]:
    row["parameter_names"] = json.loads(row.pop("parameter_names_json") or "[]")
    row["data"] = json.loads(row.pop("data_json") or "{}")
    row["fingerprint_short"] = str(row.get("fingerprint_hash") or "")[:12]
    return row


def _reference(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "fingerprint_id": row.get("fingerprint_id"),
        "fingerprint_short": str(row.get("fingerprint_hash") or "")[:12],
        "item_type": row.get("item_type"),
        "item_id": row.get("item_id"),
        "title": row.get("title"),
    }


def _ensure_group(connection: Any, fingerprint: dict[str, Any], result: dict[str, Any]) -> str:
    group_hash = fingerprint["fingerprint_hash"] if result["duplicate_status"] == "exact_duplicate" else f"{fingerprint.get('host')}|{fingerprint.get('issue_type')}|{fingerprint.get('path_normalised')}"
    row = connection.execute("SELECT duplicate_group_id FROM duplicate_groups WHERE group_hash = ?", (group_hash,)).fetchone()
    now = _now()
    if row:
        group_id = str(row["duplicate_group_id"])
        connection.execute("UPDATE duplicate_groups SET duplicate_status = ?, confidence = ?, updated_at = ? WHERE duplicate_group_id = ?", (result["duplicate_status"], result["duplicate_confidence"], now, group_id))
        return group_id
    group_id = f"dg_{uuid.uuid4().hex[:16]}"
    connection.execute(
        """
        INSERT INTO duplicate_groups (
            duplicate_group_id, group_hash, primary_fingerprint_id, duplicate_status, confidence, title, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (group_id, group_hash, fingerprint["fingerprint_id"], result["duplicate_status"], result["duplicate_confidence"], fingerprint.get("title") or "Duplicate group", now, now),
    )
    return group_id


def _insert_member(connection: Any, group_id: str, fingerprint_id: str, relationship: str, confidence: str, reason: str) -> None:
    row = connection.execute("SELECT 1 FROM duplicate_group_members WHERE duplicate_group_id = ? AND fingerprint_id = ?", (group_id, fingerprint_id)).fetchone()
    if row:
        return
    connection.execute(
        "INSERT INTO duplicate_group_members (duplicate_group_id, fingerprint_id, relationship, confidence, reason, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (group_id, fingerprint_id, relationship, confidence, reason, _now()),
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
