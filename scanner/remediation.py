"""Remediation status tracking for VulScan findings."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

from scanner.database import (
    DB_PATH,
    database_exists,
    database_has_required_tables,
    get_connection,
    init_db,
)


ALLOWED_STATUS_VALUES = (
    "Open",
    "In Progress",
    "Fixed",
    "Accepted Risk",
    "False Positive",
)


def finding_fingerprint(finding: dict[str, Any]) -> str:
    """Return the stable remediation/diff fingerprint for a finding."""
    parts = [
        finding.get("title"),
        finding.get("affected_host"),
        finding.get("affected_port"),
        finding.get("affected_url"),
        finding.get("service"),
        finding.get("category"),
        finding.get("source"),
    ]
    normalized = "|".join(_normalize_part(part) for part in parts)
    return sha256(normalized.encode("utf-8")).hexdigest().upper()


def short_fingerprint(fingerprint: str) -> str:
    """Return the short display form for a remediation fingerprint."""
    return fingerprint[:8].upper()


def ensure_remediation_records_for_scan(scan_result: dict[str, Any]) -> None:
    """Create or update remediation tracking rows for findings in a saved scan."""
    init_db()
    target = str(scan_result.get("host") or "")
    observed_at = str(scan_result.get("scan_end_time") or _now())
    findings = scan_result.get("findings", [])

    with get_connection() as connection:
        for finding in findings:
            fingerprint = finding_fingerprint(finding)
            existing = connection.execute(
                """
                SELECT status, owner, note
                FROM remediation_status
                WHERE finding_fingerprint = ?
                """,
                (fingerprint,),
            ).fetchone()

            if existing is None:
                connection.execute(
                    """
                    INSERT INTO remediation_status (
                        finding_fingerprint, finding_id, target, title, status,
                        owner, note, first_seen, last_seen, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        fingerprint,
                        finding.get("id"),
                        target,
                        finding.get("title"),
                        "Open",
                        None,
                        None,
                        observed_at,
                        observed_at,
                        _now(),
                    ),
                )
                finding["remediation_status"] = "Open"
                finding["remediation_fingerprint"] = fingerprint
                finding["remediation_fingerprint_short"] = short_fingerprint(fingerprint)
                continue

            status = str(existing["status"])
            note = existing["note"]
            if status == "Fixed":
                status = "Open"
                note = "Finding observed again in latest scan."

            connection.execute(
                """
                UPDATE remediation_status
                SET finding_id = ?, target = ?, title = ?, status = ?,
                    note = ?, last_seen = ?, updated_at = ?
                WHERE finding_fingerprint = ?
                """,
                (
                    finding.get("id"),
                    target,
                    finding.get("title"),
                    status,
                    note,
                    observed_at,
                    _now(),
                    fingerprint,
                ),
            )
            finding["remediation_status"] = status
            finding["remediation_fingerprint"] = fingerprint
            finding["remediation_fingerprint_short"] = short_fingerprint(fingerprint)


def enrich_findings_with_remediation(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach remediation status fields to findings when tracking data exists."""
    if not database_exists() or not database_has_required_tables():
        return findings

    init_db()
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT finding_fingerprint, status, owner, note
            FROM remediation_status
            """
        ).fetchall()
    status_by_fingerprint = {str(row["finding_fingerprint"]): dict(row) for row in rows}

    for finding in findings:
        fingerprint = finding_fingerprint(finding)
        finding["remediation_fingerprint"] = fingerprint
        finding["remediation_fingerprint_short"] = short_fingerprint(fingerprint)
        status_row = status_by_fingerprint.get(fingerprint)
        if status_row:
            finding["remediation_status"] = status_row["status"]
            finding["remediation_owner"] = status_row["owner"]
            finding["remediation_note"] = status_row["note"]

    return findings


def get_remediation_list(target: str) -> list[dict[str, Any]]:
    """Return remediation rows for a target with latest finding context when available."""
    if not database_exists() or not database_has_required_tables():
        return []

    init_db()
    latest_findings = _latest_finding_context_by_fingerprint(target)
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT finding_fingerprint, finding_id, target, title, status,
                   owner, note, first_seen, last_seen, updated_at
            FROM remediation_status
            WHERE target = ?
            ORDER BY last_seen DESC, title ASC
            """,
            (target,),
        ).fetchall()

    results = []
    for row in rows:
        item = dict(row)
        context = latest_findings.get(str(item["finding_fingerprint"]), {})
        item["fingerprint_short"] = short_fingerprint(str(item["finding_fingerprint"]))
        item["risk_label"] = context.get("risk_label", "")
        item["affected_host"] = context.get("affected_host", "")
        item["affected_port"] = context.get("affected_port", "")
        item["service"] = context.get("service", "")
        results.append(item)
    return results


def update_remediation_status(
    fingerprint: str,
    status: str,
    owner: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    """Update remediation status by full or unique short fingerprint."""
    if status not in ALLOWED_STATUS_VALUES:
        return {
            "status": "invalid_status",
            "message": f"Invalid status. Allowed values: {', '.join(ALLOWED_STATUS_VALUES)}",
        }
    if not database_exists() or not database_has_required_tables():
        return {
            "status": "missing_database",
            "message": "No scan history database exists yet. Run a scan with --save-db first.",
        }

    init_db()
    normalized = fingerprint.strip().upper()
    if not normalized:
        return {
            "status": "not_found",
            "message": "Fingerprint is required.",
        }
    with get_connection() as connection:
        matches = connection.execute(
            """
            SELECT finding_fingerprint, title
            FROM remediation_status
            WHERE UPPER(finding_fingerprint) LIKE ?
            """,
            (f"{normalized}%",),
        ).fetchall()

        if not matches:
            return {
                "status": "not_found",
                "message": f"No remediation record found for fingerprint: {fingerprint}",
            }
        if len(matches) > 1:
            return {
                "status": "ambiguous",
                "message": "Fingerprint matches multiple findings. Use a longer fingerprint value.",
            }

        full_fingerprint = str(matches[0]["finding_fingerprint"])
        connection.execute(
            """
            UPDATE remediation_status
            SET status = ?, owner = COALESCE(?, owner),
                note = COALESCE(?, note), updated_at = ?
            WHERE finding_fingerprint = ?
            """,
            (status, owner, note, _now(), full_fingerprint),
        )

    return {
        "status": "updated",
        "message": f"Remediation status updated for {short_fingerprint(full_fingerprint)}.",
        "finding_fingerprint": full_fingerprint,
    }


def get_remediation_summary(target: str) -> dict[str, int]:
    """Return remediation status counts for a target."""
    counts = {status: 0 for status in ALLOWED_STATUS_VALUES}
    if not database_exists() or not database_has_required_tables():
        return counts

    init_db()
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT status, COUNT(*) AS count
            FROM remediation_status
            WHERE target = ?
            GROUP BY status
            """,
            (target,),
        ).fetchall()

    for row in rows:
        counts[str(row["status"])] = int(row["count"])
    return counts


def get_database_path() -> str:
    """Return the configured remediation database path."""
    return str(DB_PATH)


def _latest_finding_context_by_fingerprint(target: str) -> dict[str, dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT f.title, f.severity, f.category, f.affected_host,
                   f.affected_port, f.affected_url, f.service, f.source,
                   f.risk_label, f.risk_score, s.scan_start_time
            FROM findings f
            INNER JOIN scans s ON s.scan_id = f.scan_id
            WHERE s.target = ?
            ORDER BY s.scan_start_time DESC, s.id DESC
            """,
            (target,),
        ).fetchall()

    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        item = dict(row)
        fingerprint = finding_fingerprint(item)
        if fingerprint not in latest:
            latest[fingerprint] = item
    return latest


def _normalize_part(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
