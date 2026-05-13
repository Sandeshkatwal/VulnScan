"""Scan diffing helpers for VulScan saved scan history."""

from __future__ import annotations

from typing import Any

from scanner.database import (
    DB_PATH,
    database_exists,
    database_has_required_tables,
    get_connection,
    get_missing_required_tables,
)
from scanner.remediation import finding_fingerprint


def compare_latest_two_scans(target: str) -> dict[str, Any]:
    """Compare the latest two saved scans for a target."""
    if not database_exists():
        return {
            "status": "missing_database",
            "database_path": str(DB_PATH),
            "target": target,
            "message": "No scan history database exists yet. Run a scan with --save-db first.",
        }

    missing_tables = get_missing_required_tables()
    if missing_tables or not database_has_required_tables():
        return {
            "status": "missing_tables",
            "database_path": str(DB_PATH),
            "target": target,
            "missing_tables": sorted(missing_tables),
            "message": "Scan history database is missing required tables. Run a scan with --save-db first.",
        }

    scans = _get_latest_two_scan_rows(target)
    if not scans:
        return {
            "status": "no_history",
            "database_path": str(DB_PATH),
            "target": target,
            "message": f"No saved scans exist for target: {target}",
        }
    if len(scans) == 1:
        return {
            "status": "not_enough_scans",
            "database_path": str(DB_PATH),
            "target": target,
            "latest_scan": scans[0],
            "message": "At least two saved scans are required for diffing.",
        }

    latest_scan = scans[0]
    previous_scan = scans[1]
    latest_findings = _get_findings_for_scan(str(latest_scan["scan_id"]))
    previous_findings = _get_findings_for_scan(str(previous_scan["scan_id"]))

    if not latest_findings and not previous_findings:
        return {
            "status": "no_findings",
            "database_path": str(DB_PATH),
            "target": target,
            "previous_scan": previous_scan,
            "latest_scan": latest_scan,
            "message": "The latest two saved scans have no findings to compare.",
        }

    latest_by_fingerprint = {finding_fingerprint(finding): finding for finding in latest_findings}
    previous_by_fingerprint = {finding_fingerprint(finding): finding for finding in previous_findings}

    latest_keys = set(latest_by_fingerprint)
    previous_keys = set(previous_by_fingerprint)
    common_keys = latest_keys & previous_keys

    new_findings = [latest_by_fingerprint[key] for key in sorted(latest_keys - previous_keys)]
    fixed_findings = [previous_by_fingerprint[key] for key in sorted(previous_keys - latest_keys)]
    changed_risk_findings = [
        latest_by_fingerprint[key]
        for key in sorted(common_keys)
        if _risk_or_severity_changed(previous_by_fingerprint[key], latest_by_fingerprint[key])
    ]
    changed_keys = {finding_fingerprint(finding) for finding in changed_risk_findings}
    unchanged_findings = [
        latest_by_fingerprint[key]
        for key in sorted(common_keys)
        if key not in changed_keys
    ]

    previous_total_risk_score = _total_risk_score(previous_findings)
    latest_total_risk_score = _total_risk_score(latest_findings)

    return {
        "status": "ok",
        "database_path": str(DB_PATH),
        "target": target,
        "previous_scan": previous_scan,
        "latest_scan": latest_scan,
        "previous_total_findings": len(previous_findings),
        "latest_total_findings": len(latest_findings),
        "previous_total_risk_score": previous_total_risk_score,
        "latest_total_risk_score": latest_total_risk_score,
        "risk_trend": _risk_trend(previous_total_risk_score, latest_total_risk_score),
        "new_findings": _sort_findings(new_findings),
        "fixed_findings": _sort_findings(fixed_findings),
        "unchanged_findings": _sort_findings(unchanged_findings),
        "changed_risk_findings": _sort_findings(changed_risk_findings),
    }


def _get_latest_two_scan_rows(target: str) -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT scan_id, target, resolved_ip, scan_start_time,
                   duration_seconds, total_open_ports, total_findings,
                   highest_risk_score, highest_risk_label
            FROM scans
            WHERE target = ?
            ORDER BY scan_start_time DESC, id DESC
            LIMIT 2
            """,
            (target,),
        ).fetchall()
    return [dict(row) for row in rows]


def _get_findings_for_scan(scan_id: str) -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT finding_id, title, severity, category, affected_host,
                   affected_port, affected_url, service, evidence, confidence,
                   impact, recommendation, verification, limitation, source,
                   risk_score, risk_label, fix_priority, created_at
            FROM findings
            WHERE scan_id = ?
            """,
            (scan_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def _risk_or_severity_changed(previous: dict[str, Any], latest: dict[str, Any]) -> bool:
    return (
        int(previous.get("risk_score") or 0) != int(latest.get("risk_score") or 0)
        or str(previous.get("severity") or "") != str(latest.get("severity") or "")
    )


def _total_risk_score(findings: list[dict[str, Any]]) -> int:
    return sum(int(finding.get("risk_score") or 0) for finding in findings)


def _risk_trend(previous_total: int, latest_total: int) -> str:
    if latest_total < previous_total:
        return "Improving"
    if latest_total > previous_total:
        return "Worsening"
    return "Unchanged"


def _sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda finding: (
            int(finding.get("risk_score") or 0),
            str(finding.get("severity") or ""),
            str(finding.get("title") or ""),
        ),
        reverse=True,
    )
