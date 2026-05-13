"""Asset inventory tracking for VulScan."""

from __future__ import annotations

from hashlib import sha256
from typing import Any

from scanner.database import DB_PATH, database_exists, database_has_required_tables, get_connection, init_db


def update_asset_inventory(scan_result: dict[str, Any]) -> None:
    """Create or update asset inventory records for a saved scan."""
    init_db()
    target = str(scan_result.get("host") or "")
    resolved_ip = str(scan_result.get("resolved_ip") or "")
    asset_id = make_asset_id(target)
    observed_at = str(scan_result.get("scan_end_time") or scan_result.get("scan_start_time") or "")
    hostname = target if target and target != resolved_ip else None
    open_ports = scan_result.get("open_ports", [])
    findings = scan_result.get("findings", [])
    highest_risk_score = max((int(finding.get("risk_score") or 0) for finding in findings), default=0)
    highest_risk_label = _highest_risk_label(findings)
    exposure_summary = _build_exposure_summary(open_ports)

    with get_connection() as connection:
        existing = connection.execute(
            """
            SELECT asset_id
            FROM assets
            WHERE target = ?
            """,
            (target,),
        ).fetchone()

        if existing is None:
            connection.execute(
                """
                INSERT INTO assets (
                    asset_id, target, resolved_ip, hostname, first_seen, last_seen,
                    total_scans, last_open_port_count, last_finding_count,
                    highest_risk_score, highest_risk_label, exposure_summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    asset_id,
                    target,
                    resolved_ip,
                    hostname,
                    observed_at,
                    observed_at,
                    1,
                    len(open_ports),
                    len(findings),
                    highest_risk_score,
                    highest_risk_label,
                    exposure_summary,
                ),
            )
        else:
            asset_id = str(existing["asset_id"])
            connection.execute(
                """
                UPDATE assets
                SET resolved_ip = ?, hostname = ?, last_seen = ?,
                    total_scans = total_scans + 1,
                    last_open_port_count = ?, last_finding_count = ?,
                    highest_risk_score = ?, highest_risk_label = ?,
                    exposure_summary = ?
                WHERE asset_id = ?
                """,
                (
                    resolved_ip,
                    hostname,
                    observed_at,
                    len(open_ports),
                    len(findings),
                    highest_risk_score,
                    highest_risk_label,
                    exposure_summary,
                    asset_id,
                ),
            )

        for port_result in open_ports:
            _upsert_asset_service(connection, asset_id, port_result, observed_at)


def get_assets(target: str | None = None) -> list[dict[str, Any]]:
    """Return asset inventory rows, optionally filtered by target."""
    if not database_exists() or not database_has_required_tables():
        return []

    init_db()
    if target:
        query = """
            SELECT asset_id, target, resolved_ip, hostname, first_seen,
                   last_seen, total_scans, last_open_port_count,
                   last_finding_count, highest_risk_score,
                   highest_risk_label, exposure_summary
            FROM assets
            WHERE target = ?
            ORDER BY last_seen DESC, target ASC
        """
        parameters: tuple[Any, ...] = (target,)
    else:
        query = """
            SELECT asset_id, target, resolved_ip, hostname, first_seen,
                   last_seen, total_scans, last_open_port_count,
                   last_finding_count, highest_risk_score,
                   highest_risk_label, exposure_summary
            FROM assets
            ORDER BY last_seen DESC, target ASC
        """
        parameters = ()

    with get_connection() as connection:
        rows = connection.execute(query, parameters).fetchall()

    assets = [dict(row) for row in rows]
    for asset in assets:
        asset["asset_id_short"] = short_asset_id(str(asset["asset_id"]))
    return assets


def get_asset_services(asset_id: str) -> list[dict[str, Any]]:
    """Return detected service inventory for an asset."""
    if not database_exists() or not database_has_required_tables():
        return []

    init_db()
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT port, protocol, service, status, first_seen, last_seen,
                   last_evidence, last_recommendation
            FROM asset_services
            WHERE asset_id = ?
            ORDER BY port ASC, protocol ASC
            """,
            (asset_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def make_asset_id(target: str) -> str:
    """Return a stable asset ID for a target."""
    digest = sha256(target.strip().lower().encode("utf-8")).hexdigest()[:12].upper()
    return f"ASSET-{digest}"


def short_asset_id(asset_id: str) -> str:
    """Return the short display form of an asset ID."""
    return asset_id.replace("ASSET-", "")[:8].upper()


def get_database_path() -> str:
    """Return the configured asset inventory database path."""
    return str(DB_PATH)


def _upsert_asset_service(
    connection: Any,
    asset_id: str,
    port_result: dict[str, Any],
    observed_at: str,
) -> None:
    existing = connection.execute(
        """
        SELECT id
        FROM asset_services
        WHERE asset_id = ? AND port = ? AND protocol = ?
        """,
        (
            asset_id,
            int(port_result.get("port") or 0),
            str(port_result.get("protocol") or ""),
        ),
    ).fetchone()

    values = (
        str(port_result.get("service") or ""),
        str(port_result.get("status") or ""),
        observed_at,
        str(port_result.get("evidence") or ""),
        str(port_result.get("recommendation") or ""),
    )

    if existing is None:
        connection.execute(
            """
            INSERT INTO asset_services (
                asset_id, port, protocol, service, status, first_seen,
                last_seen, last_evidence, last_recommendation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                asset_id,
                int(port_result.get("port") or 0),
                str(port_result.get("protocol") or ""),
                values[0],
                values[1],
                observed_at,
                values[2],
                values[3],
                values[4],
            ),
        )
        return

    connection.execute(
        """
        UPDATE asset_services
        SET service = ?, status = ?, last_seen = ?,
            last_evidence = ?, last_recommendation = ?
        WHERE asset_id = ? AND port = ? AND protocol = ?
        """,
        (
            values[0],
            values[1],
            values[2],
            values[3],
            values[4],
            asset_id,
            int(port_result.get("port") or 0),
            str(port_result.get("protocol") or ""),
        ),
    )


def _build_exposure_summary(open_ports: list[dict[str, Any]]) -> str:
    if not open_ports:
        return "No open common TCP ports detected."

    services = [
        f"{port.get('service') or 'unknown'} {port.get('port')}/{port.get('protocol')}"
        for port in open_ports
    ]
    return "Open services: " + ", ".join(services[:8])


def _highest_risk_label(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "Informational"
    highest = max(findings, key=lambda finding: int(finding.get("risk_score") or 0))
    return str(highest.get("risk_label") or "Informational")
