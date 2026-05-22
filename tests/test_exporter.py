import json

from scanner.database import init_db
from scanner.exporter import export_findings, export_prioritisation


def test_finding_export_includes_asset_context_fields(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "vulscan.db"
    exports_dir = tmp_path / "exports"
    monkeypatch.setattr("scanner.exporter.DB_PATH", db_path)
    monkeypatch.setattr("scanner.exporter.EXPORTS_DIR", exports_dir)

    init_db(db_path)
    import sqlite3

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO scans (
                scan_id, target, resolved_ip, scanner_version, scan_mode,
                scan_start_time, scan_end_time, duration_seconds,
                total_open_ports, total_findings, highest_risk_score,
                highest_risk_label, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "scan-1",
                "production-web",
                "production-web",
                "test",
                "safe",
                "2026-05-22T10:00:00+00:00",
                "2026-05-22T10:00:01+00:00",
                1.0,
                0,
                1,
                75,
                "High priority",
                "2026-05-22T10:00:01+00:00",
            ),
        )
        connection.execute(
            """
            INSERT INTO findings (
                scan_id, finding_id, title, severity, category,
                affected_host, affected_port, affected_url, service,
                evidence, confidence, impact, recommendation, verification,
                limitation, source, risk_score, risk_label, fix_priority,
                asset_criticality, asset_environment, asset_business_owner, asset_tags,
                priority_score, priority_label, recommended_action, sla_hint, fix_first_rank,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "scan-1",
                "FINDING-0001",
                "Unit Finding",
                "High",
                "Unit",
                "production-web",
                None,
                None,
                None,
                "Local evidence.",
                "High",
                "Impact.",
                "Recommendation.",
                "Verification.",
                "Limitation.",
                "unit",
                75,
                "High priority",
                "Fix soon",
                "critical",
                "production",
                "Business Unit",
                "[\"production\"]",
                95,
                "Fix First",
                "Patch.",
                "Review within 24-72 hours.",
                1,
                "2026-05-22T10:00:01+00:00",
            ),
        )

    result = export_findings("json", target="production-web")
    rows = json.loads(result["path"].read_text(encoding="utf-8"))

    assert result["status"] == "exported"
    assert rows[0]["asset_criticality"] == "critical"
    assert rows[0]["asset_environment"] == "production"
    assert rows[0]["asset_business_owner"] == "Business Unit"
    assert rows[0]["priority_score"] == 95
    assert rows[0]["priority_label"] == "Fix First"
    assert "trend_status" in rows[0]
    assert "score_delta" in rows[0]


def test_prioritisation_export_includes_priority_fields(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "vulscan.db"
    exports_dir = tmp_path / "exports"
    monkeypatch.setattr("scanner.exporter.DB_PATH", db_path)
    monkeypatch.setattr("scanner.exporter.EXPORTS_DIR", exports_dir)

    init_db(db_path)
    import sqlite3

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO scans (
                scan_id, target, resolved_ip, scanner_version, scan_mode,
                scan_start_time, scan_end_time, duration_seconds,
                total_open_ports, total_findings, highest_risk_score,
                highest_risk_label, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "scan-1",
                "production-web",
                "production-web",
                "test",
                "safe",
                "2026-05-22T10:00:00+00:00",
                "2026-05-22T10:00:01+00:00",
                1.0,
                0,
                1,
                95,
                "High priority",
                "2026-05-22T10:00:01+00:00",
            ),
        )
        connection.execute(
            """
            INSERT INTO findings (
                scan_id, finding_id, title, severity, category,
                evidence, confidence, impact, recommendation, verification,
                limitation, source, risk_score, risk_label, fix_priority,
                asset_criticality, priority_score, priority_label, recommended_action,
                sla_hint, fix_first_rank, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "scan-1",
                "FINDING-0001",
                "Unit Finding",
                "High",
                "Unit",
                "Local evidence.",
                "High",
                "Impact.",
                "Recommendation.",
                "Verification.",
                "Limitation.",
                "unit",
                75,
                "High priority",
                "Fix soon",
                "critical",
                95,
                "Fix First",
                "Patch.",
                "Review within 24-72 hours.",
                1,
                "2026-05-22T10:00:01+00:00",
            ),
        )

    result = export_prioritisation("json", target="production-web")
    rows = json.loads(result["path"].read_text(encoding="utf-8"))

    assert result["status"] == "exported"
    assert rows[0]["priority_score"] == 95
    assert rows[0]["priority_label"] == "Fix First"
    assert rows[0]["fix_first_rank"] == 1
    assert "previous_priority_score" in rows[0]
    assert "current_priority_label" in rows[0]
