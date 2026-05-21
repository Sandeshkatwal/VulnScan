import json

import pytest

from scanner.epss_importer import (
    EpssImportError,
    build_epss_import_findings,
    build_epss_summary,
    enrich_cve_matches_with_epss,
    load_epss_file,
)


def _match(cve: str = "LOCAL-CVE-DEMO-0001") -> dict:
    return {
        "cve": cve,
        "title": "Demo CVE",
        "match_status": "matched",
        "cvss_score": 7.5,
    }


def test_loads_valid_epss_csv(tmp_path) -> None:
    path = tmp_path / "epss.csv"
    path.write_text("cve,epss,percentile\nLOCAL-CVE-DEMO-0001,0.72,0.94\n", encoding="utf-8")

    data = load_epss_file(path)

    assert data["records"]["LOCAL-CVE-DEMO-0001"]["epss_score"] == 0.72
    assert data["records"]["LOCAL-CVE-DEMO-0001"]["epss_percentile"] == 0.94
    assert data["invalid_records"] == 0


def test_loads_valid_epss_json(tmp_path) -> None:
    path = tmp_path / "epss.json"
    path.write_text(
        json.dumps({"feed_name": "Unit", "feed_version": "1.0", "items": [{"cve": "LOCAL-CVE-DEMO-0001", "epss": 0.72, "percentile": 0.94}]}),
        encoding="utf-8",
    )

    data = load_epss_file(path)

    assert data["feed_name"] == "Unit"
    assert data["records_loaded"] == 1


def test_rejects_missing_epss_file_gracefully(tmp_path) -> None:
    with pytest.raises(EpssImportError, match="not found"):
        load_epss_file(tmp_path / "missing.csv")


def test_skips_invalid_numeric_and_missing_cve_rows(tmp_path) -> None:
    path = tmp_path / "epss.csv"
    path.write_text(
        "cve,epss,percentile\nLOCAL-CVE-DEMO-0001,0.72,0.94\nLOCAL-CVE-BAD,abc,0.1\n,0.5,0.5\n",
        encoding="utf-8",
    )

    data = load_epss_file(path)

    assert data["records_loaded"] == 1
    assert data["invalid_records"] == 2


def test_enriches_cve_match_with_epss() -> None:
    epss_data = {
        "records": {
            "LOCAL-CVE-DEMO-0001": {
                "epss_score": 0.72,
                "epss_percentile": 0.94,
                "source": "local_epss_file",
            }
        }
    }

    enriched = enrich_cve_matches_with_epss([_match()], epss_data)

    assert enriched[0]["epss_enriched"] is True
    assert enriched[0]["epss_score"] == 0.72
    assert enriched[0]["epss_percentile"] == 0.94


def test_leaves_cve_match_unchanged_when_epss_missing() -> None:
    enriched = enrich_cve_matches_with_epss([_match("LOCAL-CVE-MISSING")], {"records": {}})

    assert enriched[0]["epss_enriched"] is False
    assert enriched[0].get("epss_score") is None


def test_builds_epss_summary_buckets_and_highest_values() -> None:
    matches = [
        {"cve": "LOCAL-1", "epss_enriched": True, "epss_score": 0.72, "epss_percentile": 0.94},
        {"cve": "LOCAL-2", "epss_enriched": True, "epss_score": 0.3, "epss_percentile": 0.7},
        {"cve": "LOCAL-3", "epss_enriched": True, "epss_score": 0.1, "epss_percentile": 0.2},
        {"cve": "LOCAL-4", "epss_enriched": False},
    ]

    summary = build_epss_summary(
        enabled=True,
        epss_file=None,
        epss_data={"records_loaded": 3, "invalid_records": 1, "duplicate_records": 0},
        cve_matches=matches,
    )

    assert summary["highest_epss_score"] == 0.72
    assert summary["highest_epss_percentile"] == 0.94
    assert summary["high_epss_count"] == 1
    assert summary["medium_epss_count"] == 1
    assert summary["low_epss_count"] == 1
    assert summary["epss_matches_enriched"] == 3
    assert summary["epss_missing_for_cve_count"] == 1


def test_generates_epss_import_completed_and_failed_findings() -> None:
    completed_summary = build_epss_summary(
        enabled=True,
        epss_file=None,
        epss_data={"records_loaded": 1, "invalid_records": 0},
        cve_matches=[{"cve": "LOCAL", "epss_enriched": True, "epss_score": 0.72, "epss_percentile": 0.94}],
    )
    failed_summary = build_epss_summary(
        enabled=True,
        epss_file=None,
        epss_data=None,
        cve_matches=[],
        error="Local EPSS metadata was not loaded.",
    )

    completed = build_epss_import_findings(completed_summary, {"host": "127.0.0.1"})
    failed = build_epss_import_findings(failed_summary, {"host": "127.0.0.1"}, failed=True)

    assert completed[0].title == "EPSS Metadata Import Completed"
    assert completed[0].source == "epss_importer"
    assert failed[0].title == "EPSS Metadata Import Failed"
    assert failed[0].source == "epss_importer"
