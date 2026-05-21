"""Offline EPSS metadata importer for VulScan."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from scanner.finding import create_finding


DEFAULT_EPSS_PATH = Path("data") / "epss" / "sample_epss.csv"
EPSS_LIMITATION = "EPSS is probability metadata and does not confirm exploitation or vulnerability presence."


class EpssImportError(ValueError):
    """Raised when a local EPSS metadata file cannot be loaded."""


def load_epss_file(path: Path) -> dict[str, Any]:
    """Load local EPSS metadata from CSV or JSON."""
    epss_path = Path(path)
    if not epss_path.exists():
        raise EpssImportError(f"Local EPSS file was not found: {epss_path}")
    suffix = epss_path.suffix.lower()
    if suffix == ".csv":
        return parse_epss_csv(epss_path)
    if suffix == ".json":
        return parse_epss_json(epss_path)
    raise EpssImportError("Local EPSS file must be a .csv or .json file.")


def parse_epss_csv(path: Path) -> dict[str, Any]:
    """Parse local EPSS CSV with cve, epss, percentile headers."""
    try:
        with Path(path).open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None:
                raise EpssImportError("Local EPSS CSV is empty.")
            required = {"cve", "epss", "percentile"}
            fieldnames = {name.strip().lower() for name in reader.fieldnames if name}
            if not required.issubset(fieldnames):
                raise EpssImportError("Local EPSS CSV must include cve, epss, and percentile headers.")
            return _records_from_rows(reader, feed_name=Path(path).name, feed_version=None, source_file=Path(path))
    except UnicodeDecodeError as exc:
        raise EpssImportError(f"Local EPSS CSV could not be decoded: {path}") from exc
    except csv.Error as exc:
        raise EpssImportError(f"Local EPSS CSV could not be parsed: {path}") from exc


def parse_epss_json(path: Path) -> dict[str, Any]:
    """Parse local EPSS JSON metadata."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EpssImportError(f"Local EPSS JSON file is not valid JSON: {path}") from exc
    if not isinstance(data, dict):
        raise EpssImportError("Local EPSS JSON must be an object.")
    items = data.get("items")
    if not isinstance(items, list):
        raise EpssImportError("Local EPSS JSON must include an items list.")
    return _records_from_rows(
        items,
        feed_name=data.get("feed_name"),
        feed_version=data.get("feed_version"),
        source_file=Path(path),
    )


def normalise_epss_record(record: Any) -> dict[str, Any] | None:
    """Normalise one EPSS row, returning None for malformed records."""
    if not isinstance(record, dict):
        return None
    record = {str(key).strip().lower(): value for key, value in record.items()}
    cve = str(record.get("cve") or "").strip().upper()
    if not cve:
        return None
    epss_score = _score(record.get("epss"))
    epss_percentile = _score(record.get("percentile"))
    if epss_score is None or epss_percentile is None:
        return None
    return {
        "cve": cve,
        "epss_score": epss_score,
        "epss_percentile": epss_percentile,
        "source": "local_epss_file",
    }


def enrich_cve_matches_with_epss(matches: list[dict[str, Any]], epss_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Enrich local CVE feed matches with offline EPSS metadata."""
    records = dict(epss_data.get("records") or {})
    enriched: list[dict[str, Any]] = []
    for match in matches:
        updated = dict(match)
        cve = str(updated.get("cve") or "").strip().upper()
        record = records.get(cve)
        if record:
            updated["epss_score"] = record.get("epss_score")
            updated["epss_percentile"] = record.get("epss_percentile")
            updated["epss_source"] = record.get("source") or "local_epss_file"
            updated["epss_enriched"] = True
        else:
            updated["epss_enriched"] = False
            updated["epss_source"] = None
            updated.setdefault("epss_score", match.get("epss_score"))
            updated.setdefault("epss_percentile", match.get("epss_percentile"))
        enriched.append(updated)
    return enriched


def build_epss_summary(
    *,
    enabled: bool,
    epss_file: Path | None,
    epss_data: dict[str, Any] | None,
    cve_matches: list[dict[str, Any]],
    error: str | None = None,
) -> dict[str, Any]:
    """Build EPSS fields for the vulnerability intelligence summary."""
    enriched_matches = [match for match in cve_matches if match.get("epss_enriched") is True]
    cve_matches_with_ids = [match for match in cve_matches if match.get("cve")]
    scores = [_score(match.get("epss_score")) for match in enriched_matches]
    percentiles = [_score(match.get("epss_percentile")) for match in enriched_matches]
    scores = [score for score in scores if score is not None]
    percentiles = [percentile for percentile in percentiles if percentile is not None]
    limitations = [
        EPSS_LIMITATION,
        "Version 14.4 imports local EPSS metadata files only and does not fetch live EPSS data.",
        "Duplicate EPSS rows keep the last valid record.",
    ]
    if error:
        limitations.append(error)
    return {
        "epss_enabled": bool(enabled),
        "epss_file": str(epss_file) if epss_file else None,
        "epss_records_loaded": int((epss_data or {}).get("records_loaded") or 0),
        "epss_invalid_records": int((epss_data or {}).get("invalid_records") or 0),
        "epss_duplicate_records": int((epss_data or {}).get("duplicate_records") or 0),
        "epss_matches_enriched": len(enriched_matches),
        "epss_missing_for_cve_count": max(0, len(cve_matches_with_ids) - len(enriched_matches)),
        "highest_epss_score": max(scores) if scores else None,
        "highest_epss_percentile": max(percentiles) if percentiles else None,
        "high_epss_count": sum(1 for score in scores if score >= 0.7),
        "medium_epss_count": sum(1 for score in scores if 0.2 <= score < 0.7),
        "low_epss_count": sum(1 for score in scores if score < 0.2),
        "epss_limitations": limitations,
    }


def build_epss_import_findings(
    summary: dict[str, Any],
    scan_result: dict[str, Any],
    *,
    failed: bool = False,
) -> list[Any]:
    """Create one EPSS importer status finding."""
    if not summary.get("epss_enabled"):
        return []
    if failed:
        return [
            create_finding(
                title="EPSS Metadata Import Failed",
                severity="Informational",
                category="Vulnerability Intelligence",
                affected_host=str(scan_result.get("host") or ""),
                evidence="Local EPSS file could not be loaded or parsed.",
                confidence="High",
                impact="CVE matching can continue without EPSS enrichment.",
                recommendation="Verify EPSS file path and format.",
                verification="Review vulnerability_intelligence.epss_limitations in the report.",
                limitation="CVE matching can continue without EPSS enrichment.",
                source="epss_importer",
                evidence_details=dict(summary),
            )
        ]
    return [
        create_finding(
            title="EPSS Metadata Import Completed",
            severity="Informational",
            category="Vulnerability Intelligence",
            affected_host=str(scan_result.get("host") or ""),
            evidence="Local EPSS metadata was loaded and used to enrich CVE matches.",
            confidence="High",
            impact="EPSS can help prioritise local CVE matches when reviewed with other context.",
            recommendation="Use EPSS as one prioritisation signal alongside CVSS, asset criticality, exposure, and exploit availability.",
            verification="Review EPSS metadata in the vulnerability intelligence report section.",
            limitation=EPSS_LIMITATION,
            source="epss_importer",
            evidence_details=dict(summary),
        )
    ]


def _records_from_rows(
    rows: Any,
    *,
    feed_name: Any,
    feed_version: Any,
    source_file: Path,
) -> dict[str, Any]:
    records: dict[str, dict[str, Any]] = {}
    invalid_records = 0
    duplicate_records = 0
    for row in rows:
        normalised = normalise_epss_record(row)
        if normalised is None:
            invalid_records += 1
            continue
        cve = normalised["cve"]
        if cve in records:
            duplicate_records += 1
        records[cve] = {
            "epss_score": normalised["epss_score"],
            "epss_percentile": normalised["epss_percentile"],
            "source": normalised["source"],
        }
    if not records and invalid_records == 0:
        raise EpssImportError("Local EPSS file does not contain any records.")
    return {
        "feed_name": feed_name,
        "feed_version": feed_version,
        "source_file": str(source_file),
        "records": records,
        "records_loaded": len(records),
        "invalid_records": invalid_records,
        "duplicate_records": duplicate_records,
    }


def _score(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if 0.0 <= score <= 1.0:
        return score
    return None
