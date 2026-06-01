"""Local Bug Intelligence workflow metrics."""

from __future__ import annotations

import csv
import io
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from scanner.database import DB_PATH, get_connection, init_db


DATE_RANGE_OPTIONS = {"all-time", "last-7-days", "last-30-days", "last-90-days", "this-year", "custom"}
OUTCOMES = ("draft", "submitted", "triaged", "accepted", "duplicate", "informative", "not_applicable", "resolved", "paid", "closed")
SEVERITY_SCORES = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "informational": 1}
LIMITATIONS = [
    "Metrics are calculated from local VulScan workflow records only.",
    "Quality score is a local workflow indicator and does not guarantee platform success.",
    "External platform dashboards, credentials, API tokens, and browser sessions are not accessed.",
]


class MetricsDateRangeError(ValueError):
    """Raised when a metrics date range is invalid."""


def build_bug_intelligence_metrics(
    *,
    range_name: str = "all-time",
    start_date: str | None = None,
    end_date: str | None = None,
    program_name: str | None = None,
    db_path: Path | str = DB_PATH,
) -> dict[str, Any]:
    """Build the top-level local Bug Intelligence metrics object."""
    date_range = resolve_date_range(range_name, start_date=start_date, end_date=end_date)
    db = Path(db_path)
    init_db(db)
    with get_connection(db) as connection:
        submissions = [dict(row) for row in connection.execute("SELECT * FROM security_submissions").fetchall()]
        retests = [dict(row) for row in connection.execute("SELECT * FROM security_retests").fetchall()]
        fingerprints = [dict(row) for row in connection.execute("SELECT * FROM finding_fingerprints").fetchall()]
        duplicate_groups = [dict(row) for row in connection.execute("SELECT * FROM duplicate_groups").fetchall()]
        findings = [dict(row) for row in connection.execute("SELECT * FROM findings").fetchall()]

    if program_name:
        wanted = program_name.strip().lower()
        submissions = [row for row in submissions if str(row.get("program_name") or "").strip().lower() == wanted]
        submission_ids = {str(row.get("submission_id") or "") for row in submissions}
        report_ids = {str(row.get("report_id") or "") for row in submissions if row.get("report_id")}
        retests = [row for row in retests if str(row.get("submission_id") or "") in submission_ids or str(row.get("report_id") or "") in report_ids]
        fingerprints = [row for row in fingerprints if str(row.get("target") or "").strip().lower() == wanted]

    submissions = _filter_rows(submissions, date_range, "created_at")
    retests = _filter_rows(retests, date_range, "created_at")
    fingerprints = _filter_rows(fingerprints, date_range, "created_at")
    findings = _filter_rows(findings, date_range, "created_at")

    total_submissions = len(submissions)
    status_counts = Counter(str(row.get("status") or "draft") for row in submissions)
    total_accepted = _accepted_total(status_counts)
    total_duplicates = _status_total(status_counts, "duplicate")
    total_informative = _status_total(status_counts, "informative")
    total_not_applicable = _status_total(status_counts, "not_applicable")
    total_resolved = _resolved_total(status_counts)
    total_paid = _status_total(status_counts, "paid")
    total_reports_created = len({str(row.get("report_id")) for row in submissions if row.get("report_id")})
    total_evidence_records = _count_evidence_records(submissions, retests, findings)
    total_retests = len(retests)
    retest_passed_count = sum(1 for row in retests if row.get("status") == "retest_passed")
    retest_failed_count = sum(1 for row in retests if row.get("status") == "retest_failed")
    bounty_totals, bounty_averages = _bounty_metrics(submissions)
    quality = _quality_indicators(
        submissions=submissions,
        retests=retests,
        findings=findings,
        total_evidence_records=total_evidence_records,
        total_reports_created=total_reports_created,
        total_accepted=total_accepted,
        total_duplicates=total_duplicates,
        total_informative=total_informative,
        total_not_applicable=total_not_applicable,
        retest_passed_count=retest_passed_count,
    )

    return {
        "bug_intelligence_metrics": {
            "enabled": True,
            "generated_at": _now(),
            "date_range": date_range,
            "total_evidence_records": total_evidence_records,
            "total_reports_created": total_reports_created,
            "total_submissions": total_submissions,
            "total_accepted": total_accepted,
            "total_duplicates": total_duplicates,
            "total_informative": total_informative,
            "total_not_applicable": total_not_applicable,
            "total_resolved": total_resolved,
            "total_paid": total_paid,
            "total_retests": total_retests,
            "retest_passed_count": retest_passed_count,
            "retest_failed_count": retest_failed_count,
            "acceptance_rate": _rate(total_accepted, total_submissions),
            "duplicate_rate": _rate(total_duplicates, total_submissions),
            "informative_rate": _rate(total_informative, total_submissions),
            "resolution_rate": _rate(total_resolved, total_submissions),
            "average_time_to_report_hours": _average_time_to_report_hours(submissions),
            "average_time_to_triage_days": _average_elapsed(submissions, "submitted_at", "triaged_at"),
            "average_time_to_resolution_days": _average_elapsed(submissions, "accepted_at", "resolved_at"),
            "average_time_to_payment_days": _average_elapsed(submissions, "accepted_at", "paid_at"),
            "total_bounty_by_currency": bounty_totals,
            "average_bounty_by_currency": bounty_averages,
            "top_programs": calculate_program_performance(submissions=submissions, retests=retests),
            "top_vulnerability_classes": calculate_vulnerability_class_metrics(submissions=submissions, fingerprints=fingerprints, findings=findings),
            "top_owasp_categories": _top_owasp_categories(fingerprints, findings),
            "monthly_activity": calculate_monthly_activity(submissions=submissions, retests=retests, findings=findings),
            "outcome_distribution": calculate_outcome_distribution(submissions),
            "quality_indicators": quality,
            "limitations": list(LIMITATIONS),
        }
    }


def calculate_program_performance(
    *,
    submissions: list[dict[str, Any]] | None = None,
    retests: list[dict[str, Any]] | None = None,
    db_path: Path | str = DB_PATH,
    range_name: str = "all-time",
    start_date: str | None = None,
    end_date: str | None = None,
) -> list[dict[str, Any]]:
    if submissions is None or retests is None:
        metrics = build_bug_intelligence_metrics(range_name=range_name, start_date=start_date, end_date=end_date, db_path=db_path)
        return metrics["bug_intelligence_metrics"]["top_programs"]
    retest_by_submission = defaultdict(list)
    for retest in retests:
        retest_by_submission[str(retest.get("submission_id") or "")].append(retest)
    programs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in submissions:
        programs[str(row.get("program_name") or "Unassigned Program")].append(row)
    results: list[dict[str, Any]] = []
    for name, rows in programs.items():
        counts = Counter(str(row.get("status") or "draft") for row in rows)
        bounty_totals, _ = _bounty_metrics(rows)
        last_activity = max((_date_text(row.get("updated_at") or row.get("created_at")) for row in rows), default="")
        triage_avg = _average_elapsed(rows, "submitted_at", "triaged_at")
        results.append(
            {
                "program_name": name,
                "total_submissions": len(rows),
                "accepted": _accepted_total(counts),
                "duplicates": _status_total(counts, "duplicate"),
                "informative": _status_total(counts, "informative"),
                "not_applicable": _status_total(counts, "not_applicable"),
                "resolved": _resolved_total(counts),
                "paid": _status_total(counts, "paid"),
                "acceptance_rate": _rate(_accepted_total(counts), len(rows)),
                "duplicate_rate": _rate(_status_total(counts, "duplicate"), len(rows)),
                "total_bounty_by_currency": bounty_totals,
                "average_time_to_triage_days": triage_avg,
                "last_activity": last_activity,
            }
        )
    return sorted(results, key=lambda item: (item["total_submissions"], item["accepted"], item["program_name"]), reverse=True)


def calculate_vulnerability_class_metrics(
    *,
    submissions: list[dict[str, Any]] | None = None,
    fingerprints: list[dict[str, Any]] | None = None,
    findings: list[dict[str, Any]] | None = None,
    db_path: Path | str = DB_PATH,
    range_name: str = "all-time",
    start_date: str | None = None,
    end_date: str | None = None,
) -> list[dict[str, Any]]:
    if submissions is None or fingerprints is None or findings is None:
        metrics = build_bug_intelligence_metrics(range_name=range_name, start_date=start_date, end_date=end_date, db_path=db_path)
        return metrics["bug_intelligence_metrics"]["top_vulnerability_classes"]
    buckets: dict[str, dict[str, Any]] = defaultdict(lambda: {"count": 0, "accepted_count": 0, "duplicate_count": 0, "severity_total": 0, "severity_count": 0})
    for row in submissions:
        name = classify_vulnerability(row.get("finding_title") or row.get("severity_submitted") or "Security Finding")
        bucket = buckets[name]
        bucket["count"] += 1
        if row.get("status") in {"accepted", "resolved", "paid"}:
            bucket["accepted_count"] += 1
        if row.get("status") == "duplicate":
            bucket["duplicate_count"] += 1
        _add_severity(bucket, row.get("severity_accepted") or row.get("severity_submitted"))
    for row in fingerprints:
        name = classify_vulnerability(row.get("issue_type") or row.get("owasp_category") or row.get("title") or "Security Finding")
        buckets[name]["count"] += 1
    for row in findings:
        name = classify_vulnerability(row.get("category") or row.get("title") or row.get("source") or "Security Finding")
        bucket = buckets[name]
        bucket["count"] += 1
        _add_severity(bucket, row.get("severity"))
    results = []
    for name, bucket in buckets.items():
        count = int(bucket["count"])
        severity_count = int(bucket["severity_count"])
        results.append(
            {
                "class_name": name,
                "count": count,
                "accepted_count": int(bucket["accepted_count"]),
                "duplicate_count": int(bucket["duplicate_count"]),
                "acceptance_rate": _rate(int(bucket["accepted_count"]), count),
                "average_severity": round(float(bucket["severity_total"]) / severity_count, 2) if severity_count else 0,
            }
        )
    return sorted(results, key=lambda item: (item["count"], item["accepted_count"], item["class_name"]), reverse=True)[:10]


def calculate_monthly_activity(
    *,
    submissions: list[dict[str, Any]],
    retests: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    months: dict[str, Counter[str]] = defaultdict(Counter)
    for row in findings:
        month = _month(row.get("created_at"))
        if month:
            months[month]["evidence_created"] += 1
    for row in submissions:
        month = _month(row.get("created_at"))
        if month:
            months[month]["submissions_created"] += 1
            if row.get("report_id"):
                months[month]["reports_created"] += 1
        for status, field in (("accepted", "accepted_at"), ("duplicates", "updated_at"), ("resolved", "resolved_at"), ("paid", "paid_at")):
            if status == "duplicates" and row.get("status") != "duplicate":
                continue
            status_month = _month(row.get(field))
            if status_month:
                months[status_month][status] += 1
    for row in retests:
        if row.get("status") in {"retest_passed", "retest_failed", "retest_blocked"}:
            month = _month(row.get("retested_at") or row.get("updated_at"))
            if month:
                months[month]["retests_completed"] += 1
    keys = ("evidence_created", "reports_created", "submissions_created", "accepted", "duplicates", "resolved", "paid", "retests_completed")
    return [{"month": month, **{key: int(counter.get(key, 0)) for key in keys}} for month, counter in sorted(months.items())]


def calculate_outcome_distribution(submissions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(str(row.get("status") or "draft") for row in submissions)
    return [{"outcome": outcome, "count": int(counts.get(outcome, 0))} for outcome in OUTCOMES]


def export_metrics(format_name: str = "json", **kwargs: Any) -> str:
    metrics = build_bug_intelligence_metrics(**kwargs)["bug_intelligence_metrics"]
    export = {
        "summary": metrics,
        "program_performance": metrics["top_programs"],
        "vulnerability_classes": metrics["top_vulnerability_classes"],
        "monthly_activity": metrics["monthly_activity"],
        "outcome_distribution": metrics["outcome_distribution"],
    }
    if format_name == "json":
        return json.dumps(export, indent=2, sort_keys=True)
    if format_name == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["program_name", "total_submissions", "accepted", "duplicates", "acceptance_rate", "duplicate_rate", "last_activity"])
        writer.writeheader()
        for row in export["program_performance"]:
            writer.writerow({key: row.get(key, "") for key in writer.fieldnames or []})
        return output.getvalue()
    raise ValueError("Unsupported metrics export format.")


def resolve_date_range(range_name: str = "all-time", *, start_date: str | None = None, end_date: str | None = None) -> dict[str, Any]:
    normalized = (range_name or "all-time").strip().lower().replace("_", "-")
    aliases = {"all": "all-time", "last-7": "last-7-days", "last-30": "last-30-days", "last-90": "last-90-days"}
    normalized = aliases.get(normalized, normalized)
    if normalized not in DATE_RANGE_OPTIONS:
        raise MetricsDateRangeError("Unsupported metrics date range.")
    now = datetime.now(timezone.utc)
    if normalized == "all-time":
        start = None
        end = None
    elif normalized == "this-year":
        start = datetime(now.year, 1, 1, tzinfo=timezone.utc)
        end = now
    elif normalized == "custom":
        start = _parse_date(start_date)
        end = _parse_date(end_date, end_of_day=True) if end_date else now
        if not start:
            raise MetricsDateRangeError("Custom metrics range requires start_date.")
    else:
        days = int(normalized.split("-")[1])
        start = now.replace(microsecond=0) - _days(days)
        end = now
    if start and end and start > end:
        raise MetricsDateRangeError("Metrics start_date cannot be after end_date.")
    return {
        "range": normalized,
        "start_date": start.isoformat() if start else None,
        "end_date": end.isoformat() if end else None,
    }


def classify_vulnerability(value: Any) -> str:
    text = str(value or "").replace("_", " ").replace("-", " ").strip().lower()
    if not text:
        return "Security Finding"
    checks = [
        ("idor", "IDOR"),
        ("insecure direct object", "IDOR"),
        ("open redirect", "Open Redirect"),
        ("cors", "CORS"),
        ("misconfiguration", "Security Misconfiguration"),
        ("reflected", "Reflected Input Indicator"),
        ("missing security header", "Missing Security Header"),
        ("security header", "Missing Security Header"),
        ("vulnerable component", "Vulnerable Component"),
        ("component", "Vulnerable Component"),
        ("directory listing", "Directory Listing"),
    ]
    for needle, label in checks:
        if needle in text:
            return label
    return " ".join(part.capitalize() for part in text.split()[:4])


def _filter_rows(rows: list[dict[str, Any]], date_range: dict[str, Any], field: str) -> list[dict[str, Any]]:
    start = _parse_date(date_range.get("start_date"))
    end = _parse_date(date_range.get("end_date"), end_of_day=True)
    if not start and not end:
        return rows
    result = []
    for row in rows:
        parsed = _parse_date(row.get(field))
        if not parsed:
            continue
        if start and parsed < start:
            continue
        if end and parsed > end:
            continue
        result.append(row)
    return result


def _count_evidence_records(submissions: list[dict[str, Any]], retests: list[dict[str, Any]], findings: list[dict[str, Any]]) -> int:
    evidence_ids: set[str] = set()
    for row in submissions:
        try:
            evidence_ids.update(str(item) for item in json.loads(row.get("evidence_ids_json") or "[]") if item)
        except (TypeError, json.JSONDecodeError):
            pass
    evidence_ids.update(str(row.get("evidence_id")) for row in retests if row.get("evidence_id"))
    return len(evidence_ids) + len(findings)


def _quality_indicators(**kwargs: Any) -> dict[str, Any]:
    submissions = kwargs["submissions"]
    findings = kwargs["findings"]
    total = len(submissions)
    score = 45
    if total:
        score += int(_rate(kwargs["total_accepted"], total) * 0.25)
        score -= int(_rate(kwargs["total_duplicates"], total) * 0.2)
        score -= int(_rate(kwargs["total_not_applicable"], total) * 0.25)
        score -= int(_rate(kwargs["total_informative"], total) * 0.08)
    if kwargs["total_reports_created"]:
        score += 8
    if kwargs["total_evidence_records"]:
        score += 10
    if any(row.get("evidence_ids_json") not in {None, "", "[]"} for row in submissions):
        score += 8
    if any(row.get("notes") for row in submissions):
        score += 5
    if any(row.get("impact") for row in findings):
        score += 5
    if any(row.get("recommendation") for row in findings):
        score += 5
    if kwargs["retest_passed_count"]:
        score += 8
    score = max(0, min(100, score))
    label = "Getting Started"
    if score >= 80:
        label = "High Quality"
    elif score >= 65:
        label = "Strong Workflow"
    elif score >= 45:
        label = "Improving"
    return {
        "score": score,
        "label": label,
        "reasons": [
            "Accepted findings, linked evidence, complete report fields, and passed retests increase the score.",
            "Duplicate, not applicable, and weakly documented outcomes reduce the score.",
            "This is a local workflow quality indicator only.",
        ],
    }


def _bounty_metrics(submissions: list[dict[str, Any]]) -> tuple[dict[str, float], dict[str, float]]:
    totals: dict[str, Decimal] = defaultdict(Decimal)
    counts: Counter[str] = Counter()
    for row in submissions:
        currency = str(row.get("bounty_currency") or "").upper().strip()
        if not currency:
            continue
        try:
            amount = Decimal(str(row.get("bounty_amount") or "0"))
        except InvalidOperation:
            continue
        if amount <= 0:
            continue
        totals[currency] += amount
        counts[currency] += 1
    total_out = {currency: float(amount) for currency, amount in sorted(totals.items())}
    average_out = {currency: float((totals[currency] / counts[currency]).quantize(Decimal("0.01"))) for currency in sorted(totals) if counts[currency]}
    return total_out, average_out


def _average_elapsed(rows: list[dict[str, Any]], start_field: str, end_field: str) -> float | None:
    values = []
    for row in rows:
        start = _parse_date(row.get(start_field))
        end = _parse_date(row.get(end_field))
        if start and end and end >= start:
            values.append((end - start).total_seconds() / 86400)
    return round(sum(values) / len(values), 2) if values else None


def _average_time_to_report_hours(submissions: list[dict[str, Any]]) -> float | None:
    values = []
    for row in submissions:
        created = _parse_date(row.get("created_at"))
        submitted = _parse_date(row.get("submitted_at"))
        if created and submitted and submitted >= created:
            values.append((submitted - created).total_seconds() / 3600)
    return round(sum(values) / len(values), 2) if values else None


def _top_owasp_categories(fingerprints: list[dict[str, Any]], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    for row in fingerprints:
        if row.get("owasp_category"):
            counts[str(row["owasp_category"])] += 1
    for row in findings:
        if row.get("category") and str(row.get("category")).upper().startswith("A0"):
            counts[str(row["category"])] += 1
    return [{"category": key, "count": value} for key, value in counts.most_common(10)]


def _add_severity(bucket: dict[str, Any], severity: Any) -> None:
    value = SEVERITY_SCORES.get(str(severity or "").strip().lower())
    if value:
        bucket["severity_total"] += value
        bucket["severity_count"] += 1


def _status_total(counts: Counter[str], status: str) -> int:
    return int(counts.get(status, 0))


def _accepted_total(counts: Counter[str]) -> int:
    return int(counts.get("accepted", 0) + counts.get("resolved", 0) + counts.get("paid", 0))


def _resolved_total(counts: Counter[str]) -> int:
    return int(counts.get("resolved", 0) + counts.get("paid", 0))


def _rate(count: int, total: int) -> float:
    return round((count / total) * 100, 2) if total else 0.0


def _month(value: Any) -> str:
    parsed = _parse_date(value)
    return parsed.strftime("%Y-%m") if parsed else ""


def _date_text(value: Any) -> str:
    parsed = _parse_date(value)
    return parsed.isoformat() if parsed else str(value or "")


def _parse_date(value: Any, *, end_of_day: bool = False) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            try:
                parsed = datetime.fromisoformat(f"{text}T23:59:59+00:00" if end_of_day else f"{text}T00:00:00+00:00")
            except ValueError:
                return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    if end_of_day and parsed.hour == 0 and parsed.minute == 0 and parsed.second == 0:
        parsed = parsed.replace(hour=23, minute=59, second=59)
    return parsed.astimezone(timezone.utc)


def _days(days: int):
    from datetime import timedelta

    return timedelta(days=days)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
