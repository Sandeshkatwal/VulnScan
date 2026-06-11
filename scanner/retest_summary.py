"""Retest status helpers for Professional Findings."""

from __future__ import annotations

from typing import Any

from scanner.finding_models import now_iso


RETEST_STATUSES = {"not_retested", "retest_required", "retest_scheduled", "retest_passed", "retest_failed", "not_applicable"}


def update_finding_retest_status(finding: dict[str, Any], retest_record: dict[str, Any]) -> dict[str, Any]:
    updated = dict(finding)
    status = str(retest_record.get("retest_status") or retest_record.get("status") or "not_retested")
    if status not in RETEST_STATUSES:
        status = "not_retested"
    updated["retest_status"] = status
    updated["retest_notes"] = retest_record.get("retest_notes") or retest_record.get("notes") or updated.get("retest_notes") or ""
    updated["updated_at"] = now_iso()
    if status == "retest_passed":
        updated["status"] = "remediated"
        updated["validation_status"] = "retest_passed"
    elif status == "retest_failed":
        updated["status"] = "retest_required"
        updated["validation_status"] = "retest_failed"
    elif status == "retest_required":
        updated["status"] = "retest_required"
        updated["validation_status"] = "retest_required"
    return updated


def build_retest_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {status: 0 for status in sorted(RETEST_STATUSES)}
    notes: list[dict[str, Any]] = []
    for finding in findings:
        status = str(finding.get("retest_status") or "not_retested")
        if status not in counts:
            status = "not_retested"
        counts[status] += 1
        if finding.get("retest_notes"):
            notes.append({"finding_id": finding.get("finding_id"), "title": finding.get("title"), "status": status, "notes": finding.get("retest_notes")})
    return {
        "requiring_retest": counts["retest_required"],
        "passed": counts["retest_passed"],
        "failed": counts["retest_failed"],
        "not_retested": counts["not_retested"],
        "scheduled": counts["retest_scheduled"],
        "not_applicable": counts["not_applicable"],
        "status_counts": counts,
        "notes": notes,
    }

