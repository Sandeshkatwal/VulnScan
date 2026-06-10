"""Retest Workflow records for A01 Manual Validation Plans."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from scanner.evidence import redact_nested
from scanner.role_profiles import validate_no_credential_fields


RETEST_STATUSES = {"not_started", "scheduled", "in_progress", "passed", "failed", "blocked", "not_applicable"}


class AccessControlRetestError(ValueError):
    """Raised when a retest record is invalid."""


@dataclass
class A01RetestRecord:
    retest_id: str
    test_plan_id: str
    original_observed_result: str = ""
    remediation_summary: str = ""
    retest_steps: list[str] = field(default_factory=list)
    retest_observed_result: str = ""
    retest_status: str = "not_started"
    retest_notes: str = ""
    retested_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_a01_retest_record(
    *,
    test_plan_id: str,
    retest_status: str,
    original_observed_result: str = "",
    remediation_summary: str = "",
    retest_steps: list[str] | None = None,
    retest_observed_result: str = "",
    retest_notes: str = "",
) -> dict[str, Any]:
    validate_no_credential_fields(
        {
            "test_plan_id": test_plan_id,
            "original_observed_result": original_observed_result,
            "remediation_summary": remediation_summary,
            "retest_steps": retest_steps or [],
            "retest_observed_result": retest_observed_result,
            "retest_notes": retest_notes,
        }
    )
    if retest_status not in RETEST_STATUSES:
        raise AccessControlRetestError(f"Unsupported retest_status: {retest_status}")
    record = A01RetestRecord(
        retest_id=f"retest_{uuid4().hex[:12]}",
        test_plan_id=str(test_plan_id),
        original_observed_result=str(original_observed_result or ""),
        remediation_summary=str(remediation_summary or ""),
        retest_steps=[str(step) for step in (retest_steps or ["Repeat the original A01 Manual Validation Plan steps using approved test data."])],
        retest_observed_result=str(retest_observed_result or ""),
        retest_status=retest_status,
        retest_notes=str(retest_notes or ""),
    )
    return redact_nested(record.to_dict())


def retest_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "retest_count": len(records or []),
        "retest_required_count": sum(1 for item in records or [] if item.get("retest_status") in {"not_started", "scheduled", "in_progress"}),
        "retest_passed_count": sum(1 for item in records or [] if item.get("retest_status") == "passed"),
        "retest_failed_count": sum(1 for item in records or [] if item.get("retest_status") == "failed"),
        "retest_blocked_count": sum(1 for item in records or [] if item.get("retest_status") == "blocked"),
    }
