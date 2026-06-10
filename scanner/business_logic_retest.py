"""Observation and Retest Workflow records for Business Logic Review."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from scanner.evidence import redact_nested
from scanner.role_profiles import validate_no_credential_fields


BUSINESS_LOGIC_REPORTS_DIR = Path("reports") / "business_logic"
BUSINESS_LOGIC_EVIDENCE_DIR = BUSINESS_LOGIC_REPORTS_DIR / "evidence"
OBSERVED_RESULTS = {"behaved_as_expected", "unexpected_success", "unexpected_denial", "control_missing", "inconclusive", "not_tested"}
RETEST_STATUSES = {"not_started", "scheduled", "in_progress", "passed", "failed", "blocked", "not_applicable"}
SAFE_TESTING_STATEMENT = "Manual Validation Required. Authorised Test Data Only. No Automatic Workflow Execution."


class BusinessLogicRetestError(ValueError):
    """Raised when a Business Logic Review workflow record is invalid."""


@dataclass
class BusinessLogicObservation:
    observation_id: str
    review_plan_id: str
    observed_result: str
    observed_status_code: int | None = None
    observed_message_summary: str = ""
    observed_workflow_effect: str = ""
    evidence_summary: str = ""
    evidence_file_path: str = ""
    redaction_status: str = "redacted"
    tester_notes: str = ""
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BusinessLogicRetest:
    retest_id: str
    review_plan_id: str
    original_observed_result: str = ""
    remediation_summary: str = ""
    retest_steps: list[str] = field(default_factory=list)
    retest_observed_result: str = ""
    retest_status: str = "not_started"
    retest_notes: str = ""
    retested_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def ensure_business_logic_dirs() -> None:
    BUSINESS_LOGIC_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    BUSINESS_LOGIC_EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def build_business_logic_observation(
    *,
    review_plan_id: str,
    observed_result: str,
    observed_status_code: int | None = None,
    observed_message_summary: str = "",
    observed_workflow_effect: str = "",
    evidence_summary: str = "",
    evidence_file_path: str = "",
    tester_notes: str = "",
) -> dict[str, Any]:
    ensure_business_logic_dirs()
    validate_no_credential_fields({"observed_message_summary": observed_message_summary, "evidence_summary": evidence_summary, "tester_notes": tester_notes})
    if observed_result not in OBSERVED_RESULTS:
        raise BusinessLogicRetestError(f"Unsupported observed_result: {observed_result}")
    observation = BusinessLogicObservation(
        observation_id=f"observation_{uuid4().hex[:12]}",
        review_plan_id=str(review_plan_id),
        observed_result=observed_result,
        observed_status_code=observed_status_code,
        observed_message_summary=str(observed_message_summary or ""),
        observed_workflow_effect=str(observed_workflow_effect or ""),
        evidence_summary=str(evidence_summary or observed_message_summary or ""),
        evidence_file_path=_safe_evidence_path(evidence_file_path) if evidence_file_path else "",
        tester_notes=str(tester_notes or ""),
    )
    return redact_nested(observation.to_dict())


def observation_to_validation_status(observation: dict[str, Any]) -> str:
    result = str(observation.get("observed_result") or "not_tested")
    if result == "behaved_as_expected":
        return "manually_verified_secure"
    if result in {"unexpected_success", "control_missing"}:
        return "manually_verified_issue"
    if result in {"unexpected_denial", "inconclusive"}:
        return "needs_more_evidence"
    return "planned"


def build_business_logic_retest(
    *,
    review_plan_id: str,
    retest_status: str,
    original_observed_result: str = "",
    remediation_summary: str = "",
    retest_steps: list[str] | None = None,
    retest_observed_result: str = "",
    retest_notes: str = "",
) -> dict[str, Any]:
    validate_no_credential_fields({"remediation_summary": remediation_summary, "retest_steps": retest_steps or [], "retest_notes": retest_notes})
    if retest_status not in RETEST_STATUSES:
        raise BusinessLogicRetestError(f"Unsupported retest_status: {retest_status}")
    retest = BusinessLogicRetest(
        retest_id=f"retest_{uuid4().hex[:12]}",
        review_plan_id=str(review_plan_id),
        original_observed_result=str(original_observed_result or ""),
        remediation_summary=str(remediation_summary or ""),
        retest_steps=[str(step) for step in (retest_steps or ["Repeat the Workflow Review Plan using Authorised Test Data Only."])],
        retest_observed_result=str(retest_observed_result or ""),
        retest_status=retest_status,
        retest_notes=str(retest_notes or ""),
    )
    return redact_nested(retest.to_dict())


def retest_summary(records: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "retest_count": len(records or []),
        "retest_required_count": sum(1 for item in records or [] if item.get("retest_status") in {"not_started", "scheduled", "in_progress"}),
        "retest_passed_count": sum(1 for item in records or [] if item.get("retest_status") == "passed"),
        "retest_failed_count": sum(1 for item in records or [] if item.get("retest_status") == "failed"),
    }


def _safe_evidence_path(value: str) -> str:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    resolved = candidate.resolve()
    root = (Path.cwd() / BUSINESS_LOGIC_EVIDENCE_DIR).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise BusinessLogicRetestError("Evidence file path must be under reports/business_logic/evidence.") from exc
    return str(resolved)
