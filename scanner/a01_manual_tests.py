"""A01 manual observation records for Access Control Manual Test Planner."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from scanner.evidence import redact_nested
from scanner.role_profiles import validate_no_credential_fields


ACCESS_TEST_REPORTS_DIR = Path("reports") / "access_control_tests"
ACCESS_TEST_EVIDENCE_DIR = ACCESS_TEST_REPORTS_DIR / "evidence"
OBSERVED_ACCESS_RESULTS = {
    "allowed_as_expected",
    "denied_as_expected",
    "unexpectedly_allowed",
    "unexpectedly_denied",
    "inconclusive",
    "not_tested",
}


class A01ManualTestError(ValueError):
    """Raised when an A01 manual test workflow object is invalid."""


@dataclass
class A01Observation:
    observation_id: str
    test_plan_id: str
    observed_status: str = "recorded"
    observed_status_code: int | None = None
    observed_message_summary: str = ""
    observed_access_result: str = "not_tested"
    evidence_summary: str = ""
    evidence_file_path: str = ""
    redaction_status: str = "redacted"
    tester_notes: str = ""
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def ensure_access_test_dirs() -> None:
    ACCESS_TEST_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ACCESS_TEST_EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def build_a01_observation(
    *,
    test_plan_id: str,
    observed_access_result: str,
    observed_status_code: int | None = None,
    observed_message_summary: str = "",
    evidence_summary: str = "",
    evidence_file_path: str = "",
    tester_notes: str = "",
    observed_status: str = "recorded",
) -> dict[str, Any]:
    """Create a redacted manual observation. No response bodies are stored."""
    ensure_access_test_dirs()
    validate_no_credential_fields(
        {
            "test_plan_id": test_plan_id,
            "observed_message_summary": observed_message_summary,
            "evidence_summary": evidence_summary,
            "evidence_file_path": evidence_file_path,
            "tester_notes": tester_notes,
        }
    )
    if observed_access_result not in OBSERVED_ACCESS_RESULTS:
        raise A01ManualTestError(f"Unsupported observed_access_result: {observed_access_result}")
    safe_path = _safe_evidence_path(evidence_file_path) if evidence_file_path else ""
    observation = A01Observation(
        observation_id=f"observation_{uuid4().hex[:12]}",
        test_plan_id=str(test_plan_id),
        observed_status=observed_status,
        observed_status_code=observed_status_code,
        observed_message_summary=str(observed_message_summary or ""),
        observed_access_result=observed_access_result,
        evidence_summary=str(evidence_summary or observed_message_summary or ""),
        evidence_file_path=safe_path,
        redaction_status="redacted",
        tester_notes=str(tester_notes or ""),
    )
    return redact_nested(observation.to_dict())


def observation_to_validation_status(observation: dict[str, Any]) -> str:
    result = str(observation.get("observed_access_result") or "not_tested")
    if result in {"allowed_as_expected", "denied_as_expected"}:
        return "manually_verified_secure"
    if result in {"unexpectedly_allowed", "unexpectedly_denied"}:
        return "manually_verified_issue"
    if result == "inconclusive":
        return "needs_more_evidence"
    return "planned"


def _safe_evidence_path(value: str) -> str:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    resolved = candidate.resolve()
    root = (Path.cwd() / ACCESS_TEST_EVIDENCE_DIR).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise A01ManualTestError("Evidence file path must be under reports/access_control_tests/evidence.") from exc
    return str(resolved)
