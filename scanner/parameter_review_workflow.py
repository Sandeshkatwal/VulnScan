"""Observation, evidence checklist, retest, and report templates for replay plans."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from scanner.evidence import redact_nested
from scanner.role_profiles import validate_no_credential_fields


PARAMETER_REPLAY_REPORTS_DIR = Path("reports") / "parameter_replay"
PARAMETER_REPLAY_EVIDENCE_DIR = PARAMETER_REPLAY_REPORTS_DIR / "evidence"
OBSERVED_ACCESS_RESULTS = {
    "allowed_as_expected",
    "denied_as_expected",
    "unexpectedly_allowed",
    "unexpectedly_denied",
    "reflected_as_expected",
    "reflected_with_context_risk",
    "inconclusive",
    "not_tested",
}
RETEST_STATUSES = {"not_started", "scheduled", "in_progress", "passed", "failed", "blocked", "not_applicable"}
SAFE_TESTING_STATEMENT = (
    "Manual Validation Required. Authorised Test Accounts Only. No Automatic Replay. "
    "VulScan creates redacted local planning records and does not send replay requests."
)


class ParameterReviewWorkflowError(ValueError):
    """Raised when replay planner workflow data is invalid."""


@dataclass
class ParameterReplayObservation:
    observation_id: str
    replay_plan_id: str
    observed_access_result: str
    observed_status_code: int | None = None
    observed_message_summary: str = ""
    observed_parameter_effect: str = ""
    evidence_summary: str = ""
    evidence_file_path: str = ""
    redaction_status: str = "redacted"
    tester_notes: str = ""
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ParameterReplayRetest:
    retest_id: str
    replay_plan_id: str
    original_observed_result: str = ""
    remediation_summary: str = ""
    retest_steps: list[str] = field(default_factory=list)
    retest_observed_result: str = ""
    retest_status: str = "not_started"
    retest_notes: str = ""
    retested_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def ensure_parameter_replay_dirs() -> None:
    PARAMETER_REPLAY_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (PARAMETER_REPLAY_REPORTS_DIR / "templates").mkdir(parents=True, exist_ok=True)
    PARAMETER_REPLAY_EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def build_replay_evidence_checklist(replay_plan_id: str) -> dict[str, Any]:
    items = [
        "Authorisation scope confirmed.",
        "Test account label recorded.",
        "Role label recorded.",
        "Parameter recorded.",
        "Parameter value redacted.",
        "Request template redacted.",
        "Expected secure behaviour recorded.",
        "Observed behaviour recorded.",
        "Status code recorded if safe.",
        "Response summary redacted.",
        "No secrets included.",
        "No real third-party data included.",
        "State-changing action avoided or approved manually.",
        "Retest requirement recorded.",
        "Recommendation recorded.",
    ]
    return {
        "checklist_id": f"checklist_{uuid4().hex[:12]}",
        "replay_plan_id": replay_plan_id,
        "items": [{"item_id": f"item_{index + 1}", "item": item, "status": "pending", "required": True, "notes": ""} for index, item in enumerate(items)],
    }


def build_parameter_replay_observation(
    *,
    replay_plan_id: str,
    observed_access_result: str,
    observed_status_code: int | None = None,
    observed_message_summary: str = "",
    observed_parameter_effect: str = "",
    evidence_summary: str = "",
    evidence_file_path: str = "",
    tester_notes: str = "",
) -> dict[str, Any]:
    ensure_parameter_replay_dirs()
    validate_no_credential_fields({"observed_message_summary": observed_message_summary, "evidence_summary": evidence_summary, "tester_notes": tester_notes})
    if observed_access_result not in OBSERVED_ACCESS_RESULTS:
        raise ParameterReviewWorkflowError(f"Unsupported observed_access_result: {observed_access_result}")
    observation = ParameterReplayObservation(
        observation_id=f"observation_{uuid4().hex[:12]}",
        replay_plan_id=str(replay_plan_id),
        observed_access_result=observed_access_result,
        observed_status_code=observed_status_code,
        observed_message_summary=str(observed_message_summary or ""),
        observed_parameter_effect=str(observed_parameter_effect or ""),
        evidence_summary=str(evidence_summary or observed_message_summary or ""),
        evidence_file_path=_safe_evidence_path(evidence_file_path) if evidence_file_path else "",
        tester_notes=str(tester_notes or ""),
    )
    return redact_nested(observation.to_dict())


def observation_to_validation_status(observation: dict[str, Any]) -> str:
    result = str(observation.get("observed_access_result") or "not_tested")
    if result in {"allowed_as_expected", "denied_as_expected", "reflected_as_expected"}:
        return "manually_verified_secure"
    if result in {"unexpectedly_allowed", "unexpectedly_denied", "reflected_with_context_risk"}:
        return "manually_verified_issue"
    if result == "inconclusive":
        return "needs_more_evidence"
    return "planned"


def build_parameter_replay_retest(
    *,
    replay_plan_id: str,
    retest_status: str,
    original_observed_result: str = "",
    remediation_summary: str = "",
    retest_steps: list[str] | None = None,
    retest_observed_result: str = "",
    retest_notes: str = "",
) -> dict[str, Any]:
    validate_no_credential_fields({"remediation_summary": remediation_summary, "retest_steps": retest_steps or [], "retest_notes": retest_notes})
    if retest_status not in RETEST_STATUSES:
        raise ParameterReviewWorkflowError(f"Unsupported retest_status: {retest_status}")
    record = ParameterReplayRetest(
        retest_id=f"retest_{uuid4().hex[:12]}",
        replay_plan_id=str(replay_plan_id),
        original_observed_result=str(original_observed_result or ""),
        remediation_summary=str(remediation_summary or ""),
        retest_steps=[str(step) for step in (retest_steps or ["Repeat the Replay Plan manual validation steps using approved test data only."])],
        retest_observed_result=str(retest_observed_result or ""),
        retest_status=retest_status,
        retest_notes=str(retest_notes or ""),
    )
    return redact_nested(record.to_dict())


def build_report_ready_replay_template(plan: dict[str, Any], observation: dict[str, Any] | None = None, retest: dict[str, Any] | None = None) -> dict[str, Any]:
    observation = observation or plan.get("observed_behaviour") or {}
    observed_result = str(observation.get("observed_access_result") or "not_tested")
    is_issue = observed_result in {"unexpectedly_allowed", "reflected_with_context_risk"}
    title_prefix = "Manually Verified Parameter Replay Issue" if is_issue else "Replay Plan"
    return redact_nested(
        {
            "Title": f"{title_prefix}: {plan.get('title') or 'Parameter Review Plan'}",
            "Summary": _summary(plan, is_issue),
            "Affected Endpoint": plan.get("affected_url") or plan.get("normalised_url") or "",
            "Parameter": plan.get("parameter_name") or "",
            "Role/Context": plan.get("role_label") or "",
            "Expected Behaviour": plan.get("expected_secure_behaviour") or "",
            "Observed Behaviour": observation.get("observed_message_summary") or "Manual validation has not confirmed an issue.",
            "Impact if Confirmed": _impact(plan),
            "Redacted Request Template": plan.get("safe_request_template_id") or "",
            "Evidence": observation.get("evidence_summary") or "Evidence Checklist pending.",
            "Manual Steps": plan.get("manual_steps") or [],
            "Recommendation": _recommendation(plan),
            "Retest Notes": (retest or {}).get("retest_notes") or "",
            "Limitations": [
                "Candidate wording is required until manual validation confirms Observed Behaviour." if not is_issue else "Issue wording is based on manually recorded Observed Behaviour.",
                "Use Authorised Test Accounts Only.",
                "No secrets, raw cookies, raw tokens, raw credentials, or third-party data may be included.",
            ],
            "Safe Testing Statement": SAFE_TESTING_STATEMENT,
            "observed_access_result": observed_result,
        }
    )


def render_report_template_markdown(template: dict[str, Any]) -> str:
    steps = "\n".join(f"{index + 1}. {step}" for index, step in enumerate(template.get("Manual Steps") or []))
    limitations = "\n".join(f"- {item}" for item in template.get("Limitations") or [])
    return f"""# {template.get('Title')}

## Summary
{template.get('Summary')}

## Affected Endpoint
{template.get('Affected Endpoint')}

## Parameter
{template.get('Parameter')}

## Role/Context
{template.get('Role/Context')}

## Expected Behaviour
{template.get('Expected Behaviour')}

## Observed Behaviour
{template.get('Observed Behaviour')}

## Impact if Confirmed
{template.get('Impact if Confirmed')}

## Redacted Request Template
{template.get('Redacted Request Template')}

## Evidence
{template.get('Evidence')}

## Manual Steps
{steps}

## Recommendation
{template.get('Recommendation')}

## Retest Notes
{template.get('Retest Notes')}

## Limitations
{limitations}

## Safe Testing Statement
{template.get('Safe Testing Statement')}
"""


def save_replay_report_markdown(template: dict[str, Any], plan_id: str) -> Path:
    ensure_parameter_replay_dirs()
    safe_id = "".join(ch for ch in str(plan_id) if ch.isalnum() or ch in {"-", "_"}) or "plan"
    path = PARAMETER_REPLAY_REPORTS_DIR / f"replay_plan_{safe_id}.md"
    path.write_text(render_report_template_markdown(template), encoding="utf-8")
    return path


def retest_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
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
    root = (Path.cwd() / PARAMETER_REPLAY_EVIDENCE_DIR).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ParameterReviewWorkflowError("Evidence file path must be under reports/parameter_replay/evidence.") from exc
    return str(resolved)


def _summary(plan: dict[str, Any], is_issue: bool) -> str:
    if is_issue:
        return f"Manual validation recorded Observed Behaviour that differs from Expected Behaviour for parameter {plan.get('parameter_name') or ''}."
    return "Candidate Replay Plan for manual review. Manual Validation Required before reporting confirmed impact."


def _impact(plan: dict[str, Any]) -> str:
    categories = ", ".join(plan.get("related_owasp_categories") or [])
    return f"Potential {categories or 'OWASP'} issue if Observed Behaviour confirms the parameter changes authorization, session, redirect, export, or input validation behaviour."


def _recommendation(plan: dict[str, Any]) -> str:
    intent = str(plan.get("replay_intent") or "")
    if intent in {"object_ownership_review", "tenant_boundary_review", "export_download_review"}:
        return "Enforce server-side authorization, ownership, and tenant checks for the parameter."
    if intent == "role_permission_review":
        return "Ignore client-controlled role or permission fields for authorization decisions."
    if intent == "auth_session_review":
        return "Validate CSRF/state/nonce/session controls server-side without exposing token values."
    if intent == "redirect_callback_review":
        return "Validate redirect and callback allowlists and state binding server-side."
    return "Validate parameter handling server-side and record manual verification evidence."
