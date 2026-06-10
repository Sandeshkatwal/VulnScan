"""Business Logic Review Workflow Assistant.

Creates local manual Workflow Review Plans only. It never executes workflow
steps, triggers payments, changes approvals, or submits state-changing requests.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from scanner.business_logic_checklists import build_abuse_case_checklist
from scanner.business_logic_retest import SAFE_TESTING_STATEMENT, observation_to_validation_status, retest_summary
from scanner.evidence import redact_nested
from scanner.request_template_builder import normalise_url_path_ids
from scanner.workflow_candidates import assess_business_logic_workflow_candidates, workflow_risk_label
from scanner.workflow_state_map import build_state_transition_map


BUSINESS_LOGIC_DIR = Path("data") / "business_logic"
BUSINESS_LOGIC_REPORTS_DIR = Path("reports") / "business_logic"
VALIDATION_STATUSES = {
    "planned",
    "in_progress",
    "manually_verified_secure",
    "manually_verified_issue",
    "needs_more_evidence",
    "not_applicable",
    "retest_required",
    "retest_passed",
    "retest_failed",
}


class BusinessLogicReviewError(ValueError):
    """Raised when Business Logic Review data is invalid."""


@dataclass
class BusinessLogicReviewPlan:
    review_plan_id: str
    title: str
    workflow_type: str
    target: str
    affected_urls: list[str]
    related_parameters: list[str] = field(default_factory=list)
    related_roles: list[str] = field(default_factory=list)
    related_owasp_categories: list[str] = field(default_factory=list)
    expected_business_rule: str = ""
    expected_secure_behaviour: str = ""
    abuse_cases: dict[str, Any] = field(default_factory=dict)
    state_transition_map: dict[str, Any] = field(default_factory=dict)
    manual_steps: list[str] = field(default_factory=list)
    evidence_checklist: dict[str, Any] = field(default_factory=dict)
    observed_behaviour: dict[str, Any] = field(default_factory=dict)
    validation_status: str = "planned"
    risk_if_failed: str = ""
    recommendation: str = ""
    retest_status: str = "not_started"
    safety_notes: list[str] = field(default_factory=list)
    linked_candidates: list[str] = field(default_factory=list)
    linked_replay_plans: list[str] = field(default_factory=list)
    linked_access_test_plans: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def ensure_business_logic_dirs() -> None:
    BUSINESS_LOGIC_DIR.mkdir(parents=True, exist_ok=True)
    BUSINESS_LOGIC_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (BUSINESS_LOGIC_REPORTS_DIR / "evidence").mkdir(parents=True, exist_ok=True)


def build_business_logic_review_plan(candidate: dict[str, Any], roles: list[dict[str, Any]] | None = None, replay_plans: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    workflow_type = str(candidate.get("workflow_type") or "custom")
    url = str(candidate.get("affected_url") or candidate.get("normalised_url") or "")
    plan_id = str(candidate.get("review_plan_id") or f"business_logic_plan_{uuid4().hex[:12]}")
    related_roles = list(candidate.get("related_roles") or [str(role.get("role_label") or role.get("role_id") or "") for role in roles or [] if isinstance(role, dict)])
    state_map = build_state_transition_map(workflow_type, [url], roles)
    abuse = build_abuse_case_checklist(workflow_type, plan_id)
    plan = BusinessLogicReviewPlan(
        review_plan_id=plan_id,
        title=f"Business Logic Review: {workflow_type.replace('_', ' ').title()}",
        workflow_type=workflow_type,
        target=str(candidate.get("target") or _target(url)),
        affected_urls=[url] if url else [],
        related_parameters=[str(item) for item in candidate.get("related_parameters") or []],
        related_roles=[item for item in related_roles if item],
        related_owasp_categories=[str(item) for item in candidate.get("related_owasp_categories") or _related_owasp(workflow_type)],
        expected_business_rule=_expected_business_rule(workflow_type),
        expected_secure_behaviour=expected_secure_behaviour(workflow_type),
        abuse_cases=abuse,
        state_transition_map=state_map,
        manual_steps=manual_steps_for_workflow(workflow_type),
        evidence_checklist=business_logic_evidence_checklist(plan_id),
        validation_status="planned",
        risk_if_failed=_risk_if_failed(workflow_type),
        recommendation=str(candidate.get("recommendation") or _recommendation(workflow_type)),
        retest_status="not_started",
        safety_notes=safety_notes_for_workflow(workflow_type),
        linked_candidates=[str(candidate.get("workflow_candidate_id") or "")],
        linked_replay_plans=_linked_replay_plans(url, workflow_type, replay_plans or []),
        linked_access_test_plans=[],
    )
    return redact_nested(plan.to_dict())


def build_review_plans_from_candidates(
    candidates: list[dict[str, Any]],
    roles: list[dict[str, Any]] | None = None,
    replay_plans: list[dict[str, Any]] | None = None,
    access_test_plans: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    plans: list[dict[str, Any]] = []
    seen: set[str] = set()
    for candidate in candidates or []:
        plan = build_business_logic_review_plan(candidate, roles, replay_plans)
        plan["linked_access_test_plans"] = _linked_access_plans(plan.get("affected_urls") or [], access_test_plans or [])
        fp = business_logic_plan_fingerprint(plan)
        if fp in seen:
            continue
        seen.add(fp)
        plans.append(plan)
    return plans


def build_business_logic_summary(
    candidates: list[dict[str, Any]] | None = None,
    plans: list[dict[str, Any]] | None = None,
    observations: list[dict[str, Any]] | None = None,
    retests: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    observed_statuses = {str(item.get("review_plan_id")): observation_to_validation_status(item) for item in observations or []}
    statuses = [observed_statuses.get(str(plan.get("review_plan_id")), str(plan.get("validation_status") or "planned")) for plan in plans or []]
    retest_counts = retest_summary(retests or [])
    return {
        "enabled": True,
        "workflow_candidates_count": len(candidates or []),
        "business_logic_review_plans_count": len(plans or []),
        "business_logic_manual_observations_count": len(observations or []),
        "business_logic_verified_issue_count": statuses.count("manually_verified_issue"),
        "business_logic_verified_secure_count": statuses.count("manually_verified_secure"),
        "critical_review_candidates_count": sum(1 for item in candidates or [] if workflow_risk_label(int(item.get("candidate_score") or 0)) == "Critical Review"),
        "high_review_candidates_count": sum(1 for item in candidates or [] if workflow_risk_label(int(item.get("candidate_score") or 0)) == "High Review"),
        "medium_review_candidates_count": sum(1 for item in candidates or [] if workflow_risk_label(int(item.get("candidate_score") or 0)) == "Medium Review"),
        "low_review_candidates_count": sum(1 for item in candidates or [] if workflow_risk_label(int(item.get("candidate_score") or 0)) == "Low Review"),
        "financial_workflows_count": sum(1 for item in candidates or [] if item.get("workflow_type") in {"checkout_payment", "refund_transfer", "subscription_plan", "coupon_discount"}),
        "approval_workflows_count": sum(1 for item in candidates or [] if item.get("workflow_type") == "approval_rejection"),
        "account_lifecycle_workflows_count": sum(1 for item in candidates or [] if item.get("workflow_type") in {"account_lifecycle", "password_reset"}),
        "import_export_webhook_workflows_count": sum(1 for item in candidates or [] if item.get("workflow_type") in {"import_export", "notification_webhook"}),
        "retest_status": _dominant_retest_status(retests or []),
        "retest_required_count": retest_counts.get("retest_required_count", 0),
        "retest_passed_count": retest_counts.get("retest_passed_count", 0),
        "retest_failed_count": retest_counts.get("retest_failed_count", 0),
        "safety_notes": [SAFE_TESTING_STATEMENT],
    }


def package_business_logic(
    candidates: list[dict[str, Any]] | None = None,
    plans: list[dict[str, Any]] | None = None,
    observations: list[dict[str, Any]] | None = None,
    retests: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    plans = plans or []
    state_maps = [plan.get("state_transition_map") for plan in plans if plan.get("state_transition_map")]
    checklists = [plan.get("abuse_cases") for plan in plans if plan.get("abuse_cases")]
    return redact_nested(
        {
            "business_logic_workflow_candidates": candidates or [],
            "business_logic_review_plans": plans,
            "business_logic_state_transition_maps": state_maps,
            "business_logic_abuse_case_checklists": checklists,
            "business_logic_observations": observations or [],
            "business_logic_retests": retests or [],
            "business_logic_summary": build_business_logic_summary(candidates or [], plans, observations or [], retests or []),
        }
    )


def business_logic_plan_fingerprint(plan: dict[str, Any]) -> str:
    raw = "|".join(
        [
            str(plan.get("workflow_type") or "custom").lower(),
            normalise_url_path_ids(str((plan.get("affected_urls") or [""])[0] or "")).lower(),
            ",".join(sorted(str(role).lower() for role in plan.get("related_roles") or [])),
            ",".join(sorted(str(param).lower() for param in plan.get("related_parameters") or [])),
            ",".join(sorted(str(cat).lower() for cat in plan.get("related_owasp_categories") or [])),
        ]
    )
    return str(abs(hash(raw)))


def load_business_logic_plans(path: str | Path = BUSINESS_LOGIC_DIR / "sample_workflow_plan.json") -> dict[str, Any]:
    plan_path = _resolve_business_logic_path(path)
    try:
        payload = json.loads(plan_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BusinessLogicReviewError(f"Business Logic Review file was not found: {plan_path}") from exc
    except json.JSONDecodeError as exc:
        raise BusinessLogicReviewError(f"Business Logic Review file is not valid JSON: {plan_path}") from exc
    candidates = payload.get("business_logic_workflow_candidates") or []
    plans = payload.get("business_logic_review_plans") or payload.get("workflow_review_plans") or []
    observations = payload.get("business_logic_observations") or []
    retests = payload.get("business_logic_retests") or []
    return package_business_logic(candidates, plans, observations, retests)


def find_business_logic_plan(plans: list[dict[str, Any]], plan_id: str) -> dict[str, Any]:
    for plan in plans or []:
        if str(plan.get("review_plan_id") or "") == str(plan_id):
            return plan
    raise BusinessLogicReviewError(f"Business Logic Review plan was not found: {plan_id}")


def save_business_logic_package(package: dict[str, Any], *, json_report: bool = False, html_report: bool = False) -> tuple[Path | None, Path | None]:
    ensure_business_logic_dirs()
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    json_path: Path | None = None
    html_path: Path | None = None
    if json_report:
        json_path = BUSINESS_LOGIC_REPORTS_DIR / f"business_logic_{stamp}.json"
        json_path.write_text(json.dumps(redact_nested(package), indent=2), encoding="utf-8")
    if html_report:
        html_path = BUSINESS_LOGIC_REPORTS_DIR / f"business_logic_{stamp}.html"
        html_path.write_text(render_business_logic_html(package), encoding="utf-8")
    return json_path, html_path


def build_report_ready_business_logic_template(plan: dict[str, Any], observation: dict[str, Any] | None = None, retest: dict[str, Any] | None = None) -> dict[str, Any]:
    observation = observation or plan.get("observed_behaviour") or {}
    observed_result = str(observation.get("observed_result") or "not_tested")
    is_issue = observed_result in {"unexpected_success", "control_missing"}
    return redact_nested(
        {
            "Title": f"{'Manually Verified Business Logic Issue' if is_issue else 'Business Logic Review Plan'}: {plan.get('title') or plan.get('workflow_type')}",
            "Summary": "Manual validation recorded Observed Behaviour that differs from the Expected Business Rule." if is_issue else "Candidate Business Logic Review plan. Manual Validation Required before reporting confirmed impact.",
            "Workflow Type": plan.get("workflow_type") or "",
            "Affected Endpoint(s)": plan.get("affected_urls") or [],
            "Role/Context": ", ".join(str(role) for role in plan.get("related_roles") or []),
            "Expected Business Rule": plan.get("expected_business_rule") or "",
            "Expected Secure Behaviour": plan.get("expected_secure_behaviour") or "",
            "Observed Behaviour": observation.get("observed_message_summary") or "Manual validation has not confirmed an issue.",
            "Impact if Confirmed": plan.get("risk_if_failed") or "",
            "Abuse Case": [item.get("item") for item in (plan.get("abuse_cases") or {}).get("items", [])[:5]],
            "Evidence": observation.get("evidence_summary") or "Evidence Checklist pending.",
            "Manual Steps": plan.get("manual_steps") or [],
            "Recommendation": plan.get("recommendation") or "",
            "Retest Notes": (retest or {}).get("retest_notes") or "",
            "Limitations": [
                "Candidate wording is required until manual validation confirms Observed Behaviour." if not is_issue else "Issue wording is based on manually recorded Observed Behaviour.",
                "Authorised Test Data Only.",
                "No Automatic Workflow Execution.",
                "No raw secrets, tokens, cookies, credentials, or third-party data may be included.",
            ],
            "Safe Testing Statement": SAFE_TESTING_STATEMENT,
            "observed_result": observed_result,
        }
    )


def render_report_template_markdown(template: dict[str, Any]) -> str:
    steps = "\n".join(f"{index + 1}. {step}" for index, step in enumerate(template.get("Manual Steps") or []))
    limitations = "\n".join(f"- {item}" for item in template.get("Limitations") or [])
    abuse = "\n".join(f"- {item}" for item in template.get("Abuse Case") or [])
    endpoints = "\n".join(f"- {item}" for item in template.get("Affected Endpoint(s)") or [])
    return f"""# {template.get('Title')}

## Summary
{template.get('Summary')}

## Workflow Type
{template.get('Workflow Type')}

## Affected Endpoint(s)
{endpoints}

## Role/Context
{template.get('Role/Context')}

## Expected Business Rule
{template.get('Expected Business Rule')}

## Expected Secure Behaviour
{template.get('Expected Secure Behaviour')}

## Observed Behaviour
{template.get('Observed Behaviour')}

## Impact if Confirmed
{template.get('Impact if Confirmed')}

## Abuse Case
{abuse}

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


def save_business_logic_markdown(template: dict[str, Any], plan_id: str) -> Path:
    ensure_business_logic_dirs()
    safe_id = "".join(ch for ch in str(plan_id) if ch.isalnum() or ch in {"-", "_"}) or "plan"
    path = BUSINESS_LOGIC_REPORTS_DIR / f"business_logic_plan_{safe_id}.md"
    path.write_text(render_report_template_markdown(template), encoding="utf-8")
    return path


def render_business_logic_html(package: dict[str, Any]) -> str:
    summary = package.get("business_logic_summary") or {}
    candidates = package.get("business_logic_workflow_candidates") or []
    plans = package.get("business_logic_review_plans") or []
    observations = package.get("business_logic_observations") or []
    retests = package.get("business_logic_retests") or []
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Business Logic Review Workflow Assistant</title>
<style>body{{font-family:Arial,sans-serif;margin:24px;color:#172033}}table{{border-collapse:collapse;width:100%;margin:12px 0}}td,th{{border:1px solid #d7dce5;padding:8px;text-align:left}}th{{background:#eef2f7}}.note{{background:#f6f8fb;border:1px solid #d7dce5;padding:12px}}</style></head>
<body><h1>Business Logic Review Workflow Assistant</h1><p class="note">{SAFE_TESTING_STATEMENT}</p>
<h2>Workflow Candidate Summary</h2><p>Candidates: {summary.get('workflow_candidates_count', 0)}. Plans: {summary.get('business_logic_review_plans_count', 0)}. Verified Issues: {summary.get('business_logic_verified_issue_count', 0)}. Retest Passed/Failed: {summary.get('retest_passed_count', 0)}/{summary.get('retest_failed_count', 0)}.</p>
<h2>Workflow Candidates</h2><table><tr><th>Candidate</th><th>Type</th><th>Endpoint</th><th>Sensitivity</th><th>Score</th><th>OWASP</th></tr>{''.join(f"<tr><td>{c.get('workflow_candidate_id','')}</td><td>{c.get('workflow_type','')}</td><td>{c.get('affected_url','')}</td><td>{c.get('workflow_sensitivity','')}</td><td>{c.get('candidate_score','')}</td><td>{', '.join(c.get('related_owasp_categories') or [])}</td></tr>" for c in candidates)}</table>
<h2>Workflow Review Plans</h2><table><tr><th>Plan</th><th>Type</th><th>Endpoint</th><th>Roles</th><th>Status</th><th>Retest</th></tr>{''.join(f"<tr><td>{p.get('review_plan_id','')}</td><td>{p.get('workflow_type','')}</td><td>{', '.join(p.get('affected_urls') or [])}</td><td>{', '.join(p.get('related_roles') or [])}</td><td>{p.get('validation_status','')}</td><td>{p.get('retest_status','')}</td></tr>" for p in plans)}</table>
<h2>Expected vs Observed Behaviour</h2><table><tr><th>Plan</th><th>Observed Result</th><th>Status Code</th><th>Summary</th><th>Redaction</th></tr>{''.join(f"<tr><td>{o.get('review_plan_id','')}</td><td>{o.get('observed_result','')}</td><td>{o.get('observed_status_code','')}</td><td>{o.get('observed_message_summary','')}</td><td>{o.get('redaction_status','')}</td></tr>" for o in observations)}</table>
<h2>Retest Workflow</h2><table><tr><th>Plan</th><th>Status</th><th>Observed Result</th><th>Notes</th></tr>{''.join(f"<tr><td>{r.get('review_plan_id','')}</td><td>{r.get('retest_status','')}</td><td>{r.get('retest_observed_result','')}</td><td>{r.get('retest_notes','')}</td></tr>" for r in retests)}</table>
</body></html>"""


def expected_secure_behaviour(workflow_type: str) -> str:
    mapping = {
        "checkout_payment": "Payment, checkout, order, and price-sensitive operations must enforce server-side validation, authorization, and anti-tampering controls.",
        "approval_rejection": "Only authorised roles can approve, reject, verify, or transition workflow items.",
        "coupon_discount": "Discounts, coupons, and price changes must be validated server-side and cannot be abused beyond business rules.",
        "quota_rate_limit": "Usage, rate, quota, and credit limits must be enforced server-side.",
        "account_lifecycle": "Account creation, deactivation, suspension, and invitation workflows must enforce authorization and identity checks.",
        "import_export": "Import/export workflows must validate data integrity, authorization, and tenant boundaries.",
        "notification_webhook": "Webhooks and callbacks must verify signatures, timestamps, replay protection, and allowed destinations.",
    }
    return mapping.get(workflow_type, "Business rules and state transitions must be enforced server-side.")


def manual_steps_for_workflow(workflow_type: str) -> list[str]:
    return [
        "Confirm scope and Authorised Test Data Only.",
        "Document the Expected Business Rule before manual review.",
        "Map allowed and disallowed State Transition Review paths.",
        "Complete the Abuse Case Checklist without executing live state-changing workflows automatically.",
        "Record Expected Behaviour and Observed Behaviour with redacted evidence.",
        "Record retest requirement and recommendation.",
    ]


def business_logic_evidence_checklist(review_plan_id: str) -> dict[str, Any]:
    items = [
        "Authorisation scope confirmed.",
        "Authorised Test Data Only confirmed.",
        "Workflow type recorded.",
        "Expected Business Rule recorded.",
        "Expected Behaviour recorded.",
        "Observed Behaviour recorded.",
        "State Transition Review map completed.",
        "Abuse Case Checklist completed.",
        "No credentials, tokens, cookies, or secrets included.",
        "No real payment, approval, refund, transfer, subscription, or purchase completed.",
        "Audit/logging review noted.",
        "Retest requirement recorded.",
    ]
    return {"checklist_id": f"business_logic_checklist_{uuid4().hex[:12]}", "review_plan_id": review_plan_id, "items": [{"item_id": f"item_{index + 1}", "item": item, "status": "pending", "required": True, "notes": ""} for index, item in enumerate(items)]}


def safety_notes_for_workflow(workflow_type: str) -> list[str]:
    return [
        SAFE_TESTING_STATEMENT,
        "Do not complete checkout/payment flows.",
        "Do not trigger payments, refunds, transfers, subscriptions, or purchases.",
        "Do not approve/reject real requests automatically.",
        "Do not submit state-changing requests automatically.",
        "Do not store raw credentials, cookies, bearer tokens, passwords, or session material.",
    ]


def _expected_business_rule(workflow_type: str) -> str:
    return f"Documented Business Rule Review for {workflow_type.replace('_', ' ')} must define allowed roles, states, inputs, limits, and exceptions."


def _risk_if_failed(workflow_type: str) -> str:
    if workflow_type in {"checkout_payment", "refund_transfer", "subscription_plan", "coupon_discount"}:
        return "Potential financial, pricing, entitlement, or transaction integrity impact if manually confirmed."
    if workflow_type == "approval_rejection":
        return "Potential workflow integrity issue if unauthorised roles can transition approvals when manually confirmed."
    if workflow_type in {"account_lifecycle", "password_reset"}:
        return "Potential identity or account lifecycle control issue if manually confirmed."
    return "Potential business rule or state transition issue if manually confirmed."


def _recommendation(workflow_type: str) -> str:
    return "Enforce Business Rule Review controls server-side and document allowed state transitions, roles, limits, and audit events."


def _linked_replay_plans(url: str, workflow_type: str, replay_plans: list[dict[str, Any]]) -> list[str]:
    normalised = normalise_url_path_ids(url)
    return [str(plan.get("replay_plan_id") or "") for plan in replay_plans if normalise_url_path_ids(str(plan.get("affected_url") or plan.get("normalised_url") or "")) == normalised]


def _linked_access_plans(urls: list[str], access_plans: list[dict[str, Any]]) -> list[str]:
    normalised_urls = {normalise_url_path_ids(str(url)) for url in urls}
    return [str(plan.get("test_plan_id") or "") for plan in access_plans if normalise_url_path_ids(str(plan.get("affected_url") or plan.get("normalised_url") or "")) in normalised_urls]


def _related_owasp(workflow_type: str) -> list[str]:
    return {
        "checkout_payment": ["A01", "A06", "A08"],
        "approval_rejection": ["A01", "A06"],
        "account_lifecycle": ["A01", "A06", "A07"],
        "password_reset": ["A06", "A07"],
        "import_export": ["A01", "A06", "A08"],
        "notification_webhook": ["A06", "A08"],
        "file_upload_processing": ["A05", "A06", "A08"],
    }.get(workflow_type, ["A06"])


def _dominant_retest_status(retests: list[dict[str, Any]]) -> str:
    if not retests:
        return "not_started"
    if any(item.get("retest_status") == "failed" for item in retests):
        return "failed"
    if any(item.get("retest_status") in {"scheduled", "in_progress"} for item in retests):
        return "in_progress"
    if all(item.get("retest_status") == "passed" for item in retests):
        return "passed"
    return str(retests[-1].get("retest_status") or "not_started")


def _target(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    return parsed.netloc or parsed.path or ""


def _resolve_business_logic_path(path: str | Path) -> Path:
    candidate = Path(path)
    resolved = candidate if candidate.is_absolute() else Path.cwd() / candidate
    root = (Path.cwd() / BUSINESS_LOGIC_DIR).resolve()
    resolved = resolved.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise BusinessLogicReviewError("Business Logic Review files must be under data/business_logic.") from exc
    return resolved
