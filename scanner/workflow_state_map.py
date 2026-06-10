"""State Transition Review map helpers for Business Logic Review."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import uuid4

from scanner.evidence import redact_nested


@dataclass
class WorkflowStateTransition:
    transition_id: str
    from_state: str
    to_state: str
    action: str
    allowed_roles: list[str] = field(default_factory=list)
    disallowed_roles: list[str] = field(default_factory=list)
    endpoint: str = ""
    expected_control: str = ""
    manual_validation_status: str = "planned"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def suggest_state_transitions(workflow_type: str) -> list[dict[str, str]]:
    mapping = {
        "approval_rejection": [
            {"from_state": "pending", "to_state": "approved", "action": "approve"},
            {"from_state": "pending", "to_state": "rejected", "action": "reject"},
        ],
        "checkout_payment": [
            {"from_state": "cart", "to_state": "checkout", "action": "start_checkout"},
            {"from_state": "checkout", "to_state": "paid", "action": "confirm_payment"},
            {"from_state": "unpaid", "to_state": "paid", "action": "payment_settled"},
        ],
        "subscription_plan": [
            {"from_state": "trial", "to_state": "subscribed", "action": "subscribe"},
            {"from_state": "subscribed", "to_state": "cancelled", "action": "cancel"},
        ],
        "account_lifecycle": [
            {"from_state": "invited", "to_state": "accepted", "action": "accept_invite"},
            {"from_state": "active", "to_state": "suspended", "action": "suspend"},
        ],
        "password_reset": [
            {"from_state": "reset_requested", "to_state": "verified", "action": "verify_reset"},
            {"from_state": "verified", "to_state": "completed", "action": "complete_reset"},
        ],
    }
    return mapping.get(workflow_type, [{"from_state": "draft", "to_state": "submitted", "action": "submit"}])


def build_state_transition_map(workflow_type: str, endpoints: list[str] | list[dict[str, Any]] | None = None, roles: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    endpoint_values = [str(item.get("url") or item.get("endpoint") or item.get("affected_url") or "") if isinstance(item, dict) else str(item) for item in endpoints or []]
    allowed_roles = [str(role.get("role_label") or role.get("role_id") or "") for role in roles or [] if isinstance(role, dict)]
    transitions = []
    for index, suggested in enumerate(suggest_state_transitions(workflow_type)):
        endpoint = endpoint_values[min(index, len(endpoint_values) - 1)] if endpoint_values else ""
        transitions.append(
            WorkflowStateTransition(
                transition_id=f"transition_{uuid4().hex[:12]}",
                from_state=suggested["from_state"],
                to_state=suggested["to_state"],
                action=suggested["action"],
                allowed_roles=allowed_roles,
                disallowed_roles=[],
                endpoint=endpoint,
                expected_control=_expected_control(workflow_type),
                notes="Manual Validation Required. No Automatic Workflow Execution.",
            ).to_dict()
        )
    return redact_nested({"state_map_id": f"state_map_{uuid4().hex[:12]}", "workflow_type": workflow_type, "transitions": transitions})


def _expected_control(workflow_type: str) -> str:
    if workflow_type == "approval_rejection":
        return "Only authorised roles can perform this State Transition Review action."
    if workflow_type in {"checkout_payment", "subscription_plan"}:
        return "Server-side business rules must control price, order, payment, and state transitions."
    if workflow_type == "password_reset":
        return "Tokens, expiry, identity, and one-time use controls must be validated server-side."
    return "Server-side Business Rule Review controls must enforce the allowed transition."
