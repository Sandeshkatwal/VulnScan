"""Evidence Checklist helpers for A01 Manual Validation Plans."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import uuid4

from scanner.evidence import redact_nested
from scanner.role_profiles import validate_no_credential_fields


CHECKLIST_STATUSES = {"pending", "completed", "not_applicable", "blocked"}


class AccessControlEvidenceChecklistError(ValueError):
    """Raised when an A01 evidence checklist is invalid."""


@dataclass
class EvidenceChecklistItem:
    item_id: str
    item: str
    status: str = "pending"
    required: bool = True
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class A01EvidenceChecklist:
    checklist_id: str
    test_plan_id: str
    items: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


DEFAULT_CHECKLIST_ITEMS = [
    "Authorisation scope confirmed.",
    "Test account label recorded.",
    "Role label recorded.",
    "Endpoint recorded.",
    "Expected permission recorded.",
    "Expected secure behaviour recorded.",
    "Observed behaviour recorded.",
    "Status code recorded if safe.",
    "Redacted screenshot attached or noted.",
    "Redacted response summary captured.",
    "No secrets included.",
    "No real third-party data included.",
    "Retest requirement recorded.",
    "Recommendation recorded.",
]


def build_evidence_checklist(test_plan_id: str, items: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Build a default or supplied checklist for an A01 Manual Validation Plan."""
    validate_no_credential_fields({"test_plan_id": test_plan_id, "items": items or []})
    checklist_items = [_normalise_item(item) for item in (items or _default_items())]
    checklist = A01EvidenceChecklist(
        checklist_id=f"checklist_{uuid4().hex[:12]}",
        test_plan_id=str(test_plan_id),
        items=checklist_items,
    )
    return redact_nested(checklist.to_dict())


def evidence_checklist_summary(checklists: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [item for checklist in checklists or [] for item in checklist.get("items", []) or []]
    return {
        "checklist_count": len(checklists or []),
        "items_count": len(rows),
        "completed_count": sum(1 for item in rows if item.get("status") == "completed"),
        "pending_count": sum(1 for item in rows if item.get("status") == "pending"),
        "blocked_count": sum(1 for item in rows if item.get("status") == "blocked"),
        "required_pending_count": sum(1 for item in rows if item.get("required") and item.get("status") == "pending"),
    }


def _default_items() -> list[dict[str, Any]]:
    return [{"item": item, "status": "pending", "required": True, "notes": ""} for item in DEFAULT_CHECKLIST_ITEMS]


def _normalise_item(payload: dict[str, Any]) -> dict[str, Any]:
    validate_no_credential_fields(payload)
    status = str(payload.get("status") or "pending")
    if status not in CHECKLIST_STATUSES:
        raise AccessControlEvidenceChecklistError(f"Unsupported checklist status: {status}")
    return EvidenceChecklistItem(
        item_id=str(payload.get("item_id") or f"item_{uuid4().hex[:8]}"),
        item=str(payload.get("item") or ""),
        status=status,
        required=bool(payload.get("required", True)),
        notes=str(payload.get("notes") or ""),
    ).to_dict()
