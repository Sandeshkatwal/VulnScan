"""Abuse Case Checklist helpers for Business Logic Review."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from scanner.evidence import redact_nested


GENERIC_ITEMS = [
    "Can workflow steps be skipped?",
    "Can a user repeat a one-time action?",
    "Can a user change price/quantity/discount/client-controlled fields?",
    "Can a lower role perform higher-role actions?",
    "Can a user access another tenant/user workflow?",
    "Can a stale/expired link or token still work?",
    "Can replayed callbacks/events be accepted?",
    "Can import/export include unauthorised data?",
    "Are server-side controls enforced?",
    "Is audit logging present?",
]

SPECIFIC_ITEMS = {
    "checkout_payment": ["price tampering review", "quantity tampering review", "duplicate order/replay review", "payment state transition review", "refund/chargeback workflow review"],
    "approval_rejection": ["lower role approval review", "skipped approval step review", "repeated approval/rejection review", "conflicting state transition review"],
    "coupon_discount": ["stacking rule review", "expired coupon review", "user-specific coupon review", "discount limit review"],
    "quota_rate_limit": ["limit enforcement review", "reset window review", "quota bypass through alternate endpoint review"],
    "notification_webhook": ["signature verification review", "timestamp/replay review", "callback allowlist review", "event source validation review"],
}


def build_abuse_case_checklist(workflow_type: str, review_plan_id: str = "") -> dict[str, Any]:
    items = GENERIC_ITEMS + SPECIFIC_ITEMS.get(workflow_type, [])
    return redact_nested(
        {
            "checklist_id": f"abuse_checklist_{uuid4().hex[:12]}",
            "review_plan_id": review_plan_id,
            "workflow_type": workflow_type,
            "items": [
                {"item_id": f"item_{index + 1}", "item": item, "status": "pending", "required": True, "notes": ""}
                for index, item in enumerate(items)
            ],
            "safety_notes": ["Manual Validation Required.", "Authorised Test Data Only.", "No Automatic Workflow Execution."],
        }
    )
