"""Risk Acceptance Notes for composed assessment reports."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from scanner.finding_models import now_iso


def build_risk_acceptance_note(**kwargs: Any) -> dict[str, Any]:
    return {
        "acceptance_id": kwargs.get("acceptance_id") or f"acceptance-{uuid4().hex[:8]}",
        "finding_id": kwargs.get("finding_id") or "",
        "accepted_by": kwargs.get("accepted_by") or "",
        "accepted_at": kwargs.get("accepted_at") or now_iso(),
        "acceptance_reason": kwargs.get("acceptance_reason") or "",
        "expiry_date": kwargs.get("expiry_date") or "",
        "compensating_controls": list(kwargs.get("compensating_controls") or []),
        "review_date": kwargs.get("review_date") or "",
        "notes": kwargs.get("notes") or "",
    }


def build_risk_acceptance_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    accepted = [finding for finding in findings if finding.get("status") == "risk_accepted" or finding.get("risk_acceptance")]
    return {
        "accepted_risk_count": len(accepted),
        "accepted_findings": [
            {
                "finding_id": finding.get("finding_id"),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "risk_acceptance": finding.get("risk_acceptance"),
            }
            for finding in accepted
        ],
        "statement": "Risk acceptance is tracked separately from remediation and does not indicate that an issue was fixed.",
    }

