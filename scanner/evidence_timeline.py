"""Chain-of-custody style timeline helpers for Evidence Vault records."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def add_evidence_timeline_event(
    evidence_item: dict[str, Any],
    event_type: str,
    description: str,
    *,
    actor: str = "system",
    source_module: str = "evidence_vault",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    event = {
        "event_id": f"timeline_{uuid4().hex[:12]}",
        "evidence_id": evidence_item.get("evidence_id") or "",
        "event_type": event_type,
        "timestamp": now_iso(),
        "actor": actor,
        "description": description,
        "source_module": source_module,
        "redaction_status": evidence_item.get("redaction_status") or "pending_redaction",
        "metadata": metadata or {},
    }
    evidence_item.setdefault("timeline_events", []).append(event)
    evidence_item["updated_at"] = event["timestamp"]
    return event


def build_evidence_timeline(evidence_id: str, evidence_items: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    items = evidence_items or []
    for item in items:
        if item.get("evidence_id") == evidence_id:
            return {"evidence_id": evidence_id, "timeline_events": item.get("timeline_events") or []}
    return {"evidence_id": evidence_id, "timeline_events": []}


def summarise_evidence_timeline(evidence_item: dict[str, Any]) -> dict[str, Any]:
    events = evidence_item.get("timeline_events") or []
    return {
        "evidence_id": evidence_item.get("evidence_id"),
        "events_count": len(events),
        "first_event": events[0] if events else None,
        "latest_event": events[-1] if events else None,
        "timeline_label": "Chain-of-Custody Style Timeline",
    }
