"""Export Safety Check helpers for Evidence Vault records."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.evidence_redaction import validate_redaction


EXPORTS_DIR = Path("reports") / "evidence_vault" / "exports"


def can_export_evidence(evidence_item: dict[str, Any]) -> dict[str, Any]:
    text = json.dumps(evidence_item, sort_keys=True, default=str)
    redaction = validate_redaction(text)
    reasons: list[str] = []
    allowed = True
    if evidence_item.get("redaction_status") in {"failed_secret_check", "blocked_from_export", "pending_redaction"}:
        allowed = False
        reasons.append("Redaction status blocks export.")
    if evidence_item.get("secret_detection_status") == "failed":
        allowed = False
        reasons.append("Secret Detection failed.")
    if not evidence_item.get("safe_summary"):
        allowed = False
        reasons.append("Safe summary is required before export.")
    if not redaction["passed"]:
        allowed = False
        reasons.append("Secret-like patterns remain in the Evidence Item.")
    return {"export_allowed": allowed, "reasons": reasons, "redaction_check": redaction, "status": "allowed" if allowed else "blocked"}


def evidence_export_safety_check(evidence_item: dict[str, Any]) -> dict[str, Any]:
    return can_export_evidence(evidence_item)


def build_evidence_export_bundle(evidence_items: list[dict[str, Any]]) -> dict[str, Any]:
    safe_items = []
    blocked = []
    for item in evidence_items:
        check = can_export_evidence(item)
        if check["export_allowed"]:
            safe_items.append(item)
        else:
            blocked.append({"evidence_id": item.get("evidence_id"), "reasons": check["reasons"]})
    return {
        "export_created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "evidence_items": safe_items,
        "blocked_evidence": blocked,
        "export_safety_status": "passed" if not blocked else "blocked_items_omitted",
        "safe_testing_statement": "Evidence Vault exports include Redacted Evidence only.",
    }


def export_evidence_summary_json(evidence_items: list[dict[str, Any]], exports_dir: Path = EXPORTS_DIR) -> Path:
    exports_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    path = exports_dir / f"evidence_export_{stamp}.json"
    path.write_text(json.dumps(build_evidence_export_bundle(evidence_items), indent=2), encoding="utf-8")
    return path


def export_evidence_summary_markdown(evidence_items: list[dict[str, Any]], exports_dir: Path = EXPORTS_DIR) -> Path:
    exports_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    bundle = build_evidence_export_bundle(evidence_items)
    lines = ["# Evidence Vault Export", "", "Redacted Evidence only.", ""]
    for item in bundle["evidence_items"]:
        lines.extend([f"## {item.get('evidence_id')} - {item.get('title')}", "", str(item.get("safe_summary") or ""), ""])
    if bundle["blocked_evidence"]:
        lines.append("## Blocked Evidence")
        for item in bundle["blocked_evidence"]:
            lines.append(f"- {item.get('evidence_id')}: {'; '.join(item.get('reasons') or [])}")
    path = exports_dir / f"evidence_export_{stamp}.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
