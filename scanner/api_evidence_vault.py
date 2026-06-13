"""API handlers for Evidence Vault and Redaction Quality Controls."""

from __future__ import annotations

from typing import Any

from scanner.evidence_export_safety import can_export_evidence, export_evidence_summary_json, export_evidence_summary_markdown
from scanner.evidence_quality import calculate_evidence_quality_score
from scanner.evidence_redaction import redact_secrets, validate_redaction
from scanner.evidence_timeline import build_evidence_timeline
from scanner.evidence_vault import (
    EvidenceVaultError,
    create_evidence_item,
    link_evidence_to_access_test,
    link_evidence_to_business_logic_plan,
    link_evidence_to_finding,
    link_evidence_to_owasp_category,
    link_evidence_to_replay_plan,
    link_evidence_to_report,
    list_evidence_items,
    load_evidence_item,
    save_evidence_item,
)
from scanner.pagination import PaginationError, build_paginated_response
from scanner.response_limits import compact_record, truncate_text


EVIDENCE_SUMMARY_FIELDS = (
    "evidence_id",
    "title",
    "evidence_type",
    "source_module",
    "related_url",
    "related_host",
    "related_owasp_categories",
    "confidence",
    "evidence_strength",
    "redaction_status",
    "secret_detection_status",
    "evidence_quality_score",
    "evidence_quality_label",
    "validation_status",
    "created_at",
    "updated_at",
)


def api_list_evidence(
    *,
    page: int = 1,
    page_size: int = 25,
    sort_by: str | None = None,
    sort_direction: str = "asc",
    owasp_category: str | None = None,
    source_module: str | None = None,
    evidence_strength: str | None = None,
    validation_status: str | None = None,
    search: str | None = None,
    summary_only: bool = True,
) -> dict[str, Any]:
    items = list_evidence_items()
    records = [_evidence_summary(item) for item in items] if summary_only else items
    paginated = build_paginated_response(
        records,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_direction=sort_direction,
        filters={
            "owasp_category": owasp_category,
            "source_module": source_module,
            "evidence_strength": evidence_strength,
            "validation_status": validation_status,
            "search": search,
        },
    )
    return {
        "evidence_items": paginated["items"],
        "count": len(paginated["items"]),
        "total": paginated["total"],
        "paginated_response": paginated,
        "summary_only": summary_only,
    }


def api_get_evidence(evidence_id: str) -> dict[str, Any]:
    item = load_evidence_item(evidence_id)
    if item is None:
        raise EvidenceVaultError(f"Evidence Item not found: {evidence_id}")
    return {"evidence_vault_item": item}


def api_create_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    item = create_evidence_item(**payload)
    save_evidence_item(item)
    return {"evidence_vault_item": item}


def api_redact_check(text: str) -> dict[str, Any]:
    redacted = redact_secrets(text)
    return {"redacted_text": redacted, "redaction_check": validate_redaction(redacted)}


def api_quality(evidence_id: str) -> dict[str, Any]:
    item = load_evidence_item(evidence_id)
    if item is None:
        raise EvidenceVaultError(f"Evidence Item not found: {evidence_id}")
    return {"evidence_id": evidence_id, "evidence_quality": calculate_evidence_quality_score(item)}


def api_timeline(evidence_id: str) -> dict[str, Any]:
    return build_evidence_timeline(evidence_id, list_evidence_items())


def api_link(evidence_id: str, link_type: str, linked_id: str) -> dict[str, Any]:
    if link_type == "finding":
        item = link_evidence_to_finding(evidence_id, linked_id)
    elif link_type == "owasp":
        item = link_evidence_to_owasp_category(evidence_id, linked_id)
    elif link_type == "access_test":
        item = link_evidence_to_access_test(evidence_id, linked_id)
    elif link_type == "replay_plan":
        item = link_evidence_to_replay_plan(evidence_id, linked_id)
    elif link_type == "business_logic_plan":
        item = link_evidence_to_business_logic_plan(evidence_id, linked_id)
    elif link_type == "report":
        item = link_evidence_to_report(evidence_id, linked_id)
    else:
        raise EvidenceVaultError("Unsupported evidence link type.")
    return {"evidence_vault_item": item}


def api_export(evidence_ids: list[str], markdown: bool = False, json_export: bool = True) -> dict[str, Any]:
    items = []
    blocked = []
    for evidence_id in evidence_ids:
        item = load_evidence_item(evidence_id, raw=True)
        if item is None:
            raise EvidenceVaultError(f"Evidence Item not found: {evidence_id}")
        check = can_export_evidence(item)
        if check["export_allowed"]:
            items.append(item)
        else:
            blocked.append({"evidence_id": evidence_id, "reasons": check["reasons"]})
    if blocked:
        return {"export_allowed": False, "blocked_evidence": blocked}
    paths: dict[str, str] = {}
    if json_export:
        paths["json"] = str(export_evidence_summary_json(items))
    if markdown:
        paths["markdown"] = str(export_evidence_summary_markdown(items))
    return {"export_allowed": True, "export_paths": paths, "evidence_count": len(items)}


def _evidence_summary(item: dict[str, Any]) -> dict[str, Any]:
    summary = compact_record(item, EVIDENCE_SUMMARY_FIELDS)
    summary["safe_summary"] = truncate_text(item.get("safe_summary"))
    summary["detail_url"] = f"/evidence/{item.get('evidence_id')}"
    return summary
