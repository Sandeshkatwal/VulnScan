"""Evidence Vault storage, linking, imports, and report summaries."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scanner.evidence_export_safety import can_export_evidence
from scanner.evidence_models import build_evidence_item
from scanner.evidence_quality import calculate_evidence_quality_score
from scanner.evidence_redaction import redact_mapping_values, redact_secrets, validate_redaction
from scanner.evidence_timeline import add_evidence_timeline_event


DATA_DIR = Path("data") / "evidence_vault"
REPORTS_DIR = Path("reports") / "evidence_vault"
ATTACHMENTS_DIR = REPORTS_DIR / "attachments"
EXPORTS_DIR = REPORTS_DIR / "exports"


class EvidenceVaultError(ValueError):
    pass


def ensure_evidence_vault_dirs() -> None:
    for path in (DATA_DIR, REPORTS_DIR, ATTACHMENTS_DIR, EXPORTS_DIR):
        path.mkdir(parents=True, exist_ok=True)


def evidence_path(evidence_id: str) -> Path:
    safe_id = "".join(ch for ch in evidence_id if ch.isalnum() or ch in {"-", "_"}) or "evidence"
    return DATA_DIR / f"{safe_id}.json"


def redact_evidence_item(evidence_item: dict[str, Any]) -> dict[str, Any]:
    item = redact_mapping_values(dict(evidence_item))
    item["attachment_metadata"] = _safe_attachment_metadata(item.get("attachment_metadata") or [])
    for field in ("safe_summary", "redacted_request_summary", "redacted_response_summary", "safe_observed_value", "notes"):
        item[field] = redact_secrets(str(item.get(field) or ""))
    check = validate_redaction(json.dumps(item, sort_keys=True, default=str))
    item["secret_detection_status"] = str(check["secret_detection_status"])
    item["redaction_checks"] = [check]
    item["redaction_status"] = "redacted" if check["passed"] else "failed_secret_check"
    quality = calculate_evidence_quality_score(item)
    item["evidence_quality_score"] = quality["score"]
    item["evidence_quality_label"] = quality["label"]
    if not any(event.get("event_type") == "redacted" for event in item.get("timeline_events") or [] if isinstance(event, dict)):
        add_evidence_timeline_event(item, "redacted", "Redaction Quality Controls applied.", source_module="evidence_vault")
    return item


def _safe_attachment_metadata(attachments: list[dict[str, Any]] | Any) -> list[dict[str, Any]]:
    safe: list[dict[str, Any]] = []
    if not isinstance(attachments, list):
        return safe
    allowed_root = (Path("reports") / "evidence_vault" / "attachments").as_posix()
    for attachment in attachments:
        if not isinstance(attachment, dict):
            continue
        item = redact_mapping_values(dict(attachment))
        storage_path = str(item.get("storage_path") or "")
        if storage_path:
            normalised = Path(storage_path).as_posix()
            if ".." in Path(storage_path).parts or not normalised.startswith(allowed_root):
                item.pop("storage_path", None)
                item["redaction_status"] = "blocked_from_export"
                item["notes"] = "Attachment storage_path was removed because it is outside reports/evidence_vault/attachments."
        safe.append(item)
    return safe


def create_evidence_item(**kwargs: Any) -> dict[str, Any]:
    item = build_evidence_item(**kwargs)
    add_evidence_timeline_event(item, "created", "Evidence Item created.", source_module=item.get("source_module") or "evidence_vault")
    return redact_evidence_item(item)


def save_evidence_item(evidence_item: dict[str, Any]) -> Path:
    ensure_evidence_vault_dirs()
    item = redact_evidence_item(evidence_item)
    path = evidence_path(str(item["evidence_id"]))
    path.write_text(json.dumps(item, indent=2), encoding="utf-8")
    return path


def load_evidence_item(evidence_id: str, *, raw: bool = False) -> dict[str, Any] | None:
    ensure_evidence_vault_dirs()
    path = evidence_path(evidence_id)
    if not path.exists():
        for candidate in DATA_DIR.glob("*.json"):
            try:
                payload = json.loads(candidate.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and "evidence_vault_item" in payload:
                payload = payload["evidence_vault_item"]
            if isinstance(payload, dict) and payload.get("evidence_id") == evidence_id:
                return payload if raw else redact_evidence_item(payload)
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and "evidence_vault_item" in payload:
        payload = payload["evidence_vault_item"]
    return payload if raw else redact_evidence_item(payload)


def list_evidence_items() -> list[dict[str, Any]]:
    ensure_evidence_vault_dirs()
    items: list[dict[str, Any]] = []
    for path in sorted(DATA_DIR.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and "evidence_vault_item" in payload:
            payload = payload["evidence_vault_item"]
        if isinstance(payload, dict) and payload.get("evidence_id") and (payload.get("evidence_type") or payload.get("safe_summary")):
            items.append(redact_evidence_item(payload))
    return items


def evidence_vault_summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(items)
    scores = [int(item.get("evidence_quality_score") or 0) for item in items]
    return {
        "enabled": True,
        "total_evidence": total,
        "passed_redaction": sum(1 for item in items if item.get("redaction_status") in {"redacted", "not_required"}),
        "pending_redaction": sum(1 for item in items if item.get("redaction_status") == "pending_redaction"),
        "failed_secret_checks": sum(1 for item in items if item.get("secret_detection_status") == "failed" or item.get("redaction_status") == "failed_secret_check"),
        "blocked_from_export": sum(1 for item in items if not can_export_evidence(item)["export_allowed"]),
        "average_evidence_quality_score": round(sum(scores) / total, 2) if total else 0,
    }


def link_evidence(evidence_id: str, field: str, linked_id: str, event_type: str) -> dict[str, Any]:
    item = load_evidence_item(evidence_id)
    if item is None:
        raise EvidenceVaultError(f"Evidence Item not found: {evidence_id}")
    links = item.setdefault(field, [])
    if linked_id not in links:
        links.append(linked_id)
        add_evidence_timeline_event(item, event_type, f"Evidence linked to {linked_id}.", metadata={"linked_id": linked_id})
    save_evidence_item(item)
    return item


def link_evidence_to_finding(evidence_id: str, finding_id: str) -> dict[str, Any]:
    return link_evidence(evidence_id, "linked_finding_ids", finding_id, "linked_to_finding")


def link_evidence_to_owasp_category(evidence_id: str, owasp_id: str) -> dict[str, Any]:
    item = load_evidence_item(evidence_id)
    if item is None:
        raise EvidenceVaultError(f"Evidence Item not found: {evidence_id}")
    categories = item.setdefault("related_owasp_categories", [])
    if owasp_id not in categories:
        categories.append(owasp_id)
        add_evidence_timeline_event(item, "linked_to_report", f"Evidence linked to OWASP category {owasp_id}.")
    save_evidence_item(item)
    return item


def link_evidence_to_access_test(evidence_id: str, test_plan_id: str) -> dict[str, Any]:
    return link_evidence(evidence_id, "linked_test_plan_ids", test_plan_id, "linked_to_test_plan")


def link_evidence_to_replay_plan(evidence_id: str, replay_plan_id: str) -> dict[str, Any]:
    return link_evidence(evidence_id, "linked_replay_plan_ids", replay_plan_id, "linked_to_test_plan")


def link_evidence_to_business_logic_plan(evidence_id: str, review_plan_id: str) -> dict[str, Any]:
    return link_evidence(evidence_id, "linked_business_logic_plan_ids", review_plan_id, "linked_to_test_plan")


def link_evidence_to_report(evidence_id: str, report_id: str) -> dict[str, Any]:
    return link_evidence(evidence_id, "linked_submission_ids", report_id, "linked_to_report")


def build_evidence_from_owasp_item(owasp_evidence_item: dict[str, Any]) -> dict[str, Any]:
    return create_evidence_item(title=owasp_evidence_item.get("title") or "OWASP Evidence Item", evidence_type="owasp_indicator", source_module=owasp_evidence_item.get("source") or "owasp_assessment", related_url=owasp_evidence_item.get("affected_url") or owasp_evidence_item.get("url") or "", related_owasp_categories=[owasp_evidence_item.get("category") or owasp_evidence_item.get("owasp_category") or ""], confidence=owasp_evidence_item.get("confidence") or "medium", evidence_strength=owasp_evidence_item.get("evidence_strength") or "weak_indicator", safe_summary=owasp_evidence_item.get("evidence_summary") or owasp_evidence_item.get("observed_signal") or "")


def build_evidence_from_authenticated_crawl_result(crawl_result: dict[str, Any]) -> dict[str, Any]:
    return create_evidence_item(title=f"Authenticated crawl result: {crawl_result.get('url') or crawl_result.get('normalised_url') or 'endpoint'}", evidence_type="authenticated_crawl_result", source_module="authenticated_crawler", related_url=crawl_result.get("url") or "", confidence="medium", evidence_strength="informational", safe_summary=f"Authenticated Crawl observed status {crawl_result.get('status_code', 'unknown')} and category {crawl_result.get('endpoint_category', 'unknown')}.", redacted_response_summary=crawl_result.get("redacted_evidence_summary") or crawl_result.get("page_title") or "")


def build_evidence_from_access_test_observation(observation: dict[str, Any]) -> dict[str, Any]:
    strength = "manually_verified_issue" if observation.get("observed_access_result") == "unexpectedly_allowed" else "manually_verified_secure" if observation.get("observed_access_result") == "denied_as_expected" else "strong_indicator"
    return create_evidence_item(title="Access Control Manual Test Observation", evidence_type="access_control_test_observation", source_module="access_control_test_planner", linked_test_plan_ids=[observation.get("test_plan_id") or ""], evidence_strength=strength, safe_summary=observation.get("evidence_summary") or observation.get("observed_message_summary") or "", safe_observed_value=observation.get("observed_access_result") or "")


def build_evidence_from_replay_observation(observation: dict[str, Any]) -> dict[str, Any]:
    strength = "manually_verified_issue" if observation.get("observed_access_result") in {"unexpectedly_allowed", "reflected_with_context_risk"} else "strong_indicator"
    return create_evidence_item(title="Parameter Replay Observation", evidence_type="parameter_replay_observation", source_module="parameter_replay_planner", linked_replay_plan_ids=[observation.get("replay_plan_id") or ""], evidence_strength=strength, safe_summary=observation.get("evidence_summary") or observation.get("observed_message_summary") or "", safe_observed_value=observation.get("observed_access_result") or "")


def build_evidence_from_business_logic_observation(observation: dict[str, Any]) -> dict[str, Any]:
    strength = "manually_verified_issue" if observation.get("observed_result") in {"unexpected_success", "control_missing"} else "strong_indicator"
    return create_evidence_item(title="Business Logic Review Observation", evidence_type="business_logic_observation", source_module="business_logic_review", linked_business_logic_plan_ids=[observation.get("review_plan_id") or ""], evidence_strength=strength, safe_summary=observation.get("evidence_summary") or observation.get("observed_message_summary") or "", safe_observed_value=observation.get("observed_result") or "")


def build_evidence_from_vuln_intel_match(vuln_intel_item: dict[str, Any]) -> dict[str, Any]:
    return create_evidence_item(title=vuln_intel_item.get("title") or vuln_intel_item.get("cve") or "Vulnerability Intelligence Evidence", evidence_type="vulnerability_intelligence", source_module="vulnerability_intelligence", related_host=vuln_intel_item.get("host") or "", confidence=vuln_intel_item.get("confidence") or "medium", evidence_strength="strong_indicator", safe_summary=vuln_intel_item.get("summary") or vuln_intel_item.get("evidence") or "")
