"""Passive A08 integrity workflow indicator classifiers."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from scanner.evidence import redact_nested


UPLOAD_PATHS = {"upload", "uploads", "avatar", "profile-picture", "media", "document", "documents", "attachment", "attachments", "files", "import"}
UPLOAD_FIELDS = {"file", "upload", "attachment", "document", "avatar", "image", "media"}
IMPORT_EXPORT_PATHS = {"import", "export", "bulk", "sync", "restore", "backup", "download"}
IMPORT_EXPORT_PARAMS = {"format", "type", "file", "source", "destination", "dataset", "import_id", "export_id"}
WEBHOOK_PATHS = {"webhook", "webhooks", "callback", "callbacks", "events", "notifications", "integrations", "connect"}
WEBHOOK_PARAMS = {"callback", "callback_url", "webhook", "webhook_url", "redirect_uri", "return_url", "event", "state", "signature", "sig", "hmac", "timestamp"}
UPDATE_PATHS = {"update", "upgrade", "plugins", "plugin", "extensions", "themes", "modules", "packages", "install", "installer", "marketplace"}
BOUNDARY_PARAMS = {"signature", "sig", "hmac", "checksum", "hash", "digest", "token", "state", "nonce", "payload", "data", "object", "serialized", "redirect_uri", "callback_url"}
DESERIALISATION_PARAMS = {"serialized", "object", "payload", "data", "blob", "json", "xml", "yaml", "pickle", "base64"}


def collect_a08_integrity_evidence(
    endpoint_results: list[dict[str, Any]] | None,
    parameter_results: list[dict[str, Any]] | None,
    forms: list[dict[str, Any]] | None,
    scripts: list[Any] | None,
    stylesheets: list[Any] | None,
    html_snippet: str | None,
    target: str = "",
) -> list[dict[str, Any]]:
    from scanner.sri_analysis import assess_subresource_integrity

    evidence: list[dict[str, Any]] = []
    evidence.extend(assess_upload_workflow_candidates(endpoint_results, forms, parameter_results))
    evidence.extend(assess_import_export_candidates(endpoint_results, parameter_results))
    evidence.extend(assess_webhook_callback_candidates(endpoint_results, parameter_results))
    evidence.extend(assess_update_workflow_candidates(endpoint_results))
    evidence.extend(assess_trusted_data_boundary_candidates(parameter_results, endpoint_results))
    evidence.extend(assess_deserialisation_data_handling_candidates(parameter_results, endpoint_results))
    evidence.extend(assess_subresource_integrity(scripts, stylesheets, html_snippet, target=target, evidence_factory=make_a08_evidence_item))
    return _dedupe_evidence(evidence)


def assess_upload_workflow_candidates(endpoint_results: list[dict[str, Any]] | None, forms: list[dict[str, Any]] | None, parameter_results: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for endpoint in _collect_endpoints(endpoint_results):
        url = endpoint["url"]
        keywords = _path_keywords(url)
        if not (keywords & UPLOAD_PATHS):
            continue
        rule_id = _upload_rule(keywords)
        evidence.append(
            make_a08_evidence_item(
                rule_id=rule_id,
                rule_group="upload_workflow_indicators",
                title="File upload workflow indicator",
                affected_url=url,
                workflow_type="upload",
                integrity_candidate_type="file upload workflow indicator",
                candidate_score=35,
                evidence_strength="weak_indicator",
                confidence="Medium",
                safe_evidence_summary="Upload-related endpoint path observed. No upload was performed and no file payload was generated.",
                manual_test_plan_id="upload_integrity_review",
                recommendation="Manually review file type validation, storage isolation, authorization, and safe processing.",
            )
        )
    for form in forms or []:
        action = str(form.get("action_url") or form.get("action") or form.get("url") or "")
        enctype = str(form.get("enctype") or form.get("encoding") or "").lower()
        fields = _form_fields(form)
        has_file = any(str(field.get("type") or "").lower() == "file" for field in fields)
        names = [str(field.get("name") or "").lower() for field in fields]
        if has_file or "multipart/form-data" in enctype or any(name in UPLOAD_FIELDS for name in names):
            rule_id = "file_upload_endpoint_detected" if has_file else ("multipart_form_detected" if "multipart/form-data" in enctype else "upload_parameter_detected")
            evidence.append(
                make_a08_evidence_item(
                    rule_id=rule_id,
                    rule_group="upload_workflow_indicators",
                    title="Upload form integrity indicator",
                    affected_url=action,
                    affected_parameter=", ".join(sorted(name for name in names if name in UPLOAD_FIELDS)),
                    workflow_type="upload",
                    integrity_candidate_type="file upload workflow indicator",
                    candidate_score=50 if has_file and "multipart/form-data" in enctype else 35,
                    evidence_strength="weak_indicator",
                    confidence="Medium",
                    safe_evidence_summary="Upload-capable form metadata was observed. Forms were not submitted and files were not uploaded.",
                    manual_test_plan_id="upload_integrity_review",
                    recommendation="Manually review upload validation, authorization, storage, and processing controls.",
                    extra={"form_enctype": enctype, "file_input_present": has_file},
                )
            )
    for param in _collect_parameters(endpoint_results, parameter_results):
        if param["name"] in UPLOAD_FIELDS:
            evidence.append(
                make_a08_evidence_item(
                    rule_id="upload_parameter_detected",
                    rule_group="upload_workflow_indicators",
                    title=f"Upload parameter integrity indicator: {param['name']}",
                    affected_url=param["url"],
                    affected_parameter=param["name"],
                    workflow_type="upload",
                    integrity_candidate_type="file upload workflow indicator",
                    candidate_score=25,
                    evidence_strength="informational",
                    confidence="Low",
                    safe_evidence_summary="Upload-related parameter name observed. Parameter values were not retained or modified.",
                    manual_test_plan_id="upload_integrity_review",
                    recommendation="Review whether upload parameters are validated and authorised server-side.",
                )
            )
    return _dedupe_evidence(evidence)


def assess_import_export_candidates(endpoint_results: list[dict[str, Any]] | None, parameter_results: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    params_by_url = _params_by_url(endpoint_results, parameter_results)
    for endpoint in _collect_endpoints(endpoint_results):
        url = endpoint["url"]
        keywords = _path_keywords(url)
        if not (keywords & IMPORT_EXPORT_PATHS or "/report/export" in url.lower() or "/data/import" in url.lower() or "/api/import" in url.lower() or "/api/export" in url.lower()):
            continue
        params = sorted(params_by_url.get(_normalised_url_without_values(url), set()))
        score = score_a08_candidate(url=url, parameter_names=params, workflow_type="import_export")
        evidence.append(
            make_a08_evidence_item(
                rule_id=_import_export_rule(url, keywords),
                rule_group="import_export_integrity_indicators",
                title="Import/export workflow integrity indicator",
                affected_url=url,
                affected_parameter=", ".join(name for name in params if name in IMPORT_EXPORT_PARAMS),
                workflow_type="import_export",
                integrity_candidate_type="import/export workflow indicator",
                candidate_score=score,
                evidence_strength="strong_indicator" if score >= 70 else "weak_indicator",
                confidence="High" if score >= 70 else "Medium",
                safe_evidence_summary="Import/export workflow path observed from supplied metadata. No import/export action was performed.",
                manual_test_plan_id="import_data_validation_review",
                recommendation="Manually review data validation, authorization, tamper protection, and audit logging.",
            )
        )
    return _dedupe_evidence(evidence)


def assess_webhook_callback_candidates(endpoint_results: list[dict[str, Any]] | None, parameter_results: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    params_by_url = _params_by_url(endpoint_results, parameter_results)
    for endpoint in _collect_endpoints(endpoint_results):
        url = endpoint["url"]
        keywords = _path_keywords(url)
        params = sorted(params_by_url.get(_normalised_url_without_values(url), set()))
        if not (keywords & WEBHOOK_PATHS or any(name in WEBHOOK_PARAMS for name in params) or "/oauth/callback" in url.lower()):
            continue
        score = score_a08_candidate(url=url, parameter_names=params, workflow_type="webhook_callback")
        evidence.append(
            make_a08_evidence_item(
                rule_id=_webhook_rule(url, keywords, params),
                rule_group="webhook_callback_indicators",
                title="Webhook/callback integrity indicator",
                affected_url=url,
                affected_parameter=", ".join(name for name in params if name in WEBHOOK_PARAMS),
                workflow_type="webhook_callback",
                integrity_candidate_type="webhook/callback integrity indicator",
                candidate_score=score,
                evidence_strength="strong_indicator" if score >= 70 else "weak_indicator",
                confidence="High" if score >= 70 else "Medium",
                safe_evidence_summary="Webhook/callback/signature/state metadata was observed. VulScan did not trigger webhooks or send callback requests.",
                manual_test_plan_id="webhook_signature_review",
                recommendation="Manually validate signature verification, replay protection, timestamp checks, callback restrictions, and state validation.",
            )
        )
    return _dedupe_evidence(evidence)


def assess_update_workflow_candidates(endpoint_results: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for endpoint in _collect_endpoints(endpoint_results):
        url = endpoint["url"]
        keywords = _path_keywords(url)
        if not (keywords & UPDATE_PATHS):
            continue
        evidence.append(
            make_a08_evidence_item(
                rule_id=_update_rule(keywords),
                rule_group="update_workflow_indicators",
                title="Update/plugin workflow integrity indicator",
                affected_url=url,
                workflow_type="update_workflow",
                integrity_candidate_type="update workflow indicator",
                candidate_score=55,
                evidence_strength="weak_indicator",
                confidence="Medium",
                safe_evidence_summary="Update/plugin/extension workflow path observed. VulScan did not call update, install, or upgrade endpoints.",
                manual_test_plan_id="update_integrity_review",
                recommendation="Manually review package signing, trusted source enforcement, rollback, and audit logging.",
            )
        )
    return _dedupe_evidence(evidence)


def assess_trusted_data_boundary_candidates(parameter_results: list[dict[str, Any]] | None, endpoint_results: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for param in _collect_parameters(endpoint_results, parameter_results):
        name = param["name"]
        if name not in BOUNDARY_PARAMS:
            continue
        rule_id = {
            "signature": "signature_parameter_name_detected",
            "sig": "signature_parameter_name_detected",
            "hmac": "signature_parameter_name_detected",
            "checksum": "checksum_parameter_name_detected",
            "hash": "hash_parameter_name_detected",
            "digest": "hash_parameter_name_detected",
            "state": "state_parameter_detected",
            "callback_url": "callback_url_parameter_detected",
            "redirect_uri": "callback_url_parameter_detected",
        }.get(name, "token_parameter_integrity_review")
        evidence.append(
            make_a08_evidence_item(
                rule_id=rule_id,
                rule_group="trusted_data_boundary_indicators",
                title=f"Trusted-data boundary indicator: {name}",
                affected_url=param["url"],
                affected_parameter=name,
                workflow_type="trusted_data_boundary",
                integrity_candidate_type="trusted-data boundary indicator",
                candidate_score=40 if name in {"signature", "sig", "hmac", "checksum", "hash", "digest", "state", "nonce"} else 30,
                evidence_strength="weak_indicator",
                confidence="Medium" if name in {"signature", "sig", "hmac", "checksum", "hash", "digest"} else "Low",
                safe_evidence_summary="Integrity-related parameter name observed. Values were not stored, modified, decoded, or tested.",
                manual_test_plan_id="webhook_signature_review" if name in WEBHOOK_PARAMS else "deserialisation_safety_review",
                recommendation="Manually review trust-boundary validation and tamper protection.",
            )
        )
    return _dedupe_evidence(evidence)


def assess_deserialisation_data_handling_candidates(parameter_results: list[dict[str, Any]] | None, endpoint_results: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for param in _collect_parameters(endpoint_results, parameter_results):
        name = param["name"]
        if name not in DESERIALISATION_PARAMS:
            continue
        evidence.append(
            make_a08_evidence_item(
                rule_id=_deserialisation_rule(name),
                rule_group="deserialisation_data_handling_candidates",
                title=f"Deserialisation/data handling candidate: {name}",
                affected_url=param["url"],
                affected_parameter=name,
                workflow_type="deserialisation_data_handling",
                integrity_candidate_type="trusted-data boundary indicator",
                candidate_score=45,
                evidence_strength="weak_indicator",
                confidence="Medium",
                safe_evidence_summary="Data-handling parameter name observed. VulScan did not decode, execute, or submit deserialisation payloads.",
                manual_test_plan_id="deserialisation_safety_review",
                recommendation="Manually verify safe parsers and rejection of untrusted serialized data.",
            )
        )
    return _dedupe_evidence(evidence)


def make_a08_evidence_item(
    *,
    rule_id: str,
    rule_group: str,
    title: str,
    affected_url: str = "",
    affected_host: str = "",
    affected_parameter: str = "",
    workflow_type: str = "",
    integrity_candidate_type: str = "integrity indicator",
    evidence_strength: str = "informational",
    confidence: str = "Low",
    candidate_score: int = 0,
    safe_evidence_summary: str = "",
    manual_validation_required: bool = True,
    manual_test_plan_id: str = "",
    recommended_manual_steps: list[str] | None = None,
    recommendation: str = "",
    limitation: str = "",
    source: str = "owasp_a08",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    safe_url = _normalised_url_without_values(affected_url)
    plan = build_a08_manual_validation_plan({"manual_test_plan_id": manual_test_plan_id, "workflow_type": workflow_type})
    item = {
        "evidence_id": "",
        "rule_id": rule_id,
        "rule_group": rule_group,
        "title": title,
        "affected_url": safe_url,
        "affected_host": affected_host or (urlsplit(safe_url).hostname or ""),
        "affected_parameter": affected_parameter,
        "workflow_type": workflow_type,
        "integrity_candidate_type": integrity_candidate_type,
        "evidence_strength": evidence_strength if evidence_strength in {"informational", "weak_indicator", "strong_indicator", "confirmed_finding"} else "informational",
        "candidate_score": max(0, min(100, int(candidate_score))),
        "interest_label": interest_label(candidate_score),
        "confidence": confidence if confidence in {"Low", "Medium", "High"} else "Low",
        "safe_evidence_summary": safe_evidence_summary,
        "manual_validation_required": bool(manual_validation_required),
        "manual_test_plan_id": manual_test_plan_id or plan["plan_id"],
        "recommended_manual_steps": recommended_manual_steps or plan["safe_manual_steps"],
        "recommendation": recommendation or "Review A08 Software or Data Integrity Failures indicator manually.",
        "limitation": limitation or "Candidate requiring manual validation. No upload, form submission, webhook triggering, update call, or control-circumvention testing was performed.",
        "source": source,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if extra:
        item.update(extra)
    item["evidence_template"] = build_a08_evidence_template(item)
    item["duplicate_fingerprint"] = build_a08_candidate_fingerprint(item)
    item["evidence_id"] = _evidence_id(item)
    return redact_nested(item)


def score_a08_candidate(url: str, parameter_names: list[str] | None = None, workflow_type: str = "") -> int:
    lower = url.lower()
    names = {name.lower() for name in parameter_names or []}
    score = 0
    if workflow_type in {"upload", "import_export", "webhook_callback", "update_workflow"}:
        score += 20
    if any(name in names for name in {"file", "payload", "data", "source", "dataset"}):
        score += 20
    if any(name in names for name in {"signature", "sig", "hmac", "timestamp", "state", "callback_url", "redirect_uri"}):
        score += 25
    if any(marker in lower for marker in ("/api/", "/bulk", "/restore", "/backup", "/plugin", "/update", "/webhook", "/callback")):
        score += 20
    if any(marker in lower for marker in ("/import", "/export", "/upload", "/download", "/sync")):
        score += 15
    if any(lower.endswith(ext) for ext in (".css", ".png", ".jpg", ".gif", ".ico", ".svg")):
        score -= 30
    return max(0, min(100, score))


def interest_label(score: int) -> str:
    if score >= 70:
        return "High Interest"
    if score >= 45:
        return "Medium Interest"
    if score >= 20:
        return "Low Interest"
    return "Informational"


def build_a08_manual_validation_plan(evidence_item: dict[str, Any]) -> dict[str, Any]:
    plan_id = str(evidence_item.get("manual_test_plan_id") or "")
    workflow = str(evidence_item.get("workflow_type") or "").lower()
    if not plan_id:
        if "upload" in workflow:
            plan_id = "upload_integrity_review"
        elif "import" in workflow:
            plan_id = "import_data_validation_review"
        elif "webhook" in workflow or "callback" in workflow:
            plan_id = "webhook_signature_review"
        elif "update" in workflow:
            plan_id = "update_integrity_review"
        elif "subresource" in workflow:
            plan_id = "third_party_script_integrity_review"
        else:
            plan_id = "deserialisation_safety_review"
    plans = {
        "upload_integrity_review": ["Verify file type validation.", "Verify storage isolation.", "Verify malware scanning process if applicable.", "Verify authorization on uploaded files.", "Use only safe test files and programme-approved assets."],
        "import_data_validation_review": ["Verify schema validation.", "Verify invalid or tampered data is rejected.", "Verify imported data cannot override unauthorized fields.", "Use only approved test data."],
        "webhook_signature_review": ["Verify signatures/HMAC are required.", "Verify timestamp and replay protection.", "Verify callback URL restrictions.", "Do not trigger third-party systems."],
        "update_integrity_review": ["Verify update packages are signed.", "Verify trusted source enforcement.", "Verify rollback and audit logging."],
        "third_party_script_integrity_review": ["Verify SRI and CSP strategy.", "Review trusted third-party scripts.", "Confirm business need."],
        "deserialisation_safety_review": ["Verify untrusted serialized data is not accepted.", "Verify safe parsers are used.", "Avoid unsafe deserialisation."],
    }
    expected = {
        "upload_integrity_review": "Uploaded content is validated, authorised, isolated, and safely processed.",
        "import_data_validation_review": "Imported data is schema-validated and cannot tamper with unauthorized fields.",
        "webhook_signature_review": "Webhook and callback requests require signature validation, timestamp checks, replay protection, and allowed destinations.",
        "update_integrity_review": "Update/plugin artifacts are signed, trusted, auditable, and rollback-capable.",
        "third_party_script_integrity_review": "Third-party scripts/stylesheets are governed by an intentional SRI/CSP strategy.",
        "deserialisation_safety_review": "Untrusted serialized data is rejected or parsed only with safe parsers.",
    }
    return {
        "plan_id": plan_id,
        "plan_type": plan_id.replace("_", " ").title(),
        "safe_manual_steps": plans.get(plan_id, plans["deserialisation_safety_review"]),
        "expected_secure_behaviour": expected.get(plan_id, expected["deserialisation_safety_review"]),
        "evidence_needed_for_confirmation": "Redacted screenshots, configuration excerpts, or logs from authorised manual validation only.",
        "risk_if_confirmed": "Integrity controls may be missing if manual validation confirms unsafe trust-boundary handling.",
        "safety_note": "Manual validation required. No uploads, form submissions, webhook triggering, update calls, or bypass testing are performed by VulScan.",
    }


def build_a08_evidence_template(evidence_item: dict[str, Any]) -> dict[str, Any]:
    plan = build_a08_manual_validation_plan(evidence_item)
    return {
        "candidate_title": evidence_item.get("title") or "A08 integrity indicator",
        "affected_endpoint": evidence_item.get("affected_url") or "",
        "workflow_type": evidence_item.get("workflow_type") or "",
        "integrity_boundary": evidence_item.get("integrity_candidate_type") or "integrity indicator",
        "why_it_may_matter": evidence_item.get("safe_evidence_summary") or "Candidate requiring manual validation.",
        "safe_manual_validation_steps": plan["safe_manual_steps"],
        "expected_secure_behaviour": plan["expected_secure_behaviour"],
        "evidence_needed_for_confirmation": plan["evidence_needed_for_confirmation"],
        "risk_if_confirmed": plan["risk_if_confirmed"],
        "recommendation": evidence_item.get("recommendation") or "Manually review integrity protections.",
    }


def build_a08_candidate_fingerprint(evidence_item: dict[str, Any]) -> dict[str, Any]:
    from scanner.finding_fingerprint import build_finding_fingerprint

    item = {
        "affected_url": evidence_item.get("affected_url") or "",
        "affected_host": evidence_item.get("affected_host") or "",
        "parameter_names": [evidence_item.get("affected_parameter")] if evidence_item.get("affected_parameter") else [],
        "issue_type": evidence_item.get("integrity_candidate_type") or evidence_item.get("workflow_type") or "integrity_indicator",
        "endpoint_category": evidence_item.get("workflow_type") or "",
        "owasp_category": "A08:2025",
        "owasp_id": "A08:2025",
        "source": evidence_item.get("source") or "owasp_a08",
        "title": evidence_item.get("title") or "A08 integrity indicator",
    }
    fingerprint = build_finding_fingerprint(item, item_type="a08_candidate")
    return {
        **fingerprint,
        "normalised_url": fingerprint.get("data", {}).get("path") or evidence_item.get("affected_url") or "",
        "workflow_type": evidence_item.get("workflow_type") or "",
        "integrity_candidate_type": evidence_item.get("integrity_candidate_type") or "",
        "owasp_category": "A08:2025",
    }


def build_a08_summary(target: str, evidence: list[dict[str, Any]]) -> dict[str, Any]:
    interest_counts = Counter(str(item.get("interest_label") or "Informational") for item in evidence)
    groups = Counter(str(item.get("rule_group") or "") for item in evidence)
    confidence_order = {"Low": 1, "Medium": 2, "High": 3}
    highest = "Low"
    for item in evidence:
        confidence = str(item.get("confidence") or "Low")
        if confidence_order.get(confidence, 0) > confidence_order.get(highest, 0):
            highest = confidence
    return {
        "enabled": True,
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_evidence_items": len(evidence),
        "high_interest_count": interest_counts.get("High Interest", 0),
        "medium_interest_count": interest_counts.get("Medium Interest", 0),
        "low_interest_count": interest_counts.get("Low Interest", 0),
        "informational_count": interest_counts.get("Informational", 0),
        "manual_validation_required_count": sum(1 for item in evidence if item.get("manual_validation_required")),
        "upload_candidate_count": groups.get("upload_workflow_indicators", 0),
        "import_export_candidate_count": groups.get("import_export_integrity_indicators", 0),
        "webhook_callback_candidate_count": groups.get("webhook_callback_indicators", 0),
        "update_workflow_candidate_count": groups.get("update_workflow_indicators", 0),
        "sri_indicator_count": groups.get("subresource_integrity_indicators", 0),
        "trusted_data_boundary_candidate_count": groups.get("trusted_data_boundary_indicators", 0),
        "deserialisation_candidate_count": groups.get("deserialisation_data_handling_candidates", 0),
        "rule_group_counts": dict(groups),
        "highest_confidence": highest,
        "top_candidates": sorted(evidence, key=lambda row: int(row.get("candidate_score") or 0), reverse=True)[:10],
        "recommendations": [
            "Review integrity candidates manually and validate trust-boundary protections.",
            "Review upload/import validation, authorization, tamper protection, and audit logging.",
            "Review webhook signatures, timestamp validation, replay protection, and callback restrictions.",
            "Review update/plugin package signing and trusted source enforcement.",
            "Review SRI/CSP strategy for external scripts and stylesheets.",
        ],
        "limitations": [
            "A08 checks are candidate-based and require manual validation.",
            "No uploads, form submissions, webhook triggering, update calls, deserialisation payloads, or control-circumvention testing are performed.",
            "Missing SRI is context-dependent and is not marked as a confirmed finding.",
        ],
    }


def _collect_endpoints(endpoint_results: list[dict[str, Any]] | None) -> list[dict[str, str]]:
    return [{"url": str(item.get("normalised_url") or item.get("url") or item.get("path") or item.get("affected_url") or "")} for item in endpoint_results or [] if str(item.get("normalised_url") or item.get("url") or item.get("path") or item.get("affected_url") or "")]


def _collect_parameters(endpoint_results: list[dict[str, Any]] | None, parameter_results: list[dict[str, Any]] | None) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for item in parameter_results or []:
        name = str(item.get("parameter_name") or item.get("name") or item.get("parameter") or "").strip().lower()
        url = _normalised_url_without_values(str(item.get("url") or item.get("normalised_url") or item.get("path") or ""))
        if name:
            rows.append({"name": name, "url": url})
    for endpoint in endpoint_results or []:
        url = str(endpoint.get("normalised_url") or endpoint.get("url") or endpoint.get("path") or "")
        for name, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            if name:
                rows.append({"name": name.lower(), "url": _normalised_url_without_values(url)})
        for param in endpoint.get("parameters") or []:
            if isinstance(param, dict):
                name = str(param.get("name") or param.get("parameter_name") or "").strip().lower()
                if name:
                    rows.append({"name": name, "url": _normalised_url_without_values(url)})
    return rows


def _params_by_url(endpoint_results: list[dict[str, Any]] | None, parameter_results: list[dict[str, Any]] | None) -> dict[str, set[str]]:
    grouped: dict[str, set[str]] = {}
    for param in _collect_parameters(endpoint_results, parameter_results):
        grouped.setdefault(param["url"], set()).add(param["name"])
    return grouped


def _form_fields(form: dict[str, Any]) -> list[dict[str, Any]]:
    fields = form.get("fields") or form.get("inputs") or form.get("form_fields") or []
    return [field for field in fields if isinstance(field, dict)]


def _path_keywords(url: str) -> set[str]:
    path = urlsplit(url).path.lower()
    return {part for part in re.split(r"[^a-z0-9_-]+", path) if part}


def _normalised_url_without_values(url: str) -> str:
    if not url:
        return ""
    parsed = urlsplit(url)
    names = [name for name, _value in parse_qsl(parsed.query, keep_blank_values=True)]
    query = "&".join(sorted(set(names)))
    return parsed._replace(query=query, fragment="").geturl()


def _upload_rule(keywords: set[str]) -> str:
    if "avatar" in keywords or "profile-picture" in keywords:
        return "avatar_upload_endpoint_detected"
    if "document" in keywords or "documents" in keywords:
        return "document_upload_endpoint_detected"
    if "media" in keywords:
        return "media_upload_endpoint_detected"
    if "import" in keywords:
        return "import_upload_form_detected"
    return "file_upload_endpoint_detected"


def _import_export_rule(url: str, keywords: set[str]) -> str:
    lower = url.lower()
    if "restore" in keywords or "backup" in keywords:
        return "backup_restore_endpoint_detected"
    if "sync" in keywords:
        return "data_sync_endpoint_detected"
    if "bulk" in keywords:
        return "bulk_import_endpoint_detected"
    if "import" in keywords:
        return "import_endpoint_detected"
    if "export" in keywords or "download" in keywords or "/report/export" in lower:
        return "export_endpoint_detected"
    return "import_endpoint_detected"


def _webhook_rule(url: str, keywords: set[str], params: list[str]) -> str:
    if any(name in {"callback", "callback_url", "redirect_uri", "return_url"} for name in params):
        return "third_party_callback_url_parameter_detected"
    if "webhook" in keywords or "webhooks" in keywords:
        return "webhook_endpoint_detected"
    if "callback" in keywords or "callbacks" in keywords or "/oauth/callback" in url.lower():
        return "callback_endpoint_detected"
    if "notifications" in keywords:
        return "notification_endpoint_detected"
    if "events" in keywords:
        return "event_endpoint_detected"
    return "integration_endpoint_detected"


def _update_rule(keywords: set[str]) -> str:
    for key, rule in {"update": "update_endpoint_detected", "upgrade": "upgrade_endpoint_detected", "plugin": "plugin_endpoint_detected", "plugins": "plugin_endpoint_detected", "extensions": "extension_endpoint_detected", "themes": "theme_endpoint_detected", "modules": "module_endpoint_detected", "packages": "package_endpoint_detected"}.items():
        if key in keywords:
            return rule
    return "update_endpoint_detected"


def _deserialisation_rule(name: str) -> str:
    if name in {"serialized"}:
        return "serialized_parameter_name_detected"
    if name == "object":
        return "object_parameter_name_detected"
    if name == "payload":
        return "payload_parameter_name_detected"
    if name in {"json"}:
        return "json_blob_parameter_detected"
    if name == "xml":
        return "xml_data_parameter_detected"
    return "data_parameter_name_detected"


def _dedupe_evidence(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str]] = set()
    result: list[dict[str, Any]] = []
    for item in evidence:
        key = (str(item.get("rule_id") or ""), str(item.get("affected_url") or ""), str(item.get("affected_parameter") or ""), str(item.get("workflow_type") or ""))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _evidence_id(item: dict[str, Any]) -> str:
    stable = "|".join(str(item.get(key) or "") for key in ("rule_id", "affected_url", "affected_parameter", "workflow_type", "integrity_candidate_type"))
    return "a08_" + hashlib.sha256(stable.encode("utf-8")).hexdigest()[:16]
