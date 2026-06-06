"""Subresource Integrity evidence helpers for A08.

The checks are passive: they inspect supplied script/style metadata and limited
HTML snippets only. They do not fetch resources or calculate remote hashes.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit


def assess_subresource_integrity(
    scripts: list[Any] | None,
    stylesheets: list[Any] | None,
    html_snippet: str | None = None,
    *,
    target: str = "",
    evidence_factory,
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    script_rows = _resource_rows(scripts, "script") + _html_resources(html_snippet or "", "script")
    style_rows = _resource_rows(stylesheets, "stylesheet") + _html_resources(html_snippet or "", "stylesheet")
    target_host = urlsplit(target).hostname or ""

    for row in _dedupe_resources(script_rows + style_rows):
        url = str(row.get("url") or "")
        if not url:
            continue
        kind = str(row.get("kind") or "script")
        host = urlsplit(url).hostname or ""
        external = _is_external(url, target_host)
        integrity = str(row.get("integrity") or "").strip()
        crossorigin = str(row.get("crossorigin") or "").strip()
        if integrity:
            evidence.append(
                evidence_factory(
                    rule_id="sri_attribute_present" if kind == "script" else "sri_attribute_present",
                    rule_group="subresource_integrity_indicators",
                    title=f"Subresource Integrity evidence: {kind}",
                    affected_url=url,
                    affected_host=host,
                    workflow_type="subresource_integrity",
                    integrity_candidate_type="Subresource Integrity evidence",
                    evidence_strength="informational",
                    confidence="Medium",
                    candidate_score=20,
                    safe_evidence_summary="Integrity attribute was observed on an external resource. VulScan did not fetch the resource or calculate hashes.",
                    manual_test_plan_id="third_party_script_integrity_review",
                    recommendation="Review SRI and CSP strategy for third-party resources.",
                    extra={"resource_type": kind, "integrity_present": True, "crossorigin_present": bool(crossorigin), "third_party_domain": host},
                )
            )
            if external and not crossorigin:
                evidence.append(
                    evidence_factory(
                        rule_id="sri_missing_crossorigin_context",
                        rule_group="subresource_integrity_indicators",
                        title=f"SRI crossorigin context indicator: {kind}",
                        affected_url=url,
                        affected_host=host,
                        workflow_type="subresource_integrity",
                        integrity_candidate_type="Subresource Integrity evidence",
                        evidence_strength="informational",
                        confidence="Low",
                        candidate_score=15,
                        safe_evidence_summary="Integrity attribute is present, but crossorigin context was not observed. Manual validation required.",
                        manual_test_plan_id="third_party_script_integrity_review",
                        recommendation="Review whether crossorigin handling matches the application SRI strategy.",
                        extra={"resource_type": kind, "integrity_present": True, "crossorigin_present": False, "third_party_domain": host},
                    )
                )
            continue
        if external:
            rule_id = "external_script_without_sri" if kind == "script" else "external_stylesheet_without_sri"
            if kind == "script" and host:
                rule_id = "third_party_script_without_sri"
            evidence.append(
                evidence_factory(
                    rule_id=rule_id,
                    rule_group="subresource_integrity_indicators",
                    title=f"External {kind} without SRI indicator",
                    affected_url=url,
                    affected_host=host,
                    workflow_type="subresource_integrity",
                    integrity_candidate_type="Subresource Integrity evidence",
                    evidence_strength="weak_indicator",
                    confidence="Medium" if host else "Low",
                    candidate_score=45 if host else 25,
                    safe_evidence_summary="External resource reference did not include an integrity attribute in supplied metadata. Missing SRI is context-dependent and not a confirmed finding.",
                    manual_test_plan_id="third_party_script_integrity_review",
                    recommendation="Review CSP/SRI strategy and trusted third-party resource requirements.",
                    extra={"resource_type": kind, "integrity_present": False, "third_party_domain": host},
                )
            )
    inline_count = len(re.findall(r"<script(?![^>]+src=)[^>]*>", html_snippet or "", re.I))
    if inline_count:
        evidence.append(
            evidence_factory(
                rule_id="inline_script_integrity_review",
                rule_group="subresource_integrity_indicators",
                title="Inline script integrity review indicator",
                workflow_type="subresource_integrity",
                integrity_candidate_type="Subresource Integrity evidence",
                evidence_strength="informational",
                confidence="Low",
                candidate_score=10,
                safe_evidence_summary=f"{inline_count} inline script tag(s) were observed in a limited HTML snippet. Full HTML was not stored.",
                manual_test_plan_id="third_party_script_integrity_review",
                recommendation="Review CSP strategy and whether inline scripts are required.",
                extra={"inline_script_count": inline_count},
            )
        )
    return _dedupe_evidence(evidence)


def _resource_rows(resources: list[Any] | None, kind: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in resources or []:
        if isinstance(item, dict):
            rows.append({"url": item.get("src") or item.get("href") or item.get("url") or "", "integrity": item.get("integrity") or "", "crossorigin": item.get("crossorigin") or "", "kind": item.get("kind") or kind})
        else:
            rows.append({"url": str(item or ""), "integrity": "", "crossorigin": "", "kind": kind})
    return rows


def _html_resources(html: str, kind: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if kind == "script":
        for tag in re.findall(r"<script[^>]+src=[\"'][^\"']+[\"'][^>]*>", html, re.I):
            rows.append(_tag_resource(tag, "src", kind))
    else:
        for tag in re.findall(r"<link[^>]+href=[\"'][^\"']+[\"'][^>]*>", html, re.I):
            if "stylesheet" in tag.lower():
                rows.append(_tag_resource(tag, "href", kind))
    return rows


def _tag_resource(tag: str, attr: str, kind: str) -> dict[str, Any]:
    def value(name: str) -> str:
        match = re.search(rf"{name}=[\"']([^\"']+)[\"']", tag, re.I)
        return match.group(1) if match else ""
    return {"url": value(attr), "integrity": value("integrity"), "crossorigin": value("crossorigin"), "kind": kind}


def _is_external(url: str, target_host: str) -> bool:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if not host:
        return url.startswith("//")
    return bool(target_host and host != target_host) or not target_host


def _dedupe_resources(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    result: list[dict[str, Any]] = []
    for row in rows:
        key = (str(row.get("kind") or ""), str(row.get("url") or ""))
        if key in seen or not key[1]:
            continue
        seen.add(key)
        result.append(row)
    return result


def _dedupe_evidence(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for row in rows:
        key = "|".join(str(row.get(key) or "") for key in ("rule_id", "affected_url", "workflow_type"))
        if key in seen:
            continue
        seen.add(key)
        result.append(row)
    return result
