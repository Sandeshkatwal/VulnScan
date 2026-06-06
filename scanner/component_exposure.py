"""Passive A03 component exposure and supply chain metadata classifiers."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from scanner.cve_feed import match_cve_feed, normalise_cve_item
from scanner.evidence import redact_nested
from scanner.service_fingerprint import normalise_cpe, normalise_product, normalise_vendor


LIBRARY_NAMES = {
    "jquery",
    "bootstrap",
    "angular",
    "react",
    "vue",
    "lodash",
    "moment",
    "axios",
    "backbone",
    "underscore",
    "chart.js",
    "d3",
    "three",
    "next",
    "nuxt",
    "webpack",
}
DEPENDENCY_FILES = {
    "package.json": "package_json_exposed",
    "package-lock.json": "package_lock_exposed",
    "yarn.lock": "yarn_lock_exposed",
    "pnpm-lock.yaml": "pnpm_lock_exposed",
    "composer.json": "composer_json_exposed",
    "composer.lock": "composer_lock_exposed",
    "requirements.txt": "requirements_txt_exposed",
    "pyproject.toml": "pyproject_toml_exposed",
    "go.mod": "go_mod_exposed",
    "cargo.toml": "cargo_toml_exposed",
    "gemfile": "gemfile_exposed",
    "gemfile.lock": "gemfile_exposed",
}
BUILD_ARTIFACTS = {"manifest.json", "asset-manifest.json", "mix-manifest.json", "webpack-stats.json", "vite-manifest.json"}


def assess_javascript_library_hints(scripts: list[Any] | None, html_snippet: str | None = None) -> list[dict[str, Any]]:
    evidence = []
    script_urls = _script_urls(scripts)
    script_urls.extend(_scripts_from_html(html_snippet or ""))
    for script in sorted({item for item in script_urls if item}):
        name = _library_name(script)
        if not name:
            continue
        version = _extract_version(script)
        rule_id = f"{name.replace('.', '').replace('-', '_')}_detected"
        if name == "express":
            rule_id = "express_client_hint"
        evidence.append(
            make_a03_evidence_item(
                rule_id=rule_id if rule_id in _known_js_rule_ids() else "library_version_exposed",
                rule_group="javascript_library_hints",
                title=f"JavaScript library hint: {name}",
                affected_url=_safe_url(script),
                component_name=name,
                component_version=version,
                component_type="javascript_library",
                package_ecosystem="npm",
                evidence_strength="weak_indicator" if version else "informational",
                confidence="Medium" if version else "Low",
                safe_evidence_summary=f"JavaScript library hint observed for {name}{' version ' + version if version else ''}. No external script was fetched.",
                recommendation="Review component version and patch status. Use local SBOM and vulnerability intelligence for validation.",
                manual_validation_required=True,
                source="owasp_a03",
            )
        )
    return _dedupe(evidence)


def assess_component_version_exposure(headers: dict[str, Any] | None, html_snippet: str | None, endpoint_results: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    evidence = []
    headers = headers or {}
    for key, value in headers.items():
        lower = str(key).lower()
        if lower not in {"server", "x-powered-by", "x-generator", "x-aspnet-version", "x-runtime"}:
            continue
        component, version = _component_from_header(str(value))
        evidence.append(
            make_a03_evidence_item(
                rule_id="server_version_exposed" if lower == "server" else "framework_version_exposed",
                rule_group="component_version_exposure",
                title=f"Component version exposure indicator: {key}",
                component_name=component or str(key),
                component_version=version,
                component_type="server_or_framework",
                evidence_strength="weak_indicator" if version else "informational",
                confidence="Medium" if version else "Low",
                safe_evidence_summary=f"Header {key} exposed component metadata. Version exposure alone does not prove vulnerability.",
                recommendation="Review whether component banners are intentional and verify patch status.",
                manual_validation_required=True,
                source="owasp_a03",
            )
        )
    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html_snippet or "", re.I)
    if generator:
        component, version = _component_from_header(generator.group(1))
        evidence.append(
            make_a03_evidence_item(
                rule_id="generator_meta_tag_detected",
                rule_group="component_version_exposure",
                title="Generator meta tag component exposure indicator",
                component_name=component,
                component_version=version,
                component_type="cms_or_framework",
                evidence_strength="weak_indicator" if version else "informational",
                confidence="Medium" if version else "Low",
                safe_evidence_summary="Generator meta tag exposed component metadata. Full HTML was not stored.",
                recommendation="Review CMS/framework version and patch status.",
                manual_validation_required=True,
                source="owasp_a03",
            )
        )
    for endpoint in endpoint_results or []:
        url = str(endpoint.get("url") or endpoint.get("normalised_url") or endpoint.get("path") or "")
        if not url:
            continue
        if urlsplit(url).path.lower().endswith(".map"):
            evidence.append(_source_map_evidence(url))
        version = _extract_version(url)
        name = _library_name(url)
        if version and name:
            evidence.append(
                make_a03_evidence_item(
                    rule_id="asset_path_version_detected",
                    rule_group="component_version_exposure",
                    title=f"Asset path version exposure indicator: {name}",
                    affected_url=_safe_url(url),
                    component_name=name,
                    component_version=version,
                    component_type="asset_component",
                    evidence_strength="weak_indicator",
                    confidence="Medium",
                    safe_evidence_summary="Asset URL exposed a component/version hint. No external asset was fetched.",
                    recommendation="Review exposed asset versions and patch status.",
                    manual_validation_required=True,
                    source="owasp_a03",
                )
            )
    return _dedupe(evidence)


def assess_dependency_metadata_exposure(endpoint_results: list[dict[str, Any]] | None = None, urls: list[str] | None = None) -> list[dict[str, Any]]:
    evidence = []
    candidates = list(urls or [])
    candidates.extend(str(item.get("url") or item.get("normalised_url") or item.get("path") or "") for item in endpoint_results or [])
    for url in sorted({item for item in candidates if item}):
        filename = _dependency_filename(url)
        if not filename:
            continue
        evidence.append(
            make_a03_evidence_item(
                rule_id=DEPENDENCY_FILES[filename],
                rule_group="dependency_metadata_exposure",
                title=f"Dependency metadata exposure indicator: {filename}",
                affected_url=_safe_url(url),
                component_name=filename,
                component_type="dependency_metadata",
                evidence_strength="strong_indicator",
                confidence="High",
                safe_evidence_summary=f"Discovered URL references dependency metadata file {filename}. VulScan did not brute-force dependency paths.",
                recommendation="Avoid exposing dependency metadata publicly unless intentionally published.",
                manual_validation_required=True,
                source="owasp_a03",
                extra={"metadata_filename": filename},
            )
        )
    return _dedupe(evidence)


def assess_build_artifact_indicators(endpoint_results: list[dict[str, Any]] | None, scripts: list[Any] | None = None) -> list[dict[str, Any]]:
    evidence = []
    urls = [str(item.get("url") or item.get("normalised_url") or item.get("path") or "") for item in endpoint_results or []]
    urls.extend(_script_urls(scripts))
    for url in sorted({item for item in urls if item}):
        path = urlsplit(url).path.lower()
        filename = path.rsplit("/", 1)[-1]
        if path.endswith(".map"):
            evidence.append(_source_map_evidence(url))
        elif filename in BUILD_ARTIFACTS:
            evidence.append(
                make_a03_evidence_item(
                    rule_id="build_metadata_exposed",
                    rule_group="supply_chain_process_manual_review",
                    title=f"Build metadata exposure indicator: {filename}",
                    affected_url=_safe_url(url),
                    component_name=filename,
                    component_type="build_artifact",
                    evidence_strength="weak_indicator",
                    confidence="Medium",
                    safe_evidence_summary="Build artifact URL was observed from supplied/discovered metadata. Content was not fetched or stored.",
                    recommendation="Review whether build metadata is intended to be public.",
                    manual_validation_required=True,
                    source="owasp_a03",
                )
            )
    return _dedupe(evidence)


def assess_third_party_script_indicators(scripts: list[Any] | None, target: str = "") -> list[dict[str, Any]]:
    evidence = []
    target_host = urlsplit(target).hostname or ""
    for script in sorted({item for item in _script_urls(scripts) if item}):
        parsed = urlsplit(script)
        host = parsed.hostname or ""
        if not host or (target_host and host.endswith(target_host)):
            continue
        evidence.append(
            make_a03_evidence_item(
                rule_id="third_party_script_manual_review",
                rule_group="supply_chain_process_manual_review",
                title=f"Third-party script manual review indicator: {host}",
                affected_url=_safe_url(script),
                affected_host=host,
                component_name=host,
                component_type="third_party_script",
                evidence_strength="informational",
                confidence="Low",
                safe_evidence_summary="Third-party script reference observed. No external fetch or malware checking was performed.",
                recommendation="Review third-party script trust, SRI, CSP, and vendor ownership manually.",
                manual_validation_required=True,
                source="owasp_a03",
            )
        )
    return _dedupe(evidence)


def assess_sbom_components(components: list[dict[str, Any]], vuln_intel: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    evidence = []
    matches = enrich_components_with_vuln_intel(components, vuln_intel or {})
    matches_by_component = {(match.get("component_name"), match.get("component_version")): match for match in matches}
    for component in components or []:
        name = str(component.get("name") or "")
        version = str(component.get("version") or "")
        match = matches_by_component.get((name, version), {})
        cve_ids = [str(match.get("cve"))] if match.get("cve") else []
        rule_id = "component_with_cve_match" if cve_ids else ("component_without_version" if not version else f"{str(component.get('sbom_format') or 'cyclonedx').lower()}_component_detected")
        if component.get("purl") and not cve_ids:
            rule_id = "component_purl_present"
        evidence.append(
            make_a03_evidence_item(
                rule_id=rule_id,
                rule_group="sbom_analysis",
                title=f"SBOM component evidence: {name}",
                component_name=name,
                component_version=version,
                component_type=str(component.get("type") or "library"),
                package_ecosystem=_ecosystem(component.get("purl")),
                cpe=str(component.get("cpe") or match.get("cpe") or ""),
                purl=str(component.get("purl") or ""),
                cve_ids=cve_ids,
                cvss_score=match.get("cvss_score"),
                epss_score=match.get("epss_score"),
                exploit_metadata={"available": bool(match.get("exploit_available"))} if match else {},
                evidence_strength="strong_indicator" if cve_ids else ("informational" if not version else "weak_indicator"),
                confidence="High" if cve_ids and version else ("Low" if not version else "Medium"),
                safe_evidence_summary=f"Local SBOM component {name}{' ' + version if version else ''} was analysed. No package registry was queried.",
                recommendation="Maintain SBOM, verify component identity/version, and update vulnerable components where validated.",
                manual_validation_required=not bool(cve_ids and version),
                source="owasp_a03",
            )
        )
    return _dedupe(evidence)


def enrich_components_with_vuln_intel(components: list[dict[str, Any]], vuln_intel: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    feed = (vuln_intel or {}).get("cve_feed") or {}
    if not feed.get("items"):
        return []
    feed = {**feed, "items": [normalise_cve_item(item) for item in feed.get("items", [])]}
    inventory = []
    for component in components or []:
        inventory.append(
            {
                "name": component.get("name"),
                "product": normalise_product(component.get("name")),
                "vendor": normalise_vendor(component.get("supplier")),
                "version": component.get("version"),
                "cpe": normalise_cpe(component.get("cpe")),
                "cpe_prefix": normalise_cpe(component.get("cpe")),
                "service_name": str(component.get("name") or "").lower(),
            }
        )
    matches = match_cve_feed(inventory, feed)
    enriched = []
    for match in matches:
        item = match.get("matched_inventory_item") or match.get("inventory_item") or {}
        enriched.append(
            {
                "component_name": item.get("name") or item.get("product") or item.get("service_name"),
                "component_version": item.get("version") or "",
                "cpe": item.get("cpe") or match.get("cpe") or "",
                "cve": match.get("cve"),
                "cvss_score": match.get("cvss_score"),
                "epss_score": match.get("epss_score"),
                "exploit_available": bool(match.get("exploit_available")),
                "match_status": match.get("match_status"),
                "identity_method": match.get("identity_method"),
            }
        )
    return enriched


def make_a03_evidence_item(
    *,
    rule_id: str,
    rule_group: str,
    title: str,
    affected_url: str = "",
    affected_host: str = "",
    component_name: str = "",
    component_version: str = "",
    component_type: str = "",
    package_ecosystem: str = "",
    cpe: str = "",
    purl: str = "",
    cve_ids: list[str] | None = None,
    cvss_score: Any = None,
    epss_score: Any = None,
    exploit_metadata: dict[str, Any] | None = None,
    evidence_strength: str = "informational",
    confidence: str = "Low",
    safe_evidence_summary: str = "",
    recommendation: str = "",
    manual_validation_required: bool = True,
    source: str = "owasp_a03",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    item = {
        "evidence_id": "",
        "rule_id": rule_id,
        "rule_group": rule_group,
        "title": title,
        "affected_url": affected_url,
        "affected_host": affected_host or (urlsplit(affected_url).hostname or ""),
        "component_name": component_name,
        "component_version": component_version,
        "component_type": component_type,
        "package_ecosystem": package_ecosystem,
        "cpe": normalise_cpe(cpe) or "",
        "purl": purl,
        "cve_ids": cve_ids or [],
        "cvss_score": cvss_score,
        "epss_score": epss_score,
        "exploit_metadata": exploit_metadata or {},
        "evidence_strength": evidence_strength if evidence_strength in {"informational", "weak_indicator", "strong_indicator", "confirmed_finding"} else "informational",
        "confidence": confidence if confidence in {"Low", "Medium", "High"} else "Low",
        "safe_evidence_summary": safe_evidence_summary,
        "recommendation": recommendation,
        "manual_validation_required": bool(manual_validation_required),
        "source": source,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "limitation": "A03 Software Supply Chain evidence is metadata-based. No dependency confusion testing, external registry fetching, or exploit code use was performed.",
    }
    if extra:
        item.update(extra)
    item["evidence_id"] = _evidence_id(item)
    return redact_nested(item)


def build_a03_summary(target: str, evidence: list[dict[str, Any]]) -> dict[str, Any]:
    groups = Counter(str(item.get("rule_group") or "") for item in evidence)
    strengths = Counter(str(item.get("evidence_strength") or "") for item in evidence)
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
        "strong_indicators_count": strengths.get("strong_indicator", 0),
        "weak_indicators_count": strengths.get("weak_indicator", 0),
        "informational_count": strengths.get("informational", 0),
        "manual_validation_required_count": sum(1 for item in evidence if item.get("manual_validation_required")),
        "component_hint_count": groups.get("javascript_library_hints", 0),
        "version_exposure_count": groups.get("component_version_exposure", 0),
        "dependency_metadata_exposure_count": groups.get("dependency_metadata_exposure", 0),
        "sbom_component_count": groups.get("sbom_analysis", 0),
        "cve_match_count": sum(len(item.get("cve_ids") or []) for item in evidence),
        "cpe_match_count": sum(1 for item in evidence if item.get("cpe")),
        "source_map_indicator_count": sum(1 for item in evidence if item.get("rule_id") in {"source_map_detected", "source_map_exposed"}),
        "third_party_script_count": sum(1 for item in evidence if item.get("rule_id") == "third_party_script_manual_review"),
        "rule_group_counts": dict(groups),
        "highest_confidence": highest,
        "top_risks": [item.get("title") for item in evidence if item.get("evidence_strength") == "strong_indicator"][:5],
        "recommendations": [
            "Maintain an SBOM and review component inventory regularly.",
            "Update vulnerable components after validating component identity and version.",
            "Avoid exposing dependency metadata publicly unless intentionally published.",
            "Review source map and build artifact exposure in production.",
            "Review third-party scripts, SRI, and CSP policy.",
        ],
        "limitations": [
            "A03 checks use supplied/discovered metadata and local intelligence only.",
            "No dependency confusion testing, package registry fetching, malicious package testing, or exploit code download is performed.",
            "CVE/CPE matching may be approximate and requires manual validation.",
        ],
    }


def _script_urls(scripts: list[Any] | None) -> list[str]:
    urls = []
    for item in scripts or []:
        if isinstance(item, dict):
            urls.append(str(item.get("src") or item.get("url") or item.get("href") or ""))
        else:
            urls.append(str(item or ""))
    return urls


def _scripts_from_html(html: str) -> list[str]:
    return re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html or "", re.I)[:50]


def _library_name(value: str) -> str:
    lower = value.lower()
    aliases = {"chart": "chart.js", "chart.js": "chart.js", "d3": "d3", "three": "three"}
    for name in LIBRARY_NAMES:
        if re.search(rf"(^|[/@._-]){re.escape(name)}([/@._-]|$)", lower):
            return aliases.get(name, name)
    if "express" in lower:
        return "express"
    return ""


def _extract_version(value: str) -> str:
    patterns = [
        r"[-@/]v?(\d+\.\d+\.\d+(?:[-._][A-Za-z0-9]+)?)",
        r"[?&]v=(\d+\.\d+(?:\.\d+)?)",
        r"/(\d+\.\d+\.\d+)/",
    ]
    for pattern in patterns:
        match = re.search(pattern, value)
        if match:
            return re.sub(r"(?i)(?:\.min|\.prod|\.production|\.dev|\.development)$", "", match.group(1).replace("_", "-"))
    return ""


def _component_from_header(value: str) -> tuple[str, str]:
    safe = value.split(";", 1)[0].strip()
    match = re.search(r"([A-Za-z][A-Za-z0-9_. -]+?)[/\s](\d+\.\d+(?:\.\d+)?)", safe)
    if match:
        return match.group(1).strip(), match.group(2)
    return safe[:80], ""


def _dependency_filename(url: str) -> str:
    path = urlsplit(url).path.lower()
    filename = path.rsplit("/", 1)[-1]
    return filename if filename in DEPENDENCY_FILES else ""


def _source_map_evidence(url: str) -> dict[str, Any]:
    return make_a03_evidence_item(
        rule_id="source_map_detected",
        rule_group="component_version_exposure",
        title="Source map exposure indicator",
        affected_url=_safe_url(url),
        component_name=urlsplit(url).path.rsplit("/", 1)[-1],
        component_type="source_map",
        evidence_strength="strong_indicator",
        confidence="Medium",
        safe_evidence_summary="Source map URL was observed from supplied/discovered metadata. Source map content was not fetched, parsed, or stored.",
        recommendation="Review whether source maps should be publicly accessible in this environment.",
        manual_validation_required=True,
        source="owasp_a03",
    )


def _ecosystem(purl: Any) -> str:
    value = str(purl or "")
    if value.startswith("pkg:") and "/" in value:
        return value[4:].split("/", 1)[0]
    return ""


def _known_js_rule_ids() -> set[str]:
    return {
        "jquery_detected",
        "bootstrap_detected",
        "angular_detected",
        "react_detected",
        "vue_detected",
        "lodash_detected",
        "moment_detected",
        "axios_detected",
        "express_client_hint",
    }


def _safe_url(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    if not parsed.query:
        return str(url or "")
    return parsed._replace(query="&".join(sorted({part.split("=", 1)[0] for part in parsed.query.split("&") if part}))).geturl()


def _dedupe(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key = {}
    for item in evidence:
        key = (item.get("rule_id"), item.get("affected_url"), item.get("component_name"), item.get("component_version"), tuple(item.get("cve_ids") or []))
        by_key[key] = item
    return list(by_key.values())


def _evidence_id(item: dict[str, Any]) -> str:
    stable = json.dumps(
        {
            "rule_id": item.get("rule_id"),
            "url": item.get("affected_url"),
            "component": item.get("component_name"),
            "version": item.get("component_version"),
            "cves": item.get("cve_ids"),
        },
        sort_keys=True,
    )
    return "a03_" + hashlib.sha256(stable.encode("utf-8")).hexdigest()[:16]
