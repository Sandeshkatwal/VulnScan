"""A03 Software Supply Chain and Component Exposure checks.

Version 20.7 is passive and evidence-based. It does not perform dependency
confusion testing, package registry fetching, exploit validation, or CI/CD
attack simulation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scanner.component_exposure import (
    assess_build_artifact_indicators,
    assess_component_version_exposure,
    assess_dependency_metadata_exposure,
    assess_javascript_library_hints,
    assess_sbom_components,
    assess_third_party_script_indicators,
    build_a03_summary,
    make_a03_evidence_item,
)
from scanner.evidence import redact_nested
from scanner.finding import create_finding, finding_to_dict
from scanner.sbom_import import load_sbom, parse_sbom


A03_RULES_PATH = Path("data") / "owasp" / "a03" / "a03_rules.json"
A03_REPORTS_DIR = Path("reports") / "owasp" / "a03"
SBOM_DATA_DIR = Path("data") / "sbom"

LIMITATIONS = [
    "A03 Software Supply Chain Failures checks are evidence-based and require manual validation.",
    "No dependency confusion testing, malicious package testing, package takeover simulation, CI/CD attack simulation, or exploit validation is performed.",
    "Only discovered endpoints, supplied URLs, observed headers, script references, local SBOM files, and local vulnerability-intelligence data are analysed.",
    "No external package registry fetching, external script fetching, or exploit code download is performed in this version.",
    "Version exposure and component hints do not prove vulnerability without strong component/version and vulnerability-intelligence evidence.",
]


class A03RulesError(ValueError):
    """Raised when A03 rules are unavailable or invalid."""


def load_a03_rules(path: str | Path = A03_RULES_PATH) -> dict[str, Any]:
    rules_path = Path(path)
    try:
        payload = json.loads(rules_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise A03RulesError(f"A03 rules file was not found: {rules_path}") from exc
    except json.JSONDecodeError as exc:
        raise A03RulesError(f"A03 rules file is not valid JSON: {rules_path}") from exc
    if payload.get("owasp_id") != "A03:2025":
        raise A03RulesError("A03 rules file must describe A03:2025.")
    if not isinstance(payload.get("rule_groups"), dict):
        raise A03RulesError("A03 rules file must include rule_groups.")
    return payload


def ensure_a03_dirs() -> None:
    A03_RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    A03_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    SBOM_DATA_DIR.mkdir(parents=True, exist_ok=True)


def assess_a03_supply_chain(
    *,
    target: str = "",
    headers: dict[str, Any] | list[dict[str, Any]] | None = None,
    html_snippet: str = "",
    scripts: list[str | dict[str, Any]] | None = None,
    endpoint_results: list[dict[str, Any]] | None = None,
    urls: list[str] | None = None,
    sbom_components: list[dict[str, Any]] | None = None,
    vuln_intel: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assess passive A03 component and software supply chain indicators."""
    ensure_a03_dirs()
    load_a03_rules()
    endpoint_rows = endpoint_results or []
    script_rows = _collect_scripts(scripts, endpoint_rows)
    url_rows = _collect_urls(urls, endpoint_rows, script_rows)
    header_map = _normalise_headers(headers)

    evidence: list[dict[str, Any]] = []
    evidence.extend(assess_javascript_library_hints(script_rows, html_snippet=html_snippet))
    evidence.extend(assess_component_version_exposure(header_map, html_snippet, endpoint_rows))
    evidence.extend(assess_dependency_metadata_exposure(endpoint_rows, url_rows))
    evidence.extend(assess_build_artifact_indicators(endpoint_rows, script_rows))
    evidence.extend(assess_third_party_script_indicators(script_rows, target=target))
    evidence.extend(assess_sbom_components(sbom_components or [], vuln_intel=vuln_intel or {}))
    evidence.extend(_build_explicit_cve_enrichment(sbom_components or [], vuln_intel or {}))
    evidence = _dedupe_evidence(evidence)

    summary = build_a03_summary(target=target or _first_target(endpoint_rows, url_rows), evidence=evidence)
    summary["limitations"] = LIMITATIONS + [item for item in summary.get("limitations", []) if item not in LIMITATIONS]
    findings = build_a03_findings(summary, evidence)
    return redact_nested({"a03_supply_chain_summary": summary, "a03_supply_chain_evidence": evidence, "findings": findings})


def attach_a03_supply_chain(
    scan_result: dict[str, Any],
    *,
    sbom_components: list[dict[str, Any]] | None = None,
    vuln_intel: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = assess_a03_supply_chain(
        target=str(scan_result.get("target") or scan_result.get("url") or scan_result.get("host") or ""),
        headers=_headers_from_scan_result(scan_result),
        html_snippet=_html_snippet_from_scan_result(scan_result),
        scripts=_scripts_from_scan_result(scan_result),
        endpoint_results=scan_result.get("endpoint_results") or _endpoints_from_scan_result(scan_result),
        urls=_urls_from_scan_result(scan_result),
        sbom_components=sbom_components or _components_from_software_inventory(scan_result),
        vuln_intel=vuln_intel or {},
    )
    findings = list(payload.get("findings", []))
    payload_without_findings = dict(payload)
    payload_without_findings.pop("findings", None)
    scan_result.update(payload_without_findings)
    scan_result.setdefault("findings", [])
    scan_result["findings"].extend(findings)
    return scan_result


def analyse_sbom_file(
    sbom_file: str | Path,
    *,
    target: str = "sbom-analysis",
    vuln_intel: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data = load_sbom(sbom_file)
    components = parse_sbom(data)
    payload = assess_a03_supply_chain(target=target, sbom_components=components, vuln_intel=vuln_intel or {})
    payload["sbom_components"] = components
    return payload


def build_a03_findings(summary: dict[str, Any], evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    target = str(summary.get("target") or "owasp-a03")
    findings = [
        finding_to_dict(
            create_finding(
                title="A03 Software Supply Chain Assessment Completed",
                severity="Informational",
                category="OWASP A03 Software Supply Chain Failures",
                affected_host=target,
                evidence=f"VulScan evaluated available component hints, version exposure, dependency metadata, SBOM, and vulnerability intelligence evidence. {summary.get('total_evidence_items', 0)} software supply chain evidence item(s) were identified.",
                recommendation="Review component inventory, update vulnerable dependencies, and maintain SBOM/vulnerability monitoring.",
                source="owasp_a03",
                confidence=str(summary.get("highest_confidence") or "Low"),
                impact="Software supply chain evidence is available for review and prioritisation.",
                verification="Review a03_supply_chain_summary and a03_supply_chain_evidence.",
                limitation="A03 checks are evidence-based and do not perform package registry analysis or exploit validation.",
            )
        )
    ]
    grouped = [
        (
            {"javascript_library_hints", "component_version_exposure"},
            "Component Version Exposure Indicator",
            "Component or version information was exposed.",
            "Review component version and patch status.",
            "Version exposure alone does not prove vulnerability.",
        ),
        (
            {"dependency_metadata_exposure"},
            "Dependency Metadata Exposure Indicator",
            "Dependency metadata file was observed.",
            "Avoid exposing dependency metadata publicly unless intentionally published.",
            "Impact depends on file contents and deployment context.",
        ),
        (
            {"sbom_analysis", "cve_cpe_enrichment"},
            "Vulnerable Component Indicator",
            "Component metadata matched vulnerability intelligence.",
            "Verify component version and apply vendor-supported updates.",
            "CVE matching may be approximate and requires manual validation.",
        ),
    ]
    for groups, title, evidence_text, recommendation, limitation in grouped:
        rows = [item for item in evidence if str(item.get("rule_group") or "") in groups]
        if not rows:
            continue
        max_cvss = max([float(item.get("cvss_score") or 0) for item in rows] or [0.0])
        has_cve = any(item.get("cve_ids") for item in rows)
        severity = "Medium" if max_cvss >= 7.0 else ("Low" if has_cve or title.startswith("Dependency") else "Informational")
        confidence = "High" if any(str(item.get("confidence")) == "High" for item in rows) else ("Medium" if any(str(item.get("confidence")) == "Medium" for item in rows) else "Low")
        findings.append(
            finding_to_dict(
                create_finding(
                    title=title,
                    severity=severity,
                    category="OWASP A03 Software Supply Chain Failures",
                    affected_host=target,
                    evidence=f"{evidence_text} {len(rows)} indicator item(s) grouped for review.",
                    recommendation=recommendation,
                    source="owasp_a03",
                    confidence=confidence,
                    impact="Potential software supply chain risk if manual validation confirms vulnerable or exposed components.",
                    verification="Review grouped A03 software supply chain evidence and component metadata.",
                    limitation=limitation,
                )
            )
        )
    return findings


def _build_explicit_cve_enrichment(components: list[dict[str, Any]], vuln_intel: dict[str, Any]) -> list[dict[str, Any]]:
    feed = vuln_intel.get("cve_feed") if isinstance(vuln_intel, dict) else None
    if not feed:
        return []
    from scanner.cve_feed import match_cve_feed, normalise_cve_item

    feed = {**feed, "items": [normalise_cve_item(item) for item in feed.get("items", [])]}

    inventory = [
        {
            "name": component.get("name"),
            "product": component.get("product") or component.get("name"),
            "vendor": component.get("vendor") or component.get("supplier"),
            "version": component.get("version"),
            "cpe": component.get("cpe"),
            "cpe_prefix": component.get("cpe"),
            "service_name": str(component.get("name") or "").lower(),
            "purl": component.get("purl") or "",
            "type": component.get("type") or "component",
            "package_ecosystem": component.get("package_ecosystem") or component.get("ecosystem") or "",
            "url": component.get("url") or "",
        }
        for component in components or []
    ]
    rows: list[dict[str, Any]] = []
    for match in match_cve_feed(inventory, feed):
        component = match.get("matched_inventory_item") or match.get("inventory_item") or {}
        cve_id = str(match.get("cve") or match.get("cve_id") or "").strip()
        if not cve_id:
            continue
        component_name = str(component.get("name") or component.get("product") or "component")
        component_version = str(component.get("version") or "")
        cpe = str(component.get("cpe") or match.get("matched_cpe") or "")
        confidence = "High" if component_version else "Low"
        rows.append(
            make_a03_evidence_item(
                rule_id="cve_match_detected",
                rule_group="cve_cpe_enrichment",
                title=f"A03 vulnerable component evidence: {component_name}",
                affected_url=str(component.get("url") or ""),
                component_name=component_name,
                component_version=component_version,
                component_type=str(component.get("type") or "component"),
                package_ecosystem=str(component.get("ecosystem") or component.get("package_ecosystem") or ""),
                cpe=cpe,
                purl=str(component.get("purl") or ""),
                cve_ids=[cve_id],
                cvss_score=match.get("cvss_score"),
                epss_score=match.get("epss_score"),
                exploit_metadata={"available": bool(match.get("exploit_available"))},
                evidence_strength="strong_indicator" if component_version else "weak_indicator",
                confidence=confidence,
                safe_evidence_summary=f"Component metadata matched local vulnerability intelligence for {cve_id}. Manual validation required.",
                recommendation="Verify component identity and version, then apply vendor-supported updates where applicable.",
                manual_validation_required=True,
                source="owasp_a03",
                extra={"match_status": match.get("match_status"), "identity_method": match.get("identity_method")},
            )
        )
    return rows


def _normalise_headers(headers: dict[str, Any] | list[dict[str, Any]] | None) -> dict[str, Any]:
    if isinstance(headers, dict):
        return headers
    merged: dict[str, Any] = {}
    for item in headers or []:
        if not isinstance(item, dict):
            continue
        for key in ("headers", "response_headers", "observed_headers"):
            value = item.get(key)
            if isinstance(value, dict):
                merged.update(value)
        for key, value in item.items():
            if isinstance(value, str) and key.lower() in {"server", "x-powered-by", "x-generator", "x-aspnet-version", "x-drupal-cache"}:
                merged[key] = value
    return merged


def _collect_scripts(scripts: list[str | dict[str, Any]] | None, endpoint_results: list[dict[str, Any]]) -> list[str | dict[str, Any]]:
    rows: list[str | dict[str, Any]] = list(scripts or [])
    for item in endpoint_results or []:
        url = str(item.get("url") or item.get("normalised_url") or item.get("path") or "")
        if url.lower().endswith((".js", ".mjs", ".jsx", ".ts", ".tsx")):
            rows.append(url)
        for key in ("scripts", "script_urls", "assets"):
            value = item.get(key)
            if isinstance(value, list):
                rows.extend(value)
    return rows


def _collect_urls(urls: list[str] | None, endpoint_results: list[dict[str, Any]], scripts: list[str | dict[str, Any]]) -> list[str]:
    rows = [str(item) for item in urls or [] if item]
    rows.extend(str(item.get("url") or item.get("normalised_url") or item.get("path") or "") for item in endpoint_results or [])
    for script in scripts or []:
        if isinstance(script, dict):
            rows.append(str(script.get("src") or script.get("url") or ""))
        else:
            rows.append(str(script))
    return [item for item in rows if item]


def _dedupe_evidence(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str, str]] = set()
    rows: list[dict[str, Any]] = []
    for item in evidence:
        key = (
            str(item.get("rule_id") or ""),
            str(item.get("affected_url") or ""),
            str(item.get("component_name") or ""),
            str(item.get("component_version") or ""),
            ",".join(str(cve) for cve in item.get("cve_ids") or []),
        )
        if key in seen:
            continue
        seen.add(key)
        rows.append(item)
    return rows


def _first_target(endpoint_results: list[dict[str, Any]], urls: list[str]) -> str:
    for item in endpoint_results or []:
        value = str(item.get("url") or item.get("normalised_url") or item.get("target") or "")
        if value:
            return value
    for value in urls or []:
        if value:
            return str(value)
    return ""


def _headers_from_scan_result(scan_result: dict[str, Any]) -> dict[str, Any]:
    return _normalise_headers(scan_result.get("headers") or scan_result.get("web_header_results") or {})


def _html_snippet_from_scan_result(scan_result: dict[str, Any]) -> str:
    for key in ("html_snippet", "body_snippet", "response_snippet"):
        value = str(scan_result.get(key) or "")
        if value:
            return value[:20000]
    return ""


def _scripts_from_scan_result(scan_result: dict[str, Any]) -> list[str | dict[str, Any]]:
    rows: list[str | dict[str, Any]] = []
    for key in ("scripts", "script_urls", "assets"):
        value = scan_result.get(key)
        if isinstance(value, list):
            rows.extend(value)
    for page in scan_result.get("crawled_pages") or []:
        if isinstance(page, dict):
            for key in ("scripts", "script_urls", "assets"):
                value = page.get(key)
                if isinstance(value, list):
                    rows.extend(value)
    return rows


def _urls_from_scan_result(scan_result: dict[str, Any]) -> list[str]:
    rows: list[str] = []
    for key in ("urls", "web_sitemap_url_samples"):
        value = scan_result.get(key)
        if isinstance(value, list):
            rows.extend(str(item) for item in value)
    for page in scan_result.get("crawled_pages") or []:
        if isinstance(page, dict):
            rows.append(str(page.get("url") or ""))
    return [item for item in rows if item]


def _endpoints_from_scan_result(scan_result: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for url in _urls_from_scan_result(scan_result):
        rows.append({"url": url})
    for result in scan_result.get("safe_active_validation_results") or []:
        if isinstance(result, dict):
            rows.append({"url": result.get("url") or result.get("affected_url") or ""})
    return rows


def _components_from_software_inventory(scan_result: dict[str, Any]) -> list[dict[str, Any]]:
    inventory = scan_result.get("software_inventory") or {}
    items = inventory.get("items") if isinstance(inventory, dict) else None
    rows: list[dict[str, Any]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "name": item.get("product") or item.get("name") or item.get("service") or item.get("service_name"),
                "version": item.get("version") or "",
                "type": item.get("type") or item.get("service") or "service",
                "cpe": item.get("cpe") or item.get("cpe23") or "",
                "purl": item.get("purl") or "",
                "package_ecosystem": item.get("package_ecosystem") or "",
            }
        )
    return [item for item in rows if item.get("name")]
