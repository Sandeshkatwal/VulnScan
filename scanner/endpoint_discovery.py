"""Safe endpoint and parameter discovery for bug intelligence workflow.

The module works from supplied URL/path lists and local scope files only. It
does not perform network requests, fuzzing, payload injection, or exploitation.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from scanner.bug_bounty_scope import get_scope_decision, load_bug_bounty_scope
from scanner.finding import assign_sequential_finding_ids, create_finding
from scanner.finding_fingerprint import build_finding_fingerprint
from scanner.parameter_intelligence import classify_parameter, is_sensitive_parameter_name


ENDPOINT_INPUT_DIR = Path("data") / "bug_bounty" / "endpoints"
ENDPOINT_REPORTS_DIR = Path("reports") / "endpoints"
DEFAULT_ENDPOINT_URLS_PATH = ENDPOINT_INPUT_DIR / "sample_urls.txt"
REDACTED_VALUE = "REDACTED"
ENDPOINT_LIMITATIONS = [
    "Endpoint discovery uses supplied/imported URLs only and does not crawl or brute-force.",
    "Parameter candidates are not confirmed vulnerabilities.",
    "No requests, payloads, form submissions, or exploit validation are performed.",
    "Scope decisions depend on local scope file accuracy.",
]


class EndpointDiscoveryError(ValueError):
    """Raised for friendly endpoint discovery configuration errors."""


def load_url_list(path: str | Path) -> list[str]:
    url_path = Path(path)
    try:
        lines = url_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise EndpointDiscoveryError(f"Endpoint URL file was not found: {url_path}") from exc
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def normalise_url(raw: str, base_url: str | None = None) -> str:
    value = str(raw or "").strip()
    if not value:
        raise EndpointDiscoveryError("URL value cannot be empty.")
    if "://" not in value:
        if not base_url:
            raise EndpointDiscoveryError(f"Path-only URL requires --base-url: {value}")
        base = urlsplit(base_url if "://" in base_url else f"http://{base_url}")
        relative = urlsplit(value if value.startswith("/") else f"/{value}")
        path = relative.path or "/"
        return urlunsplit((base.scheme or "http", base.netloc, path, relative.query, ""))
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise EndpointDiscoveryError(f"Unsupported URL format: {value}")
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, parsed.query, ""))


def canonicalise_url(url: str) -> str:
    parsed = urlsplit(url)
    pairs = [
        (name, REDACTED_VALUE if is_sensitive_parameter_name(name) else value)
        for name, value in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    sorted_query = urlencode(sorted(pairs, key=lambda item: (item[0].lower(), item[1])))
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", sorted_query, ""))


def deduplicate_urls(urls: list[str]) -> list[str]:
    seen: set[tuple[str, str, str, tuple[str, ...]]] = set()
    deduped: list[str] = []
    for url in urls:
        parsed = urlsplit(canonicalise_url(url))
        parameter_names = tuple(sorted({name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}))
        key = (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parameter_names)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(canonicalise_url(url))
    return deduped


def extract_url_components(url: str) -> dict[str, Any]:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    parameters = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        sensitive = is_sensitive_parameter_name(name)
        parameters.append(
            {
                "name": name,
                "value": REDACTED_VALUE if sensitive else value,
                "value_redacted": sensitive,
            }
        )
    return {
        "scheme": parsed.scheme,
        "host": parsed.hostname or "",
        "port": parsed.port,
        "path": path,
        "path_depth": len([part for part in path.split("/") if part]),
        "extension": _extension(path),
        "query": _redacted_query(parameters),
        "parameters": parameters,
        "fragment_removed": not bool(parsed.fragment),
        "method_hint": "GET",
    }


def run_endpoint_discovery(
    raw_urls: list[str],
    base_url: str | None = None,
    scope_file: str | Path | None = None,
    enforce_scope: bool = False,
    input_source: str = "manual",
) -> dict[str, Any]:
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    scope = load_bug_bounty_scope(scope_file) if scope_file else None
    normalised_urls: list[str] = []
    invalid_skipped: list[dict[str, Any]] = []
    for raw_url in raw_urls:
        try:
            normalised_urls.append(normalise_url(raw_url, base_url=base_url))
        except EndpointDiscoveryError as exc:
            invalid_skipped.append({"original_url": raw_url, "reason": str(exc), "scope_reason": ""})
    canonical_urls = [canonicalise_url(url) for url in normalised_urls]
    deduped_urls = deduplicate_urls(canonical_urls)

    endpoints: list[dict[str, Any]] = []
    skipped = list(invalid_skipped)
    parameter_results: list[dict[str, Any]] = []
    original_lookup = _original_lookup(raw_urls, base_url)

    for url in deduped_urls:
        decision = get_scope_decision(url, scope) if scope else _unscoped_decision(url)
        if scope and enforce_scope and not decision.get("in_scope"):
            skipped.append(
                {
                    "original_url": original_lookup.get(url, url),
                    "reason": "Out-of-scope URL skipped.",
                    "scope_reason": decision.get("reason") or "",
                }
            )
            continue
        components = extract_url_components(url)
        category = classify_endpoint(components["path"], components["parameters"])
        parameter_candidates = [
            build_parameter_result(url, parameter, components["path"])
            for parameter in components["parameters"]
        ]
        interesting_parameters = [item for item in parameter_candidates if item["parameter_type"] != "unknown"]
        score, reasons = score_endpoint(category, components["parameters"], bool(decision.get("in_scope")))
        endpoint = {
            "original_url": original_lookup.get(url, url),
            "normalised_url": url,
            **components,
            "endpoint_category": category,
            "candidate_score": score,
            "candidate_label": candidate_label(score),
            "candidate_reasons": reasons,
            "source": input_source,
            "in_scope": bool(decision.get("in_scope")),
            "scope_reason": decision.get("reason") or "",
        }
        endpoint_fingerprint = build_finding_fingerprint(
            {
                "url": url,
                "issue_type": category,
                "parameter_names": [parameter.get("name") for parameter in components["parameters"]],
                "source": "endpoint_discovery",
            },
            item_type="endpoint",
        )
        endpoint["fingerprint_id"] = endpoint_fingerprint["fingerprint_id"]
        endpoint["fingerprint_hash"] = endpoint_fingerprint["fingerprint_hash"]
        endpoint["fingerprint_short"] = endpoint_fingerprint["fingerprint_short"]
        for parameter_result in interesting_parameters:
            parameter_fingerprint = build_finding_fingerprint(
                {
                    "url": parameter_result.get("url") or url,
                    "issue_type": parameter_result.get("parameter_type") or parameter_result.get("potential_issue"),
                    "parameter_names": [parameter_result.get("parameter_name")],
                    "source": "parameter_intelligence",
                },
                item_type="parameter",
            )
            parameter_result["fingerprint_id"] = parameter_fingerprint["fingerprint_id"]
            parameter_result["fingerprint_hash"] = parameter_fingerprint["fingerprint_hash"]
            parameter_result["fingerprint_short"] = parameter_fingerprint["fingerprint_short"]
        endpoints.append(endpoint)
        parameter_results.extend(interesting_parameters)

    summary = build_endpoint_summary(
        scope=scope,
        input_source=input_source,
        input_urls_count=len(raw_urls),
        normalised_urls_count=len(normalised_urls),
        deduplicated_urls_count=len(deduped_urls),
        endpoints=endpoints,
        parameter_results=parameter_results,
        skipped=skipped,
    )
    summary["started_at"] = started_at
    summary["completed_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
    findings = build_endpoint_findings(summary, endpoints, parameter_results)
    return {
        "endpoint_discovery": summary,
        "endpoint_results": endpoints,
        "parameter_results": parameter_results,
        "endpoint_skipped": skipped,
        "findings": assign_sequential_finding_ids(findings),
    }


def classify_endpoint(path: str, parameters: list[dict[str, Any]] | None = None) -> str:
    lowered = str(path or "/").lower()
    extension = _extension(lowered)
    if extension in {"css", "js", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "map"}:
        return "static_asset"
    checks = [
        ("password_reset", ("reset-password", "forgot-password", "password/reset")),
        ("authentication", ("login", "signin", "/auth", "/oauth")),
        ("admin", ("/admin", "dashboard/admin")),
        ("api_endpoint", ("/api/", "/v1/", "/v2/", "/graphql", "/api")),
        ("file_upload", ("upload",)),
        ("file_download", ("download", "/file", "file/")),
        ("search", ("search",)),
        ("redirect", ("redirect", "callback")),
        ("export", ("export",)),
        ("debug", ("debug", "/dev", "/test")),
        ("payment_or_billing", ("billing", "payment", "checkout")),
        ("user_account", ("account", "profile", "user")),
    ]
    for category, needles in checks:
        if any(needle in lowered for needle in needles):
            return category
    return "unknown"


def build_parameter_result(url: str, parameter: dict[str, Any], path: str = "") -> dict[str, Any]:
    intelligence = classify_parameter(str(parameter.get("name") or ""))
    score = int(intelligence["candidate_score"])
    return {
        "url": url,
        "path": path or urlsplit(url).path or "/",
        "parameter_name": parameter.get("name") or "",
        "parameter_value_redacted": bool(parameter.get("value_redacted")),
        "parameter_type": intelligence["parameter_type"],
        "potential_issue": intelligence["potential_issue"],
        "confidence": intelligence["confidence"],
        "candidate_score": score,
        "recommendation": intelligence["recommendation"],
        "manual_validation_note": intelligence["manual_validation_note"],
    }


def score_endpoint(category: str, parameters: list[dict[str, Any]], in_scope: bool) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    if category == "admin":
        score += 20
        reasons.append("Admin endpoint indicator")
    if category in {"authentication", "password_reset"}:
        score += 20
        reasons.append("Authentication or password reset endpoint")
    if category == "api_endpoint":
        score += 15
        reasons.append("API endpoint indicator")
    if in_scope:
        score += 10
        reasons.append("In scope")
    if category == "static_asset":
        score -= 20
        reasons.append("Static asset")
    for parameter in parameters:
        name = str(parameter.get("name") or "")
        intelligence = classify_parameter(name)
        parameter_type = intelligence["parameter_type"]
        if parameter_type == "sensitive_token":
            score += 20
            reasons.append(f"Sensitive token parameter: {name}")
        elif parameter_type == "idor":
            score += 20
            reasons.append(f"IDOR-like parameter: {name}")
        elif parameter_type == "redirect":
            score += 15
            reasons.append(f"Redirect parameter: {name}")
        elif parameter_type == "path_traversal":
            score += 20
            reasons.append(f"File/path parameter: {name}")
        elif parameter_type == "ssrf":
            score += 20
            reasons.append(f"SSRF-like parameter: {name}")
        elif parameter_type == "debug_config":
            score += 15
            reasons.append(f"Debug/config parameter: {name}")
    return max(0, min(100, score)), sorted(set(reasons))


def candidate_label(score: int) -> str:
    if score >= 60:
        return "High Interest"
    if score >= 35:
        return "Medium Interest"
    if score >= 15:
        return "Low Interest"
    return "Informational"


def build_endpoint_summary(
    scope: dict[str, Any] | None,
    input_source: str,
    input_urls_count: int,
    normalised_urls_count: int,
    deduplicated_urls_count: int,
    endpoints: list[dict[str, Any]],
    parameter_results: list[dict[str, Any]],
    skipped: list[dict[str, Any]],
) -> dict[str, Any]:
    endpoint_categories = Counter(item.get("endpoint_category") or "unknown" for item in endpoints)
    parameter_types = Counter(item.get("parameter_type") or "unknown" for item in parameter_results)
    return {
        "enabled": True,
        "program_id": (scope or {}).get("program_id") or "",
        "program_name": (scope or {}).get("program_name") or "",
        "input_source": input_source,
        "input_urls_count": input_urls_count,
        "normalised_urls_count": normalised_urls_count,
        "deduplicated_urls_count": deduplicated_urls_count,
        "in_scope_urls_count": sum(1 for item in endpoints if item.get("in_scope")),
        "out_of_scope_urls_count": sum(1 for item in endpoints if not item.get("in_scope")) + len([item for item in skipped if item.get("scope_reason")]),
        "skipped_urls_count": len(skipped),
        "skipped_url_samples": skipped[:5],
        "endpoints_with_parameters_count": sum(1 for item in endpoints if item.get("parameters")),
        "interesting_parameters_count": len(parameter_results),
        "high_interest_count": sum(1 for item in endpoints if item.get("candidate_label") == "High Interest"),
        "medium_interest_count": sum(1 for item in endpoints if item.get("candidate_label") == "Medium Interest"),
        "low_interest_count": sum(1 for item in endpoints if item.get("candidate_label") == "Low Interest"),
        "static_asset_count": endpoint_categories.get("static_asset", 0),
        "endpoint_category_distribution": dict(endpoint_categories),
        "parameter_type_distribution": dict(parameter_types),
        "limitations": ENDPOINT_LIMITATIONS,
    }


def build_endpoint_findings(
    summary: dict[str, Any],
    endpoints: list[dict[str, Any]],
    parameter_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings = [
        create_finding(
            title="Endpoint Discovery Completed",
            severity="Informational",
            category="Bug Intelligence Endpoint Discovery",
            affected_host="endpoint-discovery",
            evidence=(
                f"Endpoint discovery processed {summary.get('input_urls_count', 0)} URLs and identified "
                f"{summary.get('interesting_parameters_count', 0)} interesting parameters."
            ),
            recommendation="Review high-interest endpoints for authorised manual validation.",
            source="endpoint_discovery",
            confidence="High",
            impact="Endpoint and parameter candidates were collected for manual review.",
            verification="Review endpoint_results and parameter_results in the report.",
            limitation="Endpoint discovery identifies candidates only and does not confirm vulnerabilities.",
        )
    ]
    high_count = summary.get("high_interest_count", 0)
    if high_count:
        findings.append(
            create_finding(
                title="High-Interest Endpoint Candidate",
                severity="Low",
                category="Bug Intelligence Endpoint Discovery",
                affected_host="endpoint-discovery",
                evidence=f"{high_count} high-interest endpoint candidate(s) were identified based on path and parameter indicators.",
                recommendation="Manually review high-interest endpoints within program scope.",
                source="endpoint_discovery",
                confidence="Medium",
                impact="High-interest endpoints may warrant careful manual validation.",
                verification="Review high-interest endpoint candidates in endpoint_results.",
                limitation="Candidate scoring is heuristic and does not prove vulnerability.",
            )
        )
    if parameter_results:
        findings.append(
            create_finding(
                title="Interesting Parameter Candidate",
                severity="Informational",
                category="Bug Intelligence Parameter Intelligence",
                affected_host="endpoint-discovery",
                evidence=(
                    "Parameters associated with IDOR, redirect, path, SSRF, token handling, "
                    "or debug/config indicators were discovered."
                ),
                recommendation="Manually validate parameter behaviour according to program rules.",
                source="parameter_intelligence",
                confidence="Medium",
                impact="Interesting parameter names can help prioritise manual testing.",
                verification="Review parameter_results and only test within authorised scope.",
                limitation="Parameter names are indicators only and may be benign.",
            )
        )
    return findings


def save_endpoint_report(payload: dict[str, Any], reports_dir: Path | str = ENDPOINT_REPORTS_DIR) -> Path:
    directory = Path(reports_dir)
    directory.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    path = directory / f"endpoint-discovery_{timestamp}.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _extension(path: str) -> str:
    name = Path(str(path or "")).name
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1].lower()


def _redacted_query(parameters: list[dict[str, Any]]) -> str:
    return urlencode([(item["name"], item["value"]) for item in parameters])


def _unscoped_decision(url: str) -> dict[str, Any]:
    return {"target": url, "in_scope": True, "reason": "No program scope configured.", "matched_rule": ""}


def _original_lookup(raw_urls: list[str], base_url: str | None) -> dict[str, str]:
    lookup: dict[str, str] = {}
    for raw in raw_urls:
        try:
            lookup[canonicalise_url(normalise_url(raw, base_url=base_url))] = raw
        except EndpointDiscoveryError:
            continue
    return lookup
