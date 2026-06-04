"""A10 Mishandling of Exceptional Conditions safe indicator collection."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from scanner.evidence import redact_nested
from scanner.finding import create_finding, finding_to_dict


A10_RULES_PATH = Path("data") / "owasp" / "a10" / "a10_rules.json"
A10_REPORTS_DIR = Path("reports") / "owasp" / "a10"
MAX_SNIPPET_LENGTH = 1000
SENSITIVE_ENDPOINT_CATEGORIES = {
    "authentication", "password_reset", "payment_or_billing", "admin", "file_upload",
    "import", "export", "account", "user_account",
}
LIMITATIONS = [
    "A10 checks are observation-based and do not force application errors.",
    "No crash testing, DoS testing, payload injection, form submission, or state-changing requests are performed.",
    "Full response bodies, secrets, tokens, passwords, cookies, session IDs, and private keys are not stored.",
]


class A10RulesError(ValueError):
    """Raised when A10 rules are unavailable or invalid."""


def load_a10_rules(path: str | Path = A10_RULES_PATH) -> dict[str, Any]:
    rules_path = Path(path)
    try:
        payload = json.loads(rules_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise A10RulesError(f"A10 rules file was not found: {rules_path}") from exc
    except json.JSONDecodeError as exc:
        raise A10RulesError(f"A10 rules file is not valid JSON: {rules_path}") from exc
    if payload.get("owasp_id") != "A10:2025":
        raise A10RulesError("A10 rules file must describe A10:2025.")
    if not isinstance(payload.get("rule_groups"), dict):
        raise A10RulesError("A10 rules file must include rule_groups.")
    return payload


def ensure_a10_dirs() -> None:
    A10_RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    A10_REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def build_safe_error_snippet(text: str, max_length: int = MAX_SNIPPET_LENGTH) -> str:
    return redact_error_snippet(str(text or "")[:max_length])


def redact_error_snippet(text: str) -> str:
    value = str(text or "")
    replacements = [
        (r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]"),
        (r"(?i)(password|passwd|pwd|token|api[_-]?key|secret|session[_-]?id|sid)\s*[:=]\s*['\"]?[^'\"\s;&<]+", r"\1=[REDACTED]"),
        (r"(?i)(cookie:\s*)[^;\r\n<\s]+", r"\1[REDACTED]"),
        (r"[A-Za-z]:\\[^\r\n\t<>\"']+", "[INTERNAL_PATH_REDACTED]"),
        (r"(?<!:)\/(?:var|home|app|srv|opt|usr|www)\/[^\r\n\t<>\"']+", "[INTERNAL_PATH_REDACTED]"),
    ]
    for pattern, replacement in replacements:
        value = re.sub(pattern, replacement, value)
    return value[:MAX_SNIPPET_LENGTH]


def detect_error_patterns(text: str) -> list[dict[str, str]]:
    haystack = str(text or "")
    checks: list[tuple[str, str, str, str, str]] = [
        ("traceback_detected", "verbose_error_messages", r"Traceback(?: \(most recent call last\))?", "Python traceback", "python_traceback"),
        ("stack_trace_detected", "verbose_error_messages", r"(?m)\bat\s+[A-Za-z0-9_.$<>]+\(.+:\d+\)", "Stack trace", "node_stack_trace"),
        ("stack_trace_detected", "verbose_error_messages", r"(?m)\s+at\s+Object\.|\s+at\s+Module\.", "Node stack trace", "node_stack_trace"),
        ("node_stack_trace", "framework_error_indicators", r"(?m)\s+at\s+(Object|Module)\.|at\s+[A-Za-z0-9_.$<>]+\s*\(.+\.js:\d+", "Node/Express stack trace", "node"),
        ("exception_message_detected", "verbose_error_messages", r"\b(TypeError|ReferenceError|ValueError|KeyError|RuntimeException|NullPointerException|SQLException)\b", "Exception message", ""),
        ("line_number_disclosure_indicator", "verbose_error_messages", r"\bline\s+\d+\b|:\d+\)", "Line number reference", ""),
        ("source_path_disclosure_indicator", "verbose_error_messages", r"[A-Za-z]:\\|/(var|home|app|srv|opt|usr|www)/", "Internal source path", ""),
        ("sql_error_message_detected", "database_error_indicators", r"SQL syntax|SQLException|syntax error at or near|mysql_fetch|ORA-\d+|PostgreSQL", "SQL/database error", ""),
        ("database_driver_error_detected", "database_error_indicators", r"PDOException|psycopg2|SQLAlchemy|SequelizeDatabaseError|MongoError|RedisError", "Database driver error", ""),
        ("database_connection_error_detected", "database_error_indicators", r"database connection failed|could not connect to database|connection refused.*database", "Database connection error", ""),
        ("orm_error_detected", "database_error_indicators", r"Doctrine\\|HibernateException|ActiveRecord::|EntityManager", "ORM error", ""),
        ("django_debug_page", "framework_error_indicators", r"Django.*DEBUG|You're seeing this error because you have DEBUG = True", "Django debug page", "django"),
        ("flask_debug_page", "framework_error_indicators", r"Werkzeug Debugger|Flask debug", "Flask/Werkzeug debugger", "flask"),
        ("laravel_error_page", "framework_error_indicators", r"Whoops!|Laravel.*Exception", "Laravel/Whoops error page", "laravel"),
        ("rails_error_page", "framework_error_indicators", r"ActiveRecord::|ActionController::|Rails.root", "Rails exception page", "rails"),
        ("express_error_page", "framework_error_indicators", r"Express error|Cannot\s+\w+\s+/.+Error:", "Express error page", "express"),
        ("spring_boot_error_page", "framework_error_indicators", r"Whitelabel Error Page|Spring Boot", "Spring Boot Whitelabel Error Page", "spring_boot"),
        ("aspnet_error_page", "framework_error_indicators", r"Server Error in '/' Application|ASP\.NET|yellow screen", "ASP.NET detailed error page", "aspnet"),
        ("java_exception_page", "framework_error_indicators", r"java\.[A-Za-z.]+Exception|NullPointerException", "Java exception page", "java"),
        ("php_warning_notice_error", "framework_error_indicators", r"PHP (Fatal error|Warning|Notice)|Fatal error:", "PHP warning/notice/fatal error", "php"),
        ("debug_error_page_detected", "verbose_error_messages", r"debug mode|debugger|stack trace", "Debug error page", ""),
        ("framework_debug_banner_detected", "verbose_error_messages", r"DEBUG\s*=\s*True|development mode|Whoops!", "Framework debug banner", ""),
        ("internal_path_disclosure", "sensitive_error_content", r"[A-Za-z]:\\|/(var|home|app|srv|opt|usr|www)/", "Internal path disclosure", ""),
        ("environment_name_disclosure", "sensitive_error_content", r"\b(staging|development|debug|test)\b", "Environment name disclosure", ""),
        ("framework_version_disclosure", "sensitive_error_content", r"\b(Django|Flask|Laravel|Rails|Express|Spring Boot|ASP\.NET|PHP)\s+v?\d+(?:\.\d+)+", "Framework version disclosure", ""),
        ("database_name_disclosure", "sensitive_error_content", r"\b(mysql|postgres|postgresql|mongodb|sqlite|redis)\b", "Database name/driver disclosure", ""),
        ("cloud_metadata_string_indicator", "sensitive_error_content", r"metadata\.google\.internal|169\.254\.169\.254|169\.254\.169\.254/latest/meta-data", "Cloud metadata string indicator", ""),
    ]
    matches: list[dict[str, str]] = []
    for rule_id, group, pattern, label, framework in checks:
        if re.search(pattern, haystack, re.IGNORECASE):
            matches.append({"rule_id": rule_id, "rule_group": group, "pattern": label, "framework_hint": framework})
    seen: set[tuple[str, str]] = set()
    unique = []
    for item in matches:
        key = (item["rule_id"], item["pattern"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def assess_verbose_errors(url: str, status_code: int | None, body_snippet: str, headers: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    safe_snippet = build_safe_error_snippet(body_snippet)
    evidence: list[dict[str, Any]] = []
    for match in detect_error_patterns(body_snippet):
        strength = "strong_indicator" if match["rule_id"] in {
            "stack_trace_detected", "traceback_detected", "debug_error_page_detected",
            "framework_debug_banner_detected", "source_path_disclosure_indicator",
            "sql_error_message_detected", "database_driver_error_detected",
            "database_connection_error_detected", "internal_path_disclosure",
            "cloud_metadata_string_indicator",
        } or match["rule_group"] == "framework_error_indicators" else "weak_indicator"
        confidence = "High" if strength == "strong_indicator" else "Medium"
        evidence.append(
            _evidence(
                rule_id=match["rule_id"],
                rule_group=match["rule_group"],
                title=f"Exception exposure evidence: {match['pattern']}",
                affected_url=url,
                status_code=status_code,
                evidence_strength=strength,
                confidence=confidence,
                observed_pattern=match["pattern"],
                redacted_snippet=safe_snippet,
                safe_evidence_summary=f"Observed response snippet matched {match['pattern']}. Full response body was not stored.",
                recommendation="Disable detailed errors in production and log diagnostic details server-side.",
                extra={"framework_hint": match.get("framework_hint", ""), "pattern_matched": match["pattern"]},
            )
        )
    if status_code and status_code >= 500 and safe_snippet and any(item.get("rule_group") == "verbose_error_messages" for item in evidence):
        evidence.append(
            _evidence(
                rule_id="generic_error_with_debug_details",
                rule_group="http_error_patterns",
                title="Verbose error evidence in 5xx response",
                affected_url=url,
                status_code=status_code,
                evidence_strength="weak_indicator",
                confidence="Medium",
                observed_pattern="5xx response with debug details",
                redacted_snippet=safe_snippet,
                safe_evidence_summary="Observed 5xx response contained diagnostic details. Full response body was not stored.",
                recommendation="Use generic user-facing errors and log details server-side.",
            )
        )
    return evidence


def assess_status_code_patterns(response_observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for obs in response_observations:
        status = _int(obs.get("status_code"))
        if status >= 500:
            by_host[urlsplit(str(obs.get("url") or "")).netloc].append(obs)
            category = str(obs.get("endpoint_category") or _endpoint_category_from_url(str(obs.get("url") or "")))
            if category in SENSITIVE_ENDPOINT_CATEGORIES:
                evidence.append(_fail_safe_evidence(obs, category))
            elif _is_common_endpoint(str(obs.get("url") or "")):
                evidence.append(_status_evidence("500_on_common_endpoint", "5xx status observation on common endpoint", obs, "weak_indicator", "Medium"))
    for host, items in by_host.items():
        if len(items) >= 2:
            sample = items[0]
            evidence.append(
                _evidence(
                    rule_id="repeated_500_responses",
                    rule_group="http_error_patterns",
                    title="Repeated 5xx status observations",
                    affected_url=str(sample.get("url") or ""),
                    status_code=_int(sample.get("status_code")),
                    evidence_strength="weak_indicator",
                    confidence="Medium",
                    observed_pattern=f"{len(items)} observed 5xx responses on {host}",
                    redacted_snippet="",
                    safe_evidence_summary="Multiple 5xx responses were observed from existing response metadata. No errors were forced.",
                    recommendation="Review server-side error handling and operational stability for affected endpoints.",
                    extra={"error_cluster_count": len(items), "host": host},
                )
            )
    return evidence


def assess_a10_error_handling(
    *,
    target: str = "",
    responses: list[dict[str, Any]] | None = None,
    crawled_pages: list[dict[str, Any]] | None = None,
    endpoint_results: list[dict[str, Any]] | None = None,
    validation_results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    ensure_a10_dirs()
    load_a10_rules()
    observations = _collect_observations(target, responses, crawled_pages, endpoint_results, validation_results)
    evidence: list[dict[str, Any]] = []
    for obs in observations:
        evidence.extend(assess_verbose_errors(str(obs.get("url") or ""), _int(obs.get("status_code")), str(obs.get("body_snippet") or obs.get("html_snippet") or obs.get("error") or ""), dict(obs.get("headers") or {})))
    evidence.extend(assess_status_code_patterns(observations))
    evidence = _dedupe_evidence(evidence)
    summary = build_a10_summary(target=target or _first_observed_url(observations), evidence=evidence, observations=observations)
    findings = build_a10_findings(summary, evidence)
    return redact_nested({"a10_error_handling_summary": summary, "a10_error_handling_evidence": evidence, "findings": findings})


def attach_a10_error_handling(scan_result: dict[str, Any]) -> dict[str, Any]:
    target = str(scan_result.get("target") or scan_result.get("url") or "")
    if not target:
        pages = scan_result.get("crawled_pages") or []
        target = str((pages[0] or {}).get("url") if pages else scan_result.get("host") or "")
    payload = assess_a10_error_handling(
        target=target,
        crawled_pages=scan_result.get("crawled_pages") or [],
        endpoint_results=scan_result.get("endpoint_results") or [],
        validation_results=scan_result.get("safe_active_validation_results") or [],
    )
    findings = list(payload.get("findings", []))
    payload_without_findings = dict(payload)
    payload_without_findings.pop("findings", None)
    scan_result.update(payload_without_findings)
    scan_result.setdefault("findings", [])
    scan_result["findings"].extend(findings)
    return scan_result


def build_a10_summary(target: str, evidence: list[dict[str, Any]], observations: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    strength_counts = Counter(str(item.get("evidence_strength") or "") for item in evidence)
    group_counts = Counter(str(item.get("rule_group") or "") for item in evidence)
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
        "strong_indicators_count": strength_counts.get("strong_indicator", 0) + strength_counts.get("confirmed_finding", 0),
        "weak_indicators_count": strength_counts.get("weak_indicator", 0),
        "informational_count": strength_counts.get("informational", 0),
        "manual_validation_required_count": sum(1 for item in evidence if item.get("manual_validation_required")),
        "stack_trace_count": sum(1 for item in evidence if item.get("rule_id") in {"stack_trace_detected", "traceback_detected", "python_traceback", "node_stack_trace"}),
        "database_error_count": group_counts.get("database_error_indicators", 0),
        "framework_error_count": group_counts.get("framework_error_indicators", 0),
        "debug_page_count": sum(1 for item in evidence if item.get("rule_id") in {"debug_error_page_detected", "framework_debug_banner_detected", "django_debug_page", "flask_debug_page"}),
        "status_5xx_count": sum(1 for obs in observations or [] if _int(obs.get("status_code")) >= 500),
        "fail_safe_review_count": group_counts.get("fail_open_manual_review", 0),
        "sensitive_error_content_count": group_counts.get("sensitive_error_content", 0),
        "rule_group_counts": dict(group_counts),
        "highest_confidence": highest if evidence else "Low",
        "top_risks": [str(item.get("title") or "") for item in evidence if item.get("evidence_strength") == "strong_indicator"][:5],
        "recommendations": _recommendations(evidence),
        "limitations": list(LIMITATIONS),
    }


def build_a10_findings(summary: dict[str, Any], evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = [
        finding_to_dict(create_finding(title="A10 Error Handling Assessment Completed", severity="Informational", category="OWASP A10 Mishandling of Exceptional Conditions", affected_host=str(summary.get("target") or "a10-assessment"), evidence="VulScan evaluated available response snippets, status codes, endpoint categories, and observed error evidence.", recommendation="Review A10 evidence and ensure applications fail safely with generic user-facing errors.", source="owasp_a10", confidence="High", impact="A10 evidence supports manual error-handling and fail-safe review.", verification="Review a10_error_handling_summary and a10_error_handling_evidence.", limitation="A10 checks are observation-based and do not force application errors."))
    ]
    if any(item.get("rule_group") in {"verbose_error_messages", "database_error_indicators", "sensitive_error_content"} for item in evidence):
        strong = any(item.get("evidence_strength") == "strong_indicator" for item in evidence if item.get("rule_group") in {"verbose_error_messages", "database_error_indicators", "sensitive_error_content"})
        findings.append(finding_to_dict(create_finding(title="Verbose Error Exposure Indicator", severity="Medium" if strong else "Low", category="OWASP A10 Mishandling of Exceptional Conditions", affected_host=str(summary.get("target") or ""), evidence="Observed error response contained verbose diagnostic information.", recommendation="Disable detailed errors in production and log details server-side.", source="owasp_a10", confidence="Medium", impact="Verbose error details can expose implementation information.", verification="Review verbose error evidence and redacted snippets.", limitation="Impact depends on disclosed details and application context.")))
    if any(item.get("rule_group") == "framework_error_indicators" for item in evidence):
        findings.append(finding_to_dict(create_finding(title="Framework Debug Indicator", severity="Medium", category="OWASP A10 Mishandling of Exceptional Conditions", affected_host=str(summary.get("target") or ""), evidence="Observed response indicated possible framework debug/error page.", recommendation="Disable debug mode in production.", source="owasp_a10", confidence="Medium", impact="Framework debug pages can expose implementation details.", verification="Review framework debug indicators.", limitation="Manual validation is required.")))
    if any(item.get("rule_group") == "fail_open_manual_review" for item in evidence):
        findings.append(finding_to_dict(create_finding(title="Fail-Safe Review Recommended", severity="Low", category="OWASP A10 Mishandling of Exceptional Conditions", affected_host=str(summary.get("target") or ""), evidence="Error indicators were observed on sensitive workflow endpoints.", recommendation="Review whether the workflow fails closed and preserves authorization/session safety.", source="owasp_a10", confidence="Medium", impact="Sensitive workflows should handle exceptional conditions safely.", verification="Review fail-safe manual review evidence.", limitation="VulScan does not confirm fail-open behaviour automatically.")))
    return findings


def _evidence(*, rule_id: str, rule_group: str, title: str, affected_url: str, status_code: int | None, evidence_strength: str, confidence: str, observed_pattern: str, redacted_snippet: str, safe_evidence_summary: str, recommendation: str, manual_validation_required: bool = True, source: str = "owasp_a10", extra: dict[str, Any] | None = None) -> dict[str, Any]:
    item = {
        "evidence_id": "",
        "rule_id": rule_id,
        "rule_group": rule_group,
        "title": title,
        "affected_url": affected_url,
        "affected_host": urlsplit(str(affected_url or "")).netloc,
        "status_code": status_code,
        "evidence_strength": evidence_strength,
        "confidence": confidence,
        "observed_pattern": observed_pattern,
        "safe_evidence_summary": safe_evidence_summary,
        "redacted_snippet": redacted_snippet,
        "recommendation": recommendation,
        "manual_validation_required": manual_validation_required,
        "source": source,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if extra:
        item.update(extra)
    item["evidence_id"] = "a10_ev_" + hashlib.sha256("|".join(str(item.get(key) or "") for key in ("rule_id", "affected_url", "status_code", "observed_pattern")).encode("utf-8")).hexdigest()[:16]
    return redact_nested(item)


def _collect_observations(target: str, responses: list[dict[str, Any]] | None, crawled_pages: list[dict[str, Any]] | None, endpoint_results: list[dict[str, Any]] | None, validation_results: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    observations = [dict(item) for item in responses or []]
    for page in crawled_pages or []:
        observations.append({"url": page.get("url") or target, "status_code": page.get("status_code"), "body_snippet": page.get("body_snippet") or page.get("html_snippet") or page.get("limited_html") or "", "headers": page.get("response_headers") or {}, "source": "web_crawler"})
    for item in validation_results or []:
        summary = item.get("evidence_summary")
        observations.append({"url": item.get("url") or target, "status_code": item.get("status_code"), "body_snippet": json.dumps(summary) if isinstance(summary, dict) else str(summary or ""), "source": "safe_active_validation", "endpoint_category": item.get("candidate_type") or ""})
    for item in endpoint_results or []:
        url = str(item.get("normalised_url") or item.get("url") or "")
        if url:
            observations.append({"url": url, "status_code": item.get("status_code"), "body_snippet": "", "source": "endpoint_discovery", "endpoint_category": item.get("endpoint_category") or ""})
    return [obs for obs in observations if obs.get("url")]


def _fail_safe_evidence(obs: dict[str, Any], category: str) -> dict[str, Any]:
    rule_id = {
        "authentication": "auth_error_surface_indicator",
        "password_reset": "reset_password_error_surface_indicator",
        "payment_or_billing": "payment_error_surface_indicator",
    }.get(category, "state_changing_endpoint_error_surface_indicator")
    return _evidence(rule_id=rule_id, rule_group="fail_open_manual_review", title="Fail-safe review required", affected_url=str(obs.get("url") or ""), status_code=_int(obs.get("status_code")), evidence_strength="informational", confidence="Medium", observed_pattern=f"5xx on {category} endpoint", redacted_snippet="", safe_evidence_summary="Observed error status on sensitive workflow endpoint. No fail-open behaviour was confirmed.", recommendation="Review whether the workflow fails closed and preserves authorization/session safety.", extra={"endpoint_category": category})


def _status_evidence(rule_id: str, title: str, obs: dict[str, Any], strength: str, confidence: str) -> dict[str, Any]:
    return _evidence(rule_id=rule_id, rule_group="http_error_patterns", title=title, affected_url=str(obs.get("url") or ""), status_code=_int(obs.get("status_code")), evidence_strength=strength, confidence=confidence, observed_pattern=f"status_code={obs.get('status_code')}", redacted_snippet="", safe_evidence_summary="Observed error status from existing response metadata. No errors were forced.", recommendation="Review error handling for affected endpoint.")


def _endpoint_category_from_url(url: str) -> str:
    lower = url.lower()
    if "login" in lower or "auth" in lower or "signin" in lower:
        return "authentication"
    if "reset-password" in lower or "forgot-password" in lower or "password-reset" in lower:
        return "password_reset"
    if "payment" in lower or "billing" in lower or "checkout" in lower:
        return "payment_or_billing"
    if "admin" in lower:
        return "admin"
    if "upload" in lower:
        return "file_upload"
    if "account" in lower or "profile" in lower:
        return "user_account"
    return ""


def _is_common_endpoint(url: str) -> bool:
    return bool(_endpoint_category_from_url(url))


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _dedupe_evidence(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    order = {"informational": 1, "weak_indicator": 2, "strong_indicator": 3, "confirmed_finding": 4}
    for item in items:
        key = (str(item.get("rule_id")), str(item.get("affected_url")), str(item.get("observed_pattern")))
        existing = by_key.get(key)
        if not existing or order.get(str(item.get("evidence_strength")), 0) > order.get(str(existing.get("evidence_strength")), 0):
            by_key[key] = item
    return list(by_key.values())


def _recommendations(evidence: list[dict[str, Any]]) -> list[str]:
    defaults = [
        "Disable detailed errors in production.",
        "Use generic user-facing error messages.",
        "Log diagnostic details safely server-side.",
        "Review sensitive workflows for fail-closed behaviour.",
        "Avoid exposing stack traces, internal paths, framework versions, and database errors.",
    ]
    seen: list[str] = []
    for item in evidence:
        rec = str(item.get("recommendation") or "")
        if rec and rec not in seen:
            seen.append(rec)
    return seen[:8] or defaults


def _first_observed_url(observations: list[dict[str, Any]]) -> str:
    return str((observations[0] or {}).get("url") or "") if observations else ""
