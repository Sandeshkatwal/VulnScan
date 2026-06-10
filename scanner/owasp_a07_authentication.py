"""A07 Authentication Failures safe indicator collection.

This module analyses existing VulScan metadata only. It does not submit login
forms, create accounts, reset passwords, perform repeated requests, or collect
credentials, cookie values, token values, hidden field values, or response bodies.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from scanner.evidence import redact_nested
from scanner.finding import create_finding, finding_to_dict
from scanner.parameter_replay_planner import build_parameter_replay_summary
from scanner.web_cookie_audit import parse_set_cookie_headers


A07_RULES_PATH = Path("data") / "owasp" / "a07" / "a07_rules.json"
A07_REPORTS_DIR = Path("reports") / "owasp" / "a07"
SESSION_COOKIE_HINTS = {
    "session", "sid", "sess", "auth", "token", "jwt", "remember", "remember_me",
    "login", "user", "identity", "id_token", "access_token", "refresh_token",
}
RESET_TOKEN_PARAMETERS = {"token", "code", "reset_token", "password_reset_token", "recovery_token", "verification_code"}
CSRF_FIELD_NAMES = {"csrf", "csrf_token", "_csrf", "authenticity_token", "request_verification_token", "anti_forgery", "xsrf", "token"}
RATE_LIMIT_HEADERS = {"ratelimit-limit", "ratelimit-remaining", "ratelimit-reset", "x-ratelimit-limit", "x-ratelimit-remaining"}
LIMITATIONS = [
    "A07 checks are indicator-based and require manual validation for authentication control conclusions.",
    "No login attempts, repeated requests, account creation, password reset, brute force, credential stuffing, password guessing, or MFA bypass testing is performed.",
    "Cookie values, hidden field values, secrets, tokens, passwords, private keys, and full response bodies are not stored.",
]


class A07RulesError(ValueError):
    """Raised when A07 rules are unavailable or invalid."""


def load_a07_rules(path: str | Path = A07_RULES_PATH) -> dict[str, Any]:
    rules_path = Path(path)
    try:
        payload = json.loads(rules_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise A07RulesError(f"A07 rules file was not found: {rules_path}") from exc
    except json.JSONDecodeError as exc:
        raise A07RulesError(f"A07 rules file is not valid JSON: {rules_path}") from exc
    if payload.get("owasp_id") != "A07:2025":
        raise A07RulesError("A07 rules file must describe A07:2025.")
    if not isinstance(payload.get("rule_groups"), dict):
        raise A07RulesError("A07 rules file must include rule_groups.")
    return payload


def ensure_a07_dirs() -> None:
    A07_RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    A07_REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def assess_a07_authentication(
    *,
    target: str = "",
    urls: list[str] | None = None,
    headers: dict[str, Any] | None = None,
    set_cookie_headers: list[str] | None = None,
    forms: list[dict[str, Any]] | None = None,
    crawled_pages: list[dict[str, Any]] | None = None,
    endpoint_results: list[dict[str, Any]] | None = None,
    parameter_results: list[dict[str, Any]] | None = None,
    validation_results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    ensure_a07_dirs()
    load_a07_rules()
    url_list = _collect_urls(target, urls, crawled_pages, endpoint_results, parameter_results, validation_results)
    evidence: list[dict[str, Any]] = []
    evidence.extend(assess_auth_endpoints(endpoint_results or [], url_list))
    evidence.extend(assess_password_reset_indicators(url_list, parameter_results or []))
    for url in url_list:
        page_headers = _headers_for_url(url, crawled_pages) or (headers or {})
        evidence.extend(assess_rate_limit_headers(url, page_headers, _endpoint_type_for_url(url)))
    for page in crawled_pages or []:
        page_url = str(page.get("url") or target)
        for cookie in page.get("cookies") or []:
            evidence.extend(assess_auth_cookies(page_url, parsed_cookies=[dict(cookie)]))
    if set_cookie_headers:
        evidence.extend(assess_auth_cookies(target or _first_url(url_list), set_cookie_headers=set_cookie_headers))
    evidence.extend(assess_auth_forms(target or _first_url(url_list), forms or _collect_forms(crawled_pages)))
    evidence = _dedupe_evidence(evidence)
    summary = build_a07_summary(target=target or _first_url(url_list), evidence=evidence)
    findings = build_a07_findings(summary, evidence)
    return redact_nested(
        {
            "a07_authentication_summary": summary,
            "a07_authentication_evidence": evidence,
            "findings": findings,
        }
    )


def attach_a07_authentication(scan_result: dict[str, Any]) -> dict[str, Any]:
    target = str(scan_result.get("target") or scan_result.get("url") or "")
    if not target:
        pages = scan_result.get("crawled_pages") or []
        target = str((pages[0] or {}).get("url") if pages else scan_result.get("host") or "")
    payload = assess_a07_authentication(
        target=target,
        urls=_collect_urls(target, scan_result.get("urls"), scan_result.get("crawled_pages"), scan_result.get("endpoint_results"), scan_result.get("parameter_results"), scan_result.get("safe_active_validation_results")),
        crawled_pages=scan_result.get("crawled_pages") or [],
        forms=scan_result.get("web_form_results") or scan_result.get("discovered_forms") or [],
        endpoint_results=scan_result.get("endpoint_results") or [],
        parameter_results=scan_result.get("parameter_results") or [],
        validation_results=scan_result.get("safe_active_validation_results") or [],
    )
    auth_summary = scan_result.get("auth_context_summary") or {}
    profile = auth_summary.get("session_profile") or {}
    cookie_names = list(profile.get("cookie_names") or auth_summary.get("cookie_names") or [])
    extra_evidence = []
    if cookie_names:
        extra_evidence.extend([
            _evidence(
                rule_id="session_profile_cookie_name_observed",
                rule_group="session_cookie_indicators",
                title="Session Profile cookie name available",
                affected_url=str(profile.get("target_base_url") or target),
                confidence="Medium",
                evidence_strength="informational",
                observed_value=f"cookie_name={name}; value=[REDACTED]",
                safe_evidence_summary=f"Session Profile includes cookie name {name}. Cookie value was not stored in the report.",
                recommendation="Use the cookie name to manually review session lifecycle, expiry, and invalidation.",
                manual_validation_required=True,
                extra={"cookie_name": name, "role_label": profile.get("role_label") or ""},
            )
            for name in cookie_names
        ])
    for row in scan_result.get("authenticated_crawl_results") or []:
        if row.get("session_expiry_indicator"):
            extra_evidence.append(
                _evidence(
                    rule_id="authenticated_crawl_session_expiry_indicator",
                    rule_group="session_expiry_indicators",
                    title="Session Expiry Indicator observed during Authenticated Crawl",
                    affected_url=str(row.get("url") or target),
                    confidence=str(row.get("session_expiry_confidence") or "Medium"),
                    evidence_strength="weak_indicator",
                    observed_value=str(row.get("session_expiry_reason") or "Session Expiry Indicator observed."),
                    safe_evidence_summary="Authenticated Crawl observed a login-required or session-expiry indicator. Raw auth material was not stored.",
                    recommendation="Manually validate expected session expiry, login redirect, and user experience for the documented Authentication Context.",
                    manual_validation_required=True,
                    extra={"role_label": profile.get("role_label") or row.get("role_label") or "", "source": "authenticated_crawl"},
                )
            )
    if extra_evidence:
        payload["a07_authentication_evidence"] = list(payload.get("a07_authentication_evidence", [])) + extra_evidence
        payload["a07_authentication_summary"] = build_a07_summary(target=target, evidence=payload["a07_authentication_evidence"])
    replay_plans = [plan for plan in scan_result.get("parameter_replay_plans") or [] if "A07" in (plan.get("related_owasp_categories") or [])]
    if replay_plans:
        replay_summary = build_parameter_replay_summary(replay_plans, scan_result.get("parameter_replay_observations") or [], scan_result.get("parameter_replay_retests") or [])
        payload["a07_authentication_summary"].update(
            {
                "auth_parameter_review_plans_count": replay_summary.get("replay_plans_count", 0),
                "session_replay_review_count": sum(1 for plan in replay_plans if plan.get("replay_intent") == "auth_session_review"),
            }
        )
    business_logic_plans = [plan for plan in scan_result.get("business_logic_review_plans") or [] if "A07" in (plan.get("related_owasp_categories") or [])]
    if business_logic_plans:
        payload["a07_authentication_summary"].update(
            {
                "business_logic_review_plans_count": len(business_logic_plans),
                "business_logic_manual_observations_count": len(scan_result.get("business_logic_observations") or []),
            }
        )
    findings = list(payload.get("findings", []))
    payload_without_findings = dict(payload)
    payload_without_findings.pop("findings", None)
    scan_result.update(payload_without_findings)
    scan_result.setdefault("findings", [])
    scan_result["findings"].extend(findings)
    return scan_result


def assess_auth_endpoints(endpoint_results: list[dict[str, Any]], urls: list[str]) -> list[dict[str, Any]]:
    collected = list(urls)
    for endpoint in endpoint_results:
        url = str(endpoint.get("normalised_url") or endpoint.get("url") or endpoint.get("path") or "")
        if url:
            collected.append(url)
    evidence: list[dict[str, Any]] = []
    for url in dict.fromkeys(collected):
        endpoint_type, rule_id = _endpoint_type_and_rule(url)
        if not rule_id:
            continue
        evidence.append(
            _evidence(
                rule_id=rule_id,
                rule_group="auth_endpoint_discovery",
                title=f"Authentication indicator: {endpoint_type}",
                affected_url=url,
                confidence="Medium",
                evidence_strength="informational",
                observed_value=f"{endpoint_type} endpoint path observed",
                safe_evidence_summary=f"Authentication-related endpoint surface observed: {endpoint_type}.",
                recommendation="Review authentication workflow controls and session handling manually.",
                extra={"endpoint_type": endpoint_type},
            )
        )
        if rule_id in {"password_reset_endpoint_detected", "forgot_password_endpoint_detected"}:
            evidence.append(
                _evidence(
                    rule_id="reset_workflow_manual_review_required",
                    rule_group="password_reset_workflow_indicators",
                    title="Password reset workflow evidence",
                    affected_url=url,
                    confidence="Medium",
                    evidence_strength="informational",
                    observed_value="Password reset workflow surface observed",
                    safe_evidence_summary="Password reset workflow endpoint requires manual validation.",
                    recommendation="Manually review token handling, expiration, single-use behaviour, and rate limiting.",
                    extra={"endpoint_type": endpoint_type},
                )
            )
        if rule_id in {"oauth_oidc_endpoint_detected", "saml_endpoint_detected", "auth_callback_endpoint_detected"}:
            evidence.extend(assess_auth_protocol_surface([url]))
    return evidence


def assess_auth_cookies(url: str, set_cookie_headers: list[str] | None = None, parsed_cookies: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    cookies = list(parsed_cookies or [])
    if set_cookie_headers:
        cookies.extend(parse_set_cookie_headers(set_cookie_headers, url))
    is_https = urlsplit(str(url or "")).scheme == "https"
    evidence: list[dict[str, Any]] = []
    for cookie in cookies:
        name = str(cookie.get("name") or cookie.get("cookie_name") or "")
        if not name:
            continue
        lower = name.lower()
        is_session = _session_like_cookie(lower)
        is_remember = "remember" in lower
        if not is_session and not is_remember:
            continue
        missing: list[str] = []
        persistent = bool(cookie.get("expires_present") or cookie.get("max_age_present") or cookie.get("expires") or cookie.get("max_age"))
        evidence.append(_cookie_evidence("session_cookie_detected" if is_session else "remember_me_cookie_detected", "Cookie/session evidence", url, name, [], "informational" if is_session else "weak_indicator", "Medium", persistent))
        if is_https and not cookie.get("secure"):
            missing.append("Secure")
            evidence.append(_cookie_evidence("session_cookie_missing_secure", "Session management indicator: Secure missing", url, name, ["Secure"], "strong_indicator", "High", persistent))
        if not cookie.get("httponly"):
            missing.append("HttpOnly")
            evidence.append(_cookie_evidence("session_cookie_missing_httponly", "Session management indicator: HttpOnly missing", url, name, ["HttpOnly"], "strong_indicator", "High", persistent))
        if not cookie.get("samesite"):
            missing.append("SameSite")
            evidence.append(_cookie_evidence("session_cookie_missing_samesite", "Session management indicator: SameSite missing", url, name, ["SameSite"], "weak_indicator", "Medium", persistent))
        if str(cookie.get("samesite") or "").lower() == "none" and not cookie.get("secure"):
            evidence.append(_cookie_evidence("session_cookie_missing_secure", "Session management indicator: SameSite=None without Secure", url, name, ["Secure"], "strong_indicator", "High", persistent))
        if is_remember:
            evidence.append(_cookie_evidence("remember_me_cookie_detected", "Remember-me indicator", url, name, missing, "weak_indicator", "Medium", persistent))
        if persistent and is_session:
            evidence.append(_cookie_evidence("persistent_session_cookie_detected", "Persistent session management indicator", url, name, missing, "weak_indicator", "Medium", persistent))
        evidence.append(_cookie_evidence("auth_cookie_name_detected", "Authentication cookie name indicator", url, name, [], "informational", "Low", persistent))
    return evidence


def assess_auth_forms(url: str, forms: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for raw in forms or []:
        form = dict(raw)
        page_url = str(form.get("page_url") or form.get("url") or url)
        action = str(form.get("resolved_action_url") or form.get("action") or "")
        fields = _field_names(form)
        lower_fields = {field.lower() for field in fields}
        has_password = bool(form.get("has_password_field")) or any("password" in field for field in lower_fields)
        classification = str(form.get("classification") or "").lower()
        is_login = has_password or "login" in classification or "signin" in (action + page_url).lower()
        is_reset = "reset" in (action + page_url).lower() or "forgot" in (action + page_url).lower()
        csrf_fields = sorted(field for field in fields if field.lower() in CSRF_FIELD_NAMES or "csrf" in field.lower() or "xsrf" in field.lower())
        remember_fields = sorted(field for field in fields if "remember" in field.lower())
        if is_login:
            evidence.append(_form_evidence("login_form_detected", "Login workflow evidence", page_url, action, has_password, csrf_fields, remember_fields, "informational", "High"))
        if has_password:
            evidence.append(_form_evidence("password_field_detected", "Password field detected", page_url, action, has_password, csrf_fields, remember_fields, "informational", "High"))
        if is_login and urlsplit(page_url).scheme == "http":
            evidence.append(_form_evidence("auth_form_over_http", "Authentication form over HTTP", page_url, action, has_password, csrf_fields, remember_fields, "strong_indicator", "High"))
        if is_login and not csrf_fields:
            evidence.append(_form_evidence("auth_form_without_csrf_indicator", "Authentication form without CSRF-like field indicator", page_url, action, has_password, csrf_fields, remember_fields, "weak_indicator", "Medium"))
        if is_reset:
            evidence.append(_form_evidence("password_reset_form_detected", "Password reset workflow evidence", page_url, action, has_password, csrf_fields, remember_fields, "informational", "Medium"))
        if remember_fields or bool(form.get("remember_me")):
            evidence.append(_form_evidence("remember_me_checkbox_detected", "Remember-me checkbox indicator", page_url, action, has_password, csrf_fields, remember_fields, "weak_indicator", "Medium"))
    return evidence


def assess_password_reset_indicators(urls: list[str], parameter_results: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    all_urls = list(urls)
    for item in parameter_results or []:
        url = str(item.get("url") or item.get("normalised_url") or "")
        if url:
            all_urls.append(url)
    for url in dict.fromkeys(all_urls):
        parsed = urlsplit(str(url or ""))
        lower_path = parsed.path.lower()
        is_reset = any(marker in lower_path for marker in ("reset-password", "password-reset", "forgot-password"))
        if is_reset and parsed.scheme == "http":
            evidence.append(_evidence(rule_id="password_reset_endpoint_over_http", rule_group="password_reset_workflow_indicators", title="Password reset endpoint over HTTP", affected_url=url, affected_parameter="", confidence="High", evidence_strength="strong_indicator", observed_value="Password reset path over HTTP", safe_evidence_summary="Password reset workflow endpoint was observed over HTTP.", recommendation="Serve password reset workflows only over HTTPS."))
        for name, _value in parse_qsl(parsed.query, keep_blank_values=True):
            lower = name.lower()
            if lower in RESET_TOKEN_PARAMETERS:
                evidence.append(_evidence(rule_id="reset_token_parameter_detected", rule_group="password_reset_workflow_indicators", title="Password reset token parameter indicator", affected_url=_redact_url_query_values(url), affected_parameter=name, confidence="High", evidence_strength="strong_indicator", observed_value=f"parameter={name}; value=[REDACTED]", safe_evidence_summary="Reset/token-like parameter name was observed in a URL. Parameter value was not stored.", recommendation="Manually review token handling, expiration, single-use behaviour, and URL exposure."))
                evidence.append(_evidence(rule_id="token_in_url_indicator", rule_group="password_reset_workflow_indicators", title="Token in URL indicator", affected_url=_redact_url_query_values(url), affected_parameter=name, confidence="High", evidence_strength="strong_indicator", observed_value=f"parameter={name}; value=[REDACTED]", safe_evidence_summary="Token-like parameter was observed in the URL query string. Parameter value was not stored.", recommendation="Avoid exposing sensitive tokens in URLs where possible and manually validate workflow controls."))
            if lower in {"jwt", "id_token", "access_token", "refresh_token"}:
                evidence.append(_evidence(rule_id="jwt_parameter_detected", rule_group="auth_protocol_indicators", title="JWT-like parameter indicator", affected_url=_redact_url_query_values(url), affected_parameter=name, confidence="Medium", evidence_strength="informational", observed_value=f"parameter={name}; value=[REDACTED]", safe_evidence_summary="JWT/token-like parameter name was observed. Parameter value was not stored.", recommendation="Manually review token handling and exposure."))
    return evidence


def assess_rate_limit_headers(url: str, headers: dict[str, Any] | None, endpoint_category: str = "") -> list[dict[str, Any]]:
    if not _is_auth_url(url) and endpoint_category not in {"login", "authentication"}:
        return []
    normalised = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    present = sorted(header for header in RATE_LIMIT_HEADERS if header in normalised)
    evidence: list[dict[str, Any]] = []
    if present:
        evidence.append(_evidence(rule_id="rate_limit_headers_present", rule_group="rate_limit_indicators", title="Rate-limit header indicator", affected_url=url, confidence="Medium", evidence_strength="informational", observed_value=", ".join(present), safe_evidence_summary="Rate-limit header metadata was present. No rate-limit testing was performed.", recommendation="Manually review authentication rate limiting and account lockout controls."))
    else:
        evidence.append(_evidence(rule_id="login_endpoint_without_rate_limit_headers" if _is_login_url(url) else "rate_limit_headers_missing", rule_group="rate_limit_indicators", title="Rate-limit header indicator missing", affected_url=url, confidence="Low", evidence_strength="weak_indicator" if _is_login_url(url) else "informational", observed_value="No rate-limit headers observed in supplied metadata", safe_evidence_summary="Rate-limit headers were not observed in available metadata. No rate-limit testing was performed.", recommendation="Manually review authentication rate limiting and account lockout controls."))
    if "retry-after" in normalised:
        evidence.append(_evidence(rule_id="retry_after_header_present", rule_group="rate_limit_indicators", title="Retry-After header indicator", affected_url=url, confidence="Medium", evidence_strength="informational", observed_value="Retry-After present", safe_evidence_summary="Retry-After header metadata was present. No rate-limit testing was performed.", recommendation="Review retry behaviour and rate limiting in authentication workflows."))
    return evidence


def assess_auth_protocol_surface(urls: list[str]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for url in urls:
        lower = str(url or "").lower()
        if "callback" in lower and "oauth" in lower:
            evidence.append(_protocol_evidence("oauth_callback_detected", "OAuth callback indicator", url))
        if "/.well-known/openid-configuration" in lower:
            evidence.append(_protocol_evidence("oidc_well_known_detected", "OIDC well-known indicator", url))
        if "saml" in lower:
            evidence.append(_protocol_evidence("saml_endpoint_detected", "SAML endpoint indicator", url))
    return evidence


def build_a07_summary(target: str, evidence: list[dict[str, Any]]) -> dict[str, Any]:
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
        "auth_endpoint_count": group_counts.get("auth_endpoint_discovery", 0),
        "login_form_count": sum(1 for item in evidence if item.get("rule_id") == "login_form_detected"),
        "password_reset_endpoint_count": sum(1 for item in evidence if item.get("rule_id") in {"password_reset_endpoint_detected", "forgot_password_endpoint_detected", "password_reset_form_detected"}),
        "session_cookie_indicator_count": group_counts.get("session_cookie_indicators", 0),
        "remember_me_indicator_count": sum(1 for item in evidence if item.get("rule_id") in {"remember_me_cookie_detected", "remember_me_checkbox_detected"}),
        "csrf_indicator_count": sum(1 for item in evidence if item.get("rule_id") == "auth_form_without_csrf_indicator"),
        "rate_limit_indicator_count": group_counts.get("rate_limit_indicators", 0),
        "protocol_surface_indicator_count": group_counts.get("auth_protocol_indicators", 0),
        "rule_group_counts": dict(group_counts),
        "highest_confidence": highest if evidence else "Low",
        "top_risks": _top_risks(evidence),
        "recommendations": _recommendations(evidence),
        "limitations": list(LIMITATIONS),
    }


def build_a07_findings(summary: dict[str, Any], evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = [
        finding_to_dict(create_finding(title="A07 Authentication Assessment Completed", severity="Informational", category="OWASP A07 Authentication Failures", affected_host=str(summary.get("target") or "a07-assessment"), evidence="VulScan evaluated available authentication endpoint, cookie, form, reset-flow, and rate-limit header evidence.", recommendation="Review A07 evidence and manually validate authentication workflow controls.", source="owasp_a07", confidence="High", impact="A07 evidence supports manual authentication and session management review.", verification="Review a07_authentication_summary and a07_authentication_evidence.", limitation="A07 checks are indicator-based and do not perform login attempts or brute force."))
    ]
    if any(item.get("rule_group") in {"auth_endpoint_discovery", "auth_form_indicators"} for item in evidence):
        findings.append(finding_to_dict(create_finding(title="Authentication Surface Indicators", severity="Informational", category="OWASP A07 Authentication Failures", affected_host=str(summary.get("target") or ""), evidence="Authentication-related endpoints or forms were discovered.", recommendation="Review authentication flows for secure design and session handling.", source="owasp_a07", confidence="Medium", impact="Authentication surfaces require manual workflow review.", verification="Review authentication endpoint and form evidence.", limitation="Endpoint discovery does not indicate a vulnerability by itself.")))
    if any(item.get("rule_group") == "session_cookie_indicators" and item.get("evidence_strength") != "informational" for item in evidence):
        strong = any(item.get("evidence_strength") == "strong_indicator" for item in evidence if item.get("rule_group") == "session_cookie_indicators")
        findings.append(finding_to_dict(create_finding(title="Session Cookie Security Indicator", severity="Medium" if strong else "Low", category="OWASP A07 Authentication Failures", affected_host=str(summary.get("target") or ""), evidence="Session-like cookies may be missing recommended security attributes.", recommendation="Configure Secure, HttpOnly, and SameSite attributes as appropriate.", source="owasp_a07", confidence="Medium", impact="Cookie/session attributes support session management controls.", verification="Review cookie/session evidence.", limitation="Cookie purpose must be manually verified.")))
    if any(item.get("rule_group") == "password_reset_workflow_indicators" for item in evidence):
        strong = any(item.get("evidence_strength") == "strong_indicator" for item in evidence if item.get("rule_group") == "password_reset_workflow_indicators")
        findings.append(finding_to_dict(create_finding(title="Password Reset Workflow Indicator", severity="Low" if strong else "Informational", category="OWASP A07 Authentication Failures", affected_host=str(summary.get("target") or ""), evidence="Password reset or token-related workflow indicators were observed.", recommendation="Manually review token handling, expiration, single-use behaviour, and rate limiting.", source="owasp_a07", confidence="Medium", impact="Password reset workflows require careful manual review.", verification="Review password reset workflow evidence.", limitation="No token exploitation or reset attempt was performed.")))
    return findings


def _evidence(*, rule_id: str, rule_group: str, title: str, affected_url: str, confidence: str, evidence_strength: str, observed_value: str, safe_evidence_summary: str, recommendation: str, affected_parameter: str = "", manual_validation_required: bool = True, source: str = "owasp_a07", extra: dict[str, Any] | None = None) -> dict[str, Any]:
    item = {
        "evidence_id": "",
        "rule_id": rule_id,
        "rule_group": rule_group,
        "title": title,
        "affected_url": _redact_url_query_values(affected_url),
        "affected_host": urlsplit(str(affected_url or "")).netloc,
        "affected_parameter": affected_parameter,
        "evidence_strength": evidence_strength,
        "confidence": confidence,
        "observed_value": observed_value,
        "safe_evidence_summary": safe_evidence_summary,
        "recommendation": recommendation,
        "manual_validation_required": manual_validation_required,
        "source": source,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if extra:
        item.update(extra)
    item["evidence_id"] = "a07_ev_" + hashlib.sha256("|".join(str(item.get(key) or "") for key in ("rule_id", "affected_url", "affected_parameter", "observed_value")).encode("utf-8")).hexdigest()[:16]
    return redact_nested(item)


def _cookie_evidence(rule_id: str, title: str, url: str, cookie_name: str, missing: list[str], strength: str, confidence: str, persistent: bool) -> dict[str, Any]:
    return _evidence(rule_id=rule_id, rule_group="session_cookie_indicators", title=title, affected_url=url, confidence=confidence, evidence_strength=strength, observed_value=f"cookie_name={cookie_name}; missing_attributes={','.join(missing)}; value=[REDACTED]", safe_evidence_summary=f"Cookie/session evidence for {cookie_name}. Cookie value was not stored.", recommendation="Configure Secure, HttpOnly, and SameSite attributes according to cookie purpose and manually review session behaviour.", extra={"cookie_name": cookie_name, "missing_attributes": missing, "persistence_indicator": persistent})


def _form_evidence(rule_id: str, title: str, page_url: str, action: str, has_password: bool, csrf_fields: list[str], remember_fields: list[str], strength: str, confidence: str) -> dict[str, Any]:
    return _evidence(rule_id=rule_id, rule_group="auth_form_indicators", title=title, affected_url=page_url, confidence=confidence, evidence_strength=strength, observed_value=f"password_field_detected={has_password}; csrf_like_fields={','.join(csrf_fields)}; hidden_values=[REDACTED]", safe_evidence_summary="Authentication form metadata was observed. Forms were not submitted and field values were not stored.", recommendation="Manually review login workflow evidence, CSRF controls, remember-me behaviour, and session handling.", extra={"form_action_scheme": urlsplit(action).scheme or urlsplit(page_url).scheme, "password_field_detected": has_password, "csrf_like_field_detected": bool(csrf_fields), "csrf_like_field_names": csrf_fields, "remember_me_checkbox": bool(remember_fields)})


def _protocol_evidence(rule_id: str, title: str, url: str) -> dict[str, Any]:
    return _evidence(rule_id=rule_id, rule_group="auth_protocol_indicators", title=title, affected_url=url, confidence="Medium", evidence_strength="informational", observed_value=title, safe_evidence_summary="Authentication protocol surface indicator observed. This is not a vulnerability by default.", recommendation="Manually review protocol configuration, redirect URIs, token handling, and session integration.")


def _collect_urls(target: str, urls: list[str] | None = None, crawled_pages: list[dict[str, Any]] | None = None, endpoint_results: list[dict[str, Any]] | None = None, parameter_results: list[dict[str, Any]] | None = None, validation_results: list[dict[str, Any]] | None = None) -> list[str]:
    collected = [target] if target else []
    collected.extend(str(url) for url in urls or [] if str(url))
    collected.extend(str(page.get("url") or "") for page in crawled_pages or [] if page.get("url"))
    for item in endpoint_results or []:
        collected.append(str(item.get("normalised_url") or item.get("url") or item.get("path") or ""))
    for item in parameter_results or []:
        collected.append(str(item.get("url") or item.get("normalised_url") or ""))
    for item in validation_results or []:
        collected.append(str(item.get("url") or ""))
    return [url for url in dict.fromkeys(collected) if urlsplit(url).scheme in {"http", "https"} or url.startswith("/")]


def _collect_forms(crawled_pages: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    forms: list[dict[str, Any]] = []
    for page in crawled_pages or []:
        for form in page.get("forms") or []:
            item = dict(form)
            item.setdefault("page_url", page.get("url") or "")
            forms.append(item)
    return forms


def _headers_for_url(url: str, crawled_pages: list[dict[str, Any]] | None) -> dict[str, Any]:
    for page in crawled_pages or []:
        if str(page.get("url") or "") == url:
            return dict(page.get("response_headers") or {})
    return {}


def _endpoint_type_and_rule(url: str) -> tuple[str, str]:
    path = urlsplit(str(url or "")).path.lower()
    full = str(url or "").lower()
    if "/.well-known/openid-configuration" in path:
        return "oidc_well_known", "oauth_oidc_endpoint_detected"
    checks = [
        ("forgot_password", "forgot_password_endpoint_detected", ("forgot-password", "forgot_password")),
        ("password_reset", "password_reset_endpoint_detected", ("reset-password", "password-reset", "password_reset")),
        ("login", "login_endpoint_detected", ("/login",)),
        ("signin", "signin_endpoint_detected", ("signin", "sign-in")),
        ("auth_callback", "auth_callback_endpoint_detected", ("callback",)),
        ("logout", "logout_endpoint_detected", ("logout",)),
        ("registration", "registration_endpoint_detected", ("register", "signup", "sign-up")),
        ("mfa", "mfa_endpoint_detected", ("mfa", "2fa")),
        ("oauth_oidc", "oauth_oidc_endpoint_detected", ("oauth", "oidc", "openid")),
        ("saml", "saml_endpoint_detected", ("saml",)),
        ("authentication", "login_endpoint_detected", ("authenticate", "/auth", "/session")),
    ]
    for endpoint_type, rule_id, needles in checks:
        if any(needle in full for needle in needles):
            return endpoint_type, rule_id
    return "", ""


def _endpoint_type_for_url(url: str) -> str:
    return _endpoint_type_and_rule(url)[0]


def _is_auth_url(url: str) -> bool:
    return bool(_endpoint_type_and_rule(url)[1])


def _is_login_url(url: str) -> bool:
    return _endpoint_type_and_rule(url)[0] in {"login", "signin", "authentication"}


def _session_like_cookie(name: str) -> bool:
    if name == "csrftoken":
        return False
    return any(hint in name for hint in SESSION_COOKIE_HINTS)


def _field_names(form: dict[str, Any]) -> list[str]:
    names = [str(name) for name in form.get("input_names") or [] if str(name)]
    for field in form.get("input_fields") or []:
        name = str(field.get("name") or field.get("id") or "")
        if name:
            names.append(name)
    return list(dict.fromkeys(names))


def _redact_url_query_values(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    if not parsed.query:
        return str(url or "")
    redacted = "&".join(f"{name}=[REDACTED]" for name, _value in parse_qsl(parsed.query, keep_blank_values=True))
    return parsed._replace(query=redacted).geturl()


def _dedupe_evidence(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    order = {"informational": 1, "weak_indicator": 2, "strong_indicator": 3, "confirmed_finding": 4}
    for item in items:
        key = (str(item.get("rule_id")), str(item.get("affected_url")), str(item.get("affected_parameter")), str(item.get("observed_value")))
        existing = by_key.get(key)
        if not existing or order.get(str(item.get("evidence_strength")), 0) > order.get(str(existing.get("evidence_strength")), 0):
            by_key[key] = item
    return list(by_key.values())


def _top_risks(evidence: list[dict[str, Any]]) -> list[str]:
    return [str(item.get("title") or "") for item in evidence if item.get("evidence_strength") in {"strong_indicator", "confirmed_finding"}][:5]


def _recommendations(evidence: list[dict[str, Any]]) -> list[str]:
    defaults = [
        "Review login controls manually.",
        "Review password reset flow manually.",
        "Review session cookie attributes.",
        "Review remember-me behaviour.",
        "Review MFA/2FA if present.",
        "Review account lockout and rate limiting manually.",
        "Review token exposure in URLs.",
        "Review logout and session invalidation manually.",
    ]
    seen: list[str] = []
    for item in evidence:
        rec = str(item.get("recommendation") or "")
        if rec and rec not in seen:
            seen.append(rec)
    return seen[:8] or defaults


def _first_url(urls: list[str]) -> str:
    return urls[0] if urls else ""
