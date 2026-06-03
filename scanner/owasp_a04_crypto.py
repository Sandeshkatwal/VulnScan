"""A04 Cryptographic Failures evidence collection.

All checks are safe, metadata-oriented indicators. The module does not submit
forms, fetch external mixed-content resources, collect cookie values, or test
TLS ciphers/protocol downgrade behaviour.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from scanner.evidence import redact_nested
from scanner.finding import create_finding, finding_to_dict
from scanner.tls_metadata import get_tls_certificate_metadata
from scanner.web_cookie_audit import parse_set_cookie_headers


A04_RULES_PATH = Path("data") / "owasp" / "a04" / "a04_rules.json"
A04_REPORTS_DIR = Path("reports") / "owasp" / "a04"
HSTS_MIN_MAX_AGE = 15552000
SENSITIVE_PATH_KEYWORDS = {
    "login", "signin", "auth", "account", "reset-password", "forgot-password",
    "password", "token", "checkout", "payment", "billing", "profile",
}
SENSITIVE_PARAMETER_NAMES = {
    "password", "token", "access_token", "refresh_token", "code", "session",
    "auth", "jwt", "key", "secret",
}
SESSION_COOKIE_HINTS = {"session", "sid", "sess", "auth", "token", "jwt", "remember", "login", "user"}
LIMITATIONS = [
    "A04 checks are evidence-based and may require manual validation.",
    "Cookie values, secrets, tokens, passwords, private keys, and full response bodies are not stored.",
    "TLS metadata collection performs a normal certificate handshake only and does not test weak ciphers, protocol downgrade behaviour, or exploitation.",
    "Mixed content checks use supplied snippets or crawler-discovered metadata only and do not fetch external assets.",
]


class A04RulesError(ValueError):
    """Raised when A04 rules are unavailable or invalid."""


def load_a04_rules(path: str | Path = A04_RULES_PATH) -> dict[str, Any]:
    rules_path = Path(path)
    try:
        payload = json.loads(rules_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise A04RulesError(f"A04 rules file was not found: {rules_path}") from exc
    except json.JSONDecodeError as exc:
        raise A04RulesError(f"A04 rules file is not valid JSON: {rules_path}") from exc
    if payload.get("owasp_id") != "A04:2025":
        raise A04RulesError("A04 rules file must describe A04:2025.")
    if not isinstance(payload.get("rule_groups"), dict):
        raise A04RulesError("A04 rules file must include rule_groups.")
    return payload


def ensure_a04_dirs() -> None:
    A04_RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    A04_REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def assess_a04_crypto(
    *,
    target: str = "",
    urls: list[str] | None = None,
    headers: dict[str, Any] | None = None,
    set_cookie_headers: list[str] | None = None,
    forms: list[dict[str, Any]] | None = None,
    html_snippet: str = "",
    crawled_pages: list[dict[str, Any]] | None = None,
    endpoint_results: list[dict[str, Any]] | None = None,
    parameter_results: list[dict[str, Any]] | None = None,
    validation_results: list[dict[str, Any]] | None = None,
    tls_metadata: list[dict[str, Any]] | dict[str, Any] | None = None,
    collect_tls: bool = True,
) -> dict[str, Any]:
    """Build A04 summary, evidence, metadata, and grouped findings."""
    ensure_a04_dirs()
    load_a04_rules()
    url_list = _collect_urls(target, urls, crawled_pages, endpoint_results, parameter_results, validation_results)
    evidence: list[dict[str, Any]] = []
    for url in url_list:
        evidence.extend(assess_transport_security(url, {}))
        if urlsplit(url).scheme == "https":
            page_headers = _headers_for_url(url, crawled_pages) or headers or {}
            evidence.extend(assess_hsts(url, page_headers))
    if target and headers and urlsplit(target).scheme == "https" and target not in url_list:
        evidence.extend(assess_hsts(target, headers))

    cookie_inputs = list(set_cookie_headers or [])
    for page in crawled_pages or []:
        for cookie in page.get("cookies") or []:
            evidence.extend(assess_cookie_security(str(page.get("url") or target), parsed_cookies=[dict(cookie)]))
    if cookie_inputs:
        evidence.extend(assess_cookie_security(target or _first_url(url_list), set_cookie_headers=cookie_inputs))

    for form in forms or _collect_forms(crawled_pages):
        evidence.extend(assess_form_security(dict(form)))
    for page in crawled_pages or []:
        snippet = str(page.get("html_snippet") or page.get("limited_html") or "")
        if snippet:
            evidence.extend(assess_mixed_content(str(page.get("url") or target), snippet))
    if html_snippet:
        evidence.extend(assess_mixed_content(target or _first_url(url_list), html_snippet))

    tls_items = _normalise_tls_metadata(tls_metadata)
    if collect_tls:
        for host in _https_hosts(url_list or [target]):
            if not any(item.get("host") == host for item in tls_items):
                tls_items.append(get_tls_certificate_metadata(host))
    for item in tls_items:
        evidence.extend(assess_tls_metadata(item))

    evidence = _dedupe_evidence(evidence)
    summary = build_a04_summary(target=target or _first_url(url_list), urls=url_list, evidence=evidence, tls_metadata=tls_items)
    findings = build_a04_findings(summary, evidence)
    return redact_nested(
        {
            "a04_crypto_summary": summary,
            "a04_crypto_evidence": evidence,
            "a04_tls_metadata": tls_items,
            "findings": findings,
        }
    )


def attach_a04_crypto(scan_result: dict[str, Any], *, collect_tls: bool = True) -> dict[str, Any]:
    target = str(scan_result.get("target") or scan_result.get("url") or "")
    if not target:
        pages = scan_result.get("crawled_pages") or []
        target = str((pages[0] or {}).get("url") if pages else scan_result.get("host") or "")
    payload = assess_a04_crypto(
        target=target,
        urls=_collect_urls(target, scan_result.get("urls"), scan_result.get("crawled_pages"), scan_result.get("endpoint_results"), scan_result.get("parameter_results"), scan_result.get("safe_active_validation_results")),
        crawled_pages=scan_result.get("crawled_pages") or [],
        forms=scan_result.get("web_form_results") or scan_result.get("discovered_forms") or [],
        endpoint_results=scan_result.get("endpoint_results") or [],
        parameter_results=scan_result.get("parameter_results") or [],
        validation_results=scan_result.get("safe_active_validation_results") or [],
        tls_metadata=scan_result.get("a04_tls_metadata"),
        collect_tls=collect_tls,
    )
    a04_findings = list(payload.get("findings", []))
    payload_without_findings = dict(payload)
    payload_without_findings.pop("findings", None)
    scan_result.update(payload_without_findings)
    scan_result.setdefault("findings", [])
    scan_result["findings"].extend(a04_findings)
    return scan_result


def assess_transport_security(url: str, response_metadata: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    parsed = urlsplit(str(url or ""))
    if parsed.scheme != "http":
        return []
    evidence = [
        _evidence(
            rule_id="http_url_detected",
            rule_group="transport_security",
            title="Cleartext transport indicator",
            affected_url=url,
            scheme=parsed.scheme,
            evidence_strength="weak_indicator",
            confidence="Medium",
            observed_value="HTTP URL observed",
            safe_evidence_summary="HTTP URL was observed in available assessment evidence.",
            recommendation="Enforce HTTPS and redirect HTTP to HTTPS where appropriate.",
        )
    ]
    sensitive_params = [name for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name.lower() in SENSITIVE_PARAMETER_NAMES]
    if sensitive_params:
        rule_id = "token_parameter_over_http" if any(name.lower() in {"token", "access_token", "refresh_token", "jwt"} for name in sensitive_params) else "sensitive_parameter_over_http"
        evidence.append(
            _evidence(
                rule_id=rule_id,
                rule_group="cleartext_sensitive_workflows" if rule_id == "token_parameter_over_http" else "transport_security",
                title="Sensitive data over cleartext indicator",
                affected_url=_redact_url_query_values(url),
                scheme="http",
                evidence_strength="strong_indicator",
                confidence="High",
                observed_value="Sensitive parameter name over HTTP: " + ", ".join(sorted(set(sensitive_params))),
                safe_evidence_summary="Sensitive-looking parameter name was observed on an HTTP URL. Parameter values were not stored.",
                recommendation="Avoid sensitive data in URLs and enforce HTTPS for sensitive workflows.",
            )
        )
    path_hit = _sensitive_path_keyword(parsed.path)
    if path_hit:
        rule_id = "reset_password_over_http" if "reset" in path_hit or "password" in path_hit else ("account_endpoint_over_http" if path_hit in {"account", "profile"} else "https_not_used")
        evidence.append(
            _evidence(
                rule_id=rule_id,
                rule_group="cleartext_sensitive_workflows" if rule_id != "https_not_used" else "transport_security",
                title="Sensitive endpoint over cleartext indicator",
                affected_url=_redact_url_query_values(url),
                scheme="http",
                evidence_strength="strong_indicator",
                confidence="Medium",
                observed_value=f"Sensitive path keyword over HTTP: {path_hit}",
                safe_evidence_summary="Sensitive-looking path was observed on an HTTP URL.",
                recommendation="Serve sensitive workflows only over HTTPS.",
            )
        )
    redirects_to_https = (response_metadata or {}).get("redirects_to_https")
    if redirects_to_https is False:
        evidence.append(
            _evidence(
                rule_id="http_to_https_redirect_missing",
                rule_group="transport_security",
                title="HTTP to HTTPS redirect missing",
                affected_url=_redact_url_query_values(url),
                scheme="http",
                evidence_strength="weak_indicator",
                confidence="Low",
                observed_value="HTTP response did not redirect to HTTPS in supplied metadata",
                safe_evidence_summary="Supplied HTTP redirect metadata did not indicate an HTTPS redirect.",
                recommendation="Redirect HTTP requests to the HTTPS origin when compatible with the application.",
            )
        )
    return evidence


def assess_hsts(url: str, headers: dict[str, Any] | None) -> list[dict[str, Any]]:
    if urlsplit(str(url or "")).scheme != "https":
        return []
    normalised = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    hsts = normalised.get("strict-transport-security", "")
    if not hsts:
        return [
            _evidence(
                rule_id="missing_hsts",
                rule_group="hsts",
                title="Transport security indicator: HSTS missing",
                affected_url=url,
                scheme="https",
                evidence_strength="weak_indicator",
                confidence="Medium",
                observed_value="Strict-Transport-Security header missing",
                safe_evidence_summary="HTTPS response metadata did not include Strict-Transport-Security.",
                recommendation="Configure HSTS after confirming HTTPS is consistently available.",
            )
        ]
    items: list[dict[str, Any]] = []
    max_age = _hsts_max_age(hsts)
    if max_age is None or max_age < HSTS_MIN_MAX_AGE:
        items.append(_evidence(rule_id="hsts_max_age_low", rule_group="hsts", title="Transport security indicator: HSTS max-age low", affected_url=url, scheme="https", evidence_strength="weak_indicator", confidence="Medium", observed_value=f"max-age={max_age if max_age is not None else 'missing'}", safe_evidence_summary="HSTS max-age was missing, invalid, or lower than the recommended threshold.", recommendation="Set an HSTS max-age appropriate to the application after HTTPS readiness review."))
    lower = hsts.lower()
    if "includesubdomains" not in lower:
        items.append(_evidence(rule_id="hsts_include_subdomains_missing", rule_group="hsts", title="HSTS includeSubDomains not present", affected_url=url, scheme="https", evidence_strength="informational", confidence="Low", observed_value="includeSubDomains missing", safe_evidence_summary="HSTS includeSubDomains was not present. This is contextual and not automatically a vulnerability.", recommendation="Consider includeSubDomains only after confirming all subdomains support HTTPS."))
    if "preload" not in lower:
        items.append(_evidence(rule_id="hsts_preload_missing", rule_group="hsts", title="HSTS preload not present", affected_url=url, scheme="https", evidence_strength="informational", confidence="Low", observed_value="preload missing", safe_evidence_summary="HSTS preload was not present. This is contextual and not required for every site.", recommendation="Consider preload only when the domain intentionally meets preload requirements."))
    return items


def assess_cookie_security(url: str, set_cookie_headers: list[str] | None = None, parsed_cookies: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
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
        missing: list[str] = []
        if is_https and not cookie.get("secure"):
            missing.append("Secure")
            evidence.append(_cookie_evidence("secure_missing", "Cookie security evidence: Secure missing", url, name, ["Secure"], "weak_indicator", "Medium"))
        if not cookie.get("httponly"):
            missing.append("HttpOnly")
            evidence.append(_cookie_evidence("httponly_missing", "Cookie security evidence: HttpOnly missing", url, name, ["HttpOnly"], "weak_indicator", "Medium"))
        if not cookie.get("samesite"):
            missing.append("SameSite")
            evidence.append(_cookie_evidence("samesite_missing", "Cookie security evidence: SameSite missing", url, name, ["SameSite"], "informational", "Low"))
        if str(cookie.get("samesite") or "").lower() == "none" and not cookie.get("secure"):
            evidence.append(_cookie_evidence("samesite_none_without_secure", "Cookie security evidence: SameSite=None without Secure", url, name, ["Secure"], "weak_indicator", "Medium"))
        if _session_like_cookie(lower) and any(attr in missing for attr in ("Secure", "HttpOnly")):
            evidence.append(_cookie_evidence("session_cookie_insecure", "Cookie security evidence: session-like cookie missing recommended attributes", url, name, missing, "strong_indicator", "High"))
        if _sensitive_cookie_name(lower):
            evidence.append(_cookie_evidence("sensitive_cookie_name_detected", "Cookie security evidence: sensitive-looking cookie name", url, name, [], "weak_indicator", "Low"))
    return evidence


def assess_form_security(form: dict[str, Any]) -> list[dict[str, Any]]:
    page_url = str(form.get("page_url") or form.get("url") or "")
    action = str(form.get("resolved_action_url") or form.get("action") or "")
    classification = str(form.get("classification") or "")
    evidence: list[dict[str, Any]] = []
    if urlsplit(page_url).scheme == "http" and (form.get("has_password_field") or classification == "login_form"):
        evidence.append(_evidence(rule_id="login_form_over_http", rule_group="transport_security", title="Cleartext form submission indicator", affected_url=page_url, affected_host=urlsplit(page_url).netloc, scheme="http", evidence_strength="strong_indicator", confidence="High", observed_value="Login/password form on HTTP page", safe_evidence_summary="Password field or login form indicator was observed on an HTTP page. The form was not submitted.", recommendation="Serve login and password workflows only over HTTPS."))
        evidence.append(_evidence(rule_id="password_field_on_http_page", rule_group="cleartext_sensitive_workflows", title="Password field on HTTP page", affected_url=page_url, affected_host=urlsplit(page_url).netloc, scheme="http", evidence_strength="strong_indicator", confidence="High", observed_value="Password field on HTTP page", safe_evidence_summary="Password field metadata was observed on an HTTP page. Values were not captured.", recommendation="Serve password fields only over HTTPS."))
    if action and urlsplit(action).scheme == "http":
        rule = "http_form_action_on_https_page" if urlsplit(page_url).scheme == "https" else "form_action_over_http"
        group = "mixed_content_indicators" if rule.startswith("http_form") else "transport_security"
        evidence.append(_evidence(rule_id=rule, rule_group=group, title="Cleartext form submission indicator", affected_url=page_url or action, affected_host=urlsplit(page_url or action).netloc, scheme=urlsplit(page_url or action).scheme, evidence_strength="strong_indicator", confidence="High", observed_value="HTTP form action observed", safe_evidence_summary="Form action points to HTTP. The form was not submitted.", recommendation="Use HTTPS form actions for sensitive and state-changing workflows."))
    return evidence


def assess_mixed_content(url: str, limited_html_or_links: str) -> list[dict[str, Any]]:
    if urlsplit(str(url or "")).scheme != "https":
        return []
    html = str(limited_html_or_links or "")[:20000]
    patterns = [
        ("script", "src", "http_script_source_on_https_page", "strong_indicator", "High"),
        ("iframe", "src", "http_script_source_on_https_page", "strong_indicator", "High"),
        ("link", "href", "http_stylesheet_source_on_https_page", "weak_indicator", "Medium"),
        ("img", "src", "http_image_source_on_https_page", "weak_indicator", "Low"),
        ("form", "action", "http_form_action_on_https_page", "strong_indicator", "High"),
    ]
    evidence: list[dict[str, Any]] = []
    for tag, attr, rule_id, strength, confidence in patterns:
        regex = re.compile(rf"<{tag}\b[^>]*\b{attr}\s*=\s*['\"](http://[^'\"]+)['\"]", re.IGNORECASE)
        for match in regex.finditer(html):
            resource = match.group(1)[:240]
            if tag == "link" and "stylesheet" not in match.group(0).lower():
                continue
            evidence.append(_evidence(rule_id=rule_id, rule_group="mixed_content_indicators", title=f"Mixed content indicator: HTTP {tag}", affected_url=url, affected_host=urlsplit(url).netloc, scheme="https", evidence_strength=strength, confidence=confidence, observed_value=f"{tag} references HTTP resource: {resource}", safe_evidence_summary=f"HTTPS page references an HTTP {tag} resource. External assets were not fetched.", recommendation="Load page resources and form actions over HTTPS.", extra={"resource_type": tag, "resource_scheme": "http"}))
    return evidence


def assess_tls_metadata(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    if not metadata:
        return []
    host = str(metadata.get("host") or "")
    if not metadata.get("metadata_available"):
        return []
    evidence = [
        _evidence(rule_id="issuer_subject_metadata", rule_group="tls_certificate_metadata", title="TLS metadata", affected_url=f"https://{host}/" if host else "", affected_host=host, scheme="https", evidence_strength="informational", confidence="High", observed_value=f"Issuer={metadata.get('issuer_common_name') or ''}; Subject={metadata.get('subject_common_name') or ''}", safe_evidence_summary="TLS certificate issuer and subject metadata collected.", recommendation="Review TLS metadata in the certificate lifecycle process.", manual_validation_required=False)
    ]
    if metadata.get("expired") is True:
        evidence.append(_evidence(rule_id="certificate_expired", rule_group="tls_certificate_metadata", title="TLS certificate expired", affected_url=f"https://{host}/", affected_host=host, scheme="https", evidence_strength="strong_indicator", confidence="High", observed_value=str(metadata.get("not_after") or ""), safe_evidence_summary="TLS certificate metadata indicates the certificate is expired.", recommendation="Renew and deploy a valid TLS certificate."))
    elif isinstance(metadata.get("days_until_expiry"), int) and int(metadata["days_until_expiry"]) <= 30:
        evidence.append(_evidence(rule_id="certificate_near_expiry", rule_group="tls_certificate_metadata", title="TLS certificate near expiry", affected_url=f"https://{host}/", affected_host=host, scheme="https", evidence_strength="weak_indicator", confidence="Medium", observed_value=f"days_until_expiry={metadata.get('days_until_expiry')}", safe_evidence_summary="TLS certificate metadata indicates near-term expiry.", recommendation="Renew the TLS certificate before expiry."))
    if metadata.get("hostname_match") is False:
        evidence.append(_evidence(rule_id="hostname_mismatch", rule_group="tls_certificate_metadata", title="TLS certificate hostname mismatch", affected_url=f"https://{host}/", affected_host=host, scheme="https", evidence_strength="strong_indicator", confidence="High", observed_value="hostname_match=false", safe_evidence_summary="TLS certificate metadata indicates the hostname did not match.", recommendation="Deploy a certificate whose names match the assessed host."))
    if metadata.get("self_signed_indicator") is True:
        evidence.append(_evidence(rule_id="self_signed_indicator", rule_group="tls_certificate_metadata", title="Self-signed certificate indicator", affected_url=f"https://{host}/", affected_host=host, scheme="https", evidence_strength="weak_indicator", confidence="Medium", observed_value="issuer equals subject", safe_evidence_summary="TLS certificate issuer and subject common names match, which may indicate a self-signed certificate.", recommendation="Use a certificate chain trusted by intended clients unless a self-signed certificate is expected."))
    evidence.append(_evidence(rule_id="certificate_validity_days", rule_group="tls_certificate_metadata", title="TLS certificate validity days", affected_url=f"https://{host}/", affected_host=host, scheme="https", evidence_strength="informational", confidence="High", observed_value=f"days_until_expiry={metadata.get('days_until_expiry')}", safe_evidence_summary="TLS certificate validity period metadata collected.", recommendation="Monitor certificate expiry and renewal workflows.", manual_validation_required=False))
    return evidence


def build_a04_summary(target: str, urls: list[str], evidence: list[dict[str, Any]], tls_metadata: list[dict[str, Any]] | None = None) -> dict[str, Any]:
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
        "rule_group_counts": dict(group_counts),
        "https_urls_count": sum(1 for url in set(urls) if urlsplit(url).scheme == "https"),
        "http_urls_count": sum(1 for url in set(urls) if urlsplit(url).scheme == "http"),
        "insecure_cookie_count": sum(1 for item in evidence if item.get("rule_group") == "cookie_security" and item.get("evidence_strength") != "informational"),
        "hsts_issue_count": group_counts.get("hsts", 0),
        "mixed_content_indicator_count": group_counts.get("mixed_content_indicators", 0),
        "tls_metadata_available": any(item.get("metadata_available") for item in tls_metadata or []),
        "highest_confidence": highest if evidence else "Low",
        "top_risks": _top_risks(evidence),
        "recommendations": _recommendations(evidence),
        "limitations": list(LIMITATIONS),
    }


def build_a04_findings(summary: dict[str, Any], evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = [
        finding_to_dict(create_finding(title="A04 Cryptographic Failures Assessment Completed", severity="Informational", category="OWASP A04 Cryptographic Failures", affected_host=str(summary.get("target") or "a04-assessment"), evidence="VulScan evaluated available transport, cookie, HSTS, mixed content, and TLS metadata evidence.", recommendation="Review A04 evidence and apply transport/security hardening.", source="owasp_a04", confidence="High", impact="A04 evidence is available for authorised assessment workflow review.", verification="Review a04_crypto_summary and a04_crypto_evidence.", limitation="A04 checks are evidence-based and may require manual validation."))
    ]
    if any(item.get("rule_group") in {"transport_security", "cleartext_sensitive_workflows"} for item in evidence):
        sensitive = any(item.get("evidence_strength") == "strong_indicator" for item in evidence if item.get("rule_group") in {"transport_security", "cleartext_sensitive_workflows"})
        findings.append(finding_to_dict(create_finding(title="Cleartext Transport Indicator", severity="Medium" if sensitive else "Low", category="OWASP A04 Cryptographic Failures", affected_host=str(summary.get("target") or ""), evidence="HTTP or sensitive endpoint over HTTP observed.", recommendation="Enforce HTTPS and redirect HTTP to HTTPS.", source="owasp_a04", confidence="Medium", impact="Sensitive workflows should use protected transport.", verification="Review transport security evidence.", limitation="Confirm whether sensitive data is actually transmitted.")))
    if any(item.get("rule_group") == "cookie_security" for item in evidence):
        findings.append(finding_to_dict(create_finding(title="Cookie Security Attribute Indicator", severity="Medium" if summary.get("insecure_cookie_count") else "Low", category="OWASP A04 Cryptographic Failures", affected_host=str(summary.get("target") or ""), evidence="One or more cookies are missing recommended security attributes.", recommendation="Configure Secure, HttpOnly, and SameSite attributes appropriately.", source="owasp_a04", confidence="Medium", impact="Cookie attributes help protect session and browser handling.", verification="Review cookie security evidence.", limitation="Cookie purpose must be reviewed manually.")))
    if any(item.get("rule_group") == "mixed_content_indicators" for item in evidence):
        strong = any(item.get("evidence_strength") == "strong_indicator" for item in evidence if item.get("rule_group") == "mixed_content_indicators")
        findings.append(finding_to_dict(create_finding(title="Mixed Content Indicator", severity="Medium" if strong else "Low", category="OWASP A04 Cryptographic Failures", affected_host=str(summary.get("target") or ""), evidence="HTTPS page references HTTP resources.", recommendation="Load resources over HTTPS.", source="owasp_a04", confidence="Medium", impact="Mixed content can weaken browser transport protections depending on resource type.", verification="Review mixed content indicators.", limitation="Impact depends on resource type and browser behaviour.")))
    return findings


def _evidence(*, rule_id: str, rule_group: str, title: str, affected_url: str, scheme: str, evidence_strength: str, confidence: str, observed_value: str, safe_evidence_summary: str, recommendation: str, affected_host: str = "", manual_validation_required: bool = True, source: str = "owasp_a04", extra: dict[str, Any] | None = None) -> dict[str, Any]:
    item = {
        "evidence_id": "",
        "rule_id": rule_id,
        "rule_group": rule_group,
        "title": title,
        "affected_url": _redact_url_query_values(affected_url),
        "affected_host": affected_host or urlsplit(str(affected_url or "")).netloc,
        "scheme": scheme,
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
    item["evidence_id"] = "a04_ev_" + hashlib.sha256("|".join(str(item.get(key) or "") for key in ("rule_id", "affected_url", "observed_value")).encode("utf-8")).hexdigest()[:16]
    return redact_nested(item)


def _cookie_evidence(rule_id: str, title: str, url: str, cookie_name: str, missing: list[str], strength: str, confidence: str) -> dict[str, Any]:
    return _evidence(rule_id=rule_id, rule_group="cookie_security", title=title, affected_url=url, affected_host=urlsplit(str(url or "")).netloc, scheme=urlsplit(str(url or "")).scheme, evidence_strength=strength, confidence=confidence, observed_value=f"cookie_name={cookie_name}; missing_attributes={','.join(missing)}; value=[REDACTED]", safe_evidence_summary=f"Cookie {cookie_name} metadata indicates missing attributes: {', '.join(missing) if missing else 'none'}. Cookie value was not stored.", recommendation="Set Secure, HttpOnly, and SameSite attributes according to cookie purpose.", extra={"cookie_name": cookie_name, "missing_attributes": missing})


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
    return [url for url in dict.fromkeys(collected) if urlsplit(url).scheme in {"http", "https"}]


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


def _normalise_tls_metadata(value: list[dict[str, Any]] | dict[str, Any] | None) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [dict(item) for item in value]
    if isinstance(value, dict) and value:
        return [dict(value)]
    return []


def _https_hosts(urls: list[str]) -> list[str]:
    hosts = []
    for url in urls:
        parsed = urlsplit(str(url or ""))
        if parsed.scheme == "https" and parsed.hostname:
            hosts.append(parsed.hostname)
    return list(dict.fromkeys(hosts))


def _hsts_max_age(value: str) -> int | None:
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    return int(match.group(1)) if match else None


def _sensitive_path_keyword(path: str) -> str:
    lower = path.lower()
    for keyword in SENSITIVE_PATH_KEYWORDS:
        if keyword in lower:
            return keyword
    return ""


def _session_like_cookie(name: str) -> bool:
    if name == "csrftoken":
        return False
    return any(hint in name for hint in SESSION_COOKIE_HINTS)


def _sensitive_cookie_name(name: str) -> bool:
    return _session_like_cookie(name) or any(token in name for token in ("secret", "key", "password"))


def _redact_url_query_values(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    if not parsed.query:
        return str(url or "")
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    redacted = "&".join(f"{name}=[REDACTED]" for name, _value in pairs)
    return parsed._replace(query=redacted).geturl()


def _dedupe_evidence(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    order = {"informational": 1, "weak_indicator": 2, "strong_indicator": 3, "confirmed_finding": 4}
    for item in items:
        key = (str(item.get("rule_id")), str(item.get("affected_url")), str(item.get("observed_value")))
        existing = by_key.get(key)
        if not existing or order.get(str(item.get("evidence_strength")), 0) > order.get(str(existing.get("evidence_strength")), 0):
            by_key[key] = item
    return list(by_key.values())


def _top_risks(evidence: list[dict[str, Any]]) -> list[str]:
    return [str(item.get("title") or "") for item in evidence if item.get("evidence_strength") in {"strong_indicator", "confirmed_finding"}][:5]


def _recommendations(evidence: list[dict[str, Any]]) -> list[str]:
    defaults = [
        "Enforce HTTPS and redirect HTTP to HTTPS.",
        "Configure HSTS after HTTPS readiness review.",
        "Set Secure, HttpOnly, and SameSite cookie attributes appropriately.",
        "Avoid sensitive data over HTTP.",
        "Remove mixed content indicators.",
        "Monitor certificate expiry.",
    ]
    if not evidence:
        return defaults
    seen = []
    for item in evidence:
        rec = str(item.get("recommendation") or "")
        if rec and rec not in seen:
            seen.append(rec)
    return seen[:8] or defaults


def _first_url(urls: list[str]) -> str:
    return urls[0] if urls else ""
