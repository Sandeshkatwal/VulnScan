"""Bug bounty scope loading and decision helpers.

This module is intentionally scope-management only. It does not perform
reconnaissance, scanning, exploitation, credential collection, or network I/O.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from scanner.finding import create_finding


BUG_BOUNTY_SCOPE_DIR = Path("data") / "bug_bounty"
DEFAULT_BUG_BOUNTY_SCOPE_PATH = BUG_BOUNTY_SCOPE_DIR / "sample_program_scope.json"
SCOPE_LIMITATION = "Local scope files may become stale or incomplete. Always verify the live program policy before testing."


class BugBountyScopeError(ValueError):
    """Raised when a local bug bounty scope file is invalid."""


def load_bug_bounty_scope(path: str | Path) -> dict[str, Any]:
    """Load, validate, and normalise a local bug bounty scope file."""
    scope_path = Path(path)
    try:
        payload = json.loads(scope_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BugBountyScopeError(f"Bug bounty scope file was not found: {scope_path}") from exc
    except json.JSONDecodeError as exc:
        raise BugBountyScopeError(f"Bug bounty scope file is not valid JSON: {scope_path}") from exc
    if not isinstance(payload, dict):
        raise BugBountyScopeError("Bug bounty scope file must contain a JSON object.")
    validate_bug_bounty_scope(payload)
    return normalise_scope(payload)


def validate_bug_bounty_scope(scope: dict[str, Any]) -> None:
    """Validate required structure and friendly field types."""
    for field in ("program_id", "program_name", "in_scope", "out_of_scope"):
        if field not in scope:
            raise BugBountyScopeError(f"Bug bounty scope is missing required field: {field}")
    for field in ("program_id", "program_name"):
        if not isinstance(scope.get(field), str) or not scope.get(field, "").strip():
            raise BugBountyScopeError(f"Bug bounty scope field must be a non-empty string: {field}")
    for section_name in ("in_scope", "out_of_scope"):
        section = scope.get(section_name)
        if not isinstance(section, dict):
            raise BugBountyScopeError(f"Bug bounty scope section must be an object: {section_name}")
        for key in ("domains", "urls", "ip_ranges"):
            value = section.get(key, [])
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise BugBountyScopeError(f"{section_name}.{key} must be a list of strings.")
        if section_name == "in_scope":
            value = section.get("api_base_urls", [])
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise BugBountyScopeError("in_scope.api_base_urls must be a list of strings.")
    for key in ("forbidden_actions", "allowed_test_types", "disallowed_test_types", "notes"):
        value = scope.get(key, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise BugBountyScopeError(f"{key} must be a list of strings.")
    rate_limits = scope.get("rate_limits", {})
    if rate_limits and not isinstance(rate_limits, dict):
        raise BugBountyScopeError("rate_limits must be an object.")
    for section_name in ("in_scope", "out_of_scope"):
        for cidr in scope.get(section_name, {}).get("ip_ranges", []) or []:
            try:
                ipaddress.ip_network(str(cidr), strict=False)
            except ValueError as exc:
                raise BugBountyScopeError(f"Invalid CIDR in {section_name}.ip_ranges: {cidr}") from exc


def normalise_scope(scope: dict[str, Any]) -> dict[str, Any]:
    """Return a normalized copy of a validated scope object."""
    normalised = dict(scope)
    normalised["program_id"] = _normalise_token(scope.get("program_id"))
    normalised["program_name"] = str(scope.get("program_name") or "").strip()
    for string_field in ("platform", "policy_url", "scope_version", "last_updated", "safe_testing_notice"):
        normalised[string_field] = str(scope.get(string_field) or "").strip()
    normalised["in_scope"] = _normalise_scope_section(scope.get("in_scope") or {}, include_api=True)
    normalised["out_of_scope"] = _normalise_scope_section(scope.get("out_of_scope") or {}, include_api=False)
    normalised["forbidden_actions"] = [_normalise_token(item) for item in scope.get("forbidden_actions", [])]
    normalised["allowed_test_types"] = [_normalise_token(item) for item in scope.get("allowed_test_types", [])]
    normalised["disallowed_test_types"] = [_normalise_token(item) for item in scope.get("disallowed_test_types", [])]
    normalised["notes"] = [str(item).strip() for item in scope.get("notes", []) if str(item).strip()]
    normalised["rate_limits"] = dict(scope.get("rate_limits") or {})
    return normalised


def is_domain_in_scope(domain: str, scope: dict[str, Any]) -> bool:
    """Return whether a domain is in scope after deny overrides."""
    decision = _domain_decision(domain, scope)
    return bool(decision["in_scope"])


def is_url_in_scope(url: str, scope: dict[str, Any]) -> bool:
    """Return whether a URL is in scope after deny overrides."""
    decision = _url_decision(url, scope)
    return bool(decision["in_scope"])


def is_ip_in_scope(ip: str, scope: dict[str, Any]) -> bool:
    """Return whether an IP address is in scope after deny overrides."""
    decision = _ip_decision(ip, scope)
    return bool(decision["in_scope"])


def get_scope_decision(target_or_url: str, scope: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a target, URL, domain, or IP against the local scope file."""
    target = str(target_or_url or "").strip()
    if not target:
        return _decision(target, False, "Empty target is out of scope.", "")
    if _looks_like_url(target):
        return _url_decision(target, scope)
    try:
        ipaddress.ip_address(target)
        return _ip_decision(target, scope)
    except ValueError:
        return _domain_decision(target, scope)


def build_bug_bounty_scope_summary(scope: dict[str, Any], decision: dict[str, Any], enabled: bool = True) -> dict[str, Any]:
    """Build the report/API summary for a scope decision."""
    return {
        "enabled": enabled,
        "program_id": scope.get("program_id") if enabled else "",
        "program_name": scope.get("program_name") if enabled else "",
        "platform": scope.get("platform") if enabled else "",
        "scope_version": scope.get("scope_version") if enabled else "",
        "target": decision.get("target") if enabled else "",
        "target_in_scope": bool(decision.get("in_scope")) if enabled else False,
        "scope_decision_reason": decision.get("reason") if enabled else "Bug bounty scope was not configured.",
        "matched_rule": decision.get("matched_rule") if enabled else "",
        "forbidden_actions": list(scope.get("forbidden_actions") or []) if enabled else [],
        "allowed_test_types": list(scope.get("allowed_test_types") or []) if enabled else [],
        "disallowed_test_types": list(scope.get("disallowed_test_types") or []) if enabled else [],
        "rate_limits": dict(scope.get("rate_limits") or {}) if enabled else {},
        "limitations": [SCOPE_LIMITATION] if enabled else ["Bug bounty scope was not configured."],
    }


def disabled_bug_bounty_scope(target: str = "") -> dict[str, Any]:
    return build_bug_bounty_scope_summary({}, _decision(target, False, "Bug bounty scope was not configured.", ""), enabled=False)


def build_scope_applied_finding(summary: dict[str, Any]) -> dict[str, Any]:
    """Create an informational finding for an evaluated scope file."""
    return create_finding(
        title="Bug Bounty Scope Applied",
        severity="Informational",
        category="Bug Bounty Scope",
        affected_host=str(summary.get("target") or ""),
        evidence="Bug bounty scope was loaded and evaluated for the target.",
        recommendation="Always verify scope against the official program policy before testing.",
        source="bug_bounty_scope",
        confidence="High",
        impact="Scope evaluation helps prevent testing assets that are not authorised.",
        verification="Review the configured local scope file and the official live program policy.",
        limitation=SCOPE_LIMITATION,
    )


def build_scope_blocked_finding(target: str, decision: dict[str, Any]) -> dict[str, Any]:
    """Create an informational finding for a blocked out-of-scope scan."""
    return create_finding(
        title="Bug Bounty Scope Blocked Scan",
        severity="Informational",
        category="Bug Bounty Scope",
        affected_host=str(target or ""),
        evidence="Target was outside configured scope and scan was blocked.",
        recommendation="Confirm program scope before testing.",
        source="bug_bounty_scope",
        confidence="High",
        impact="The scan did not run because the target was not authorised by the local scope file.",
        verification=str(decision.get("reason") or "Review the configured scope file."),
        limitation="Scope decision depends on local scope file accuracy.",
    )


def scope_metadata(scope: dict[str, Any], path: str | Path | None = None) -> dict[str, Any]:
    """Return safe metadata for listing local scope files."""
    return {
        "program_id": scope.get("program_id") or "",
        "program_name": scope.get("program_name") or "",
        "platform": scope.get("platform") or "",
        "policy_url": scope.get("policy_url") or "",
        "scope_version": scope.get("scope_version") or "",
        "last_updated": scope.get("last_updated") or "",
        "scope_file": str(path) if path is not None else "",
        "in_scope_domain_count": len(scope.get("in_scope", {}).get("domains", []) or []),
        "out_of_scope_domain_count": len(scope.get("out_of_scope", {}).get("domains", []) or []),
    }


def _normalise_scope_section(section: dict[str, Any], include_api: bool) -> dict[str, list[str]]:
    result = {
        "domains": [_normalise_domain(item) for item in section.get("domains", []) if str(item).strip()],
        "urls": [_normalise_url(item) for item in section.get("urls", []) if str(item).strip()],
        "ip_ranges": [str(ipaddress.ip_network(str(item).strip(), strict=False)) for item in section.get("ip_ranges", []) if str(item).strip()],
    }
    if include_api:
        result["api_base_urls"] = [_normalise_url(item) for item in section.get("api_base_urls", []) if str(item).strip()]
    return result


def _domain_decision(domain: str, scope: dict[str, Any]) -> dict[str, Any]:
    target = _normalise_domain(domain)
    matched = _match_domain_rules(target, scope.get("out_of_scope", {}).get("domains", []) or [])
    if matched:
        return _decision(domain, False, "Domain matched an out-of-scope rule.", matched, scope)
    matched = _match_domain_rules(target, scope.get("in_scope", {}).get("domains", []) or [])
    if matched:
        return _decision(domain, True, "Domain matched an in-scope rule.", matched, scope)
    return _decision(domain, False, "Unknown target is out of scope by default.", "", scope)


def _url_decision(url: str, scope: dict[str, Any]) -> dict[str, Any]:
    normalised_url = _normalise_url(url)
    host = urlsplit(normalised_url).hostname or ""
    for rule in scope.get("out_of_scope", {}).get("urls", []) or []:
        if _url_rule_matches(normalised_url, rule):
            return _decision(url, False, "URL matched an out-of-scope rule.", rule, scope)
    domain_deny = _match_domain_rules(host, scope.get("out_of_scope", {}).get("domains", []) or [])
    if domain_deny:
        return _decision(url, False, "URL host matched an out-of-scope domain rule.", domain_deny, scope)
    for rule in scope.get("in_scope", {}).get("urls", []) or []:
        if _url_rule_matches(normalised_url, rule):
            return _decision(url, True, "URL matched an in-scope rule.", rule, scope)
    for rule in scope.get("in_scope", {}).get("api_base_urls", []) or []:
        if _url_rule_matches(normalised_url, rule, allow_prefix=True):
            return _decision(url, True, "URL matched an in-scope API base URL rule.", rule, scope)
    domain_allow = _match_domain_rules(host, scope.get("in_scope", {}).get("domains", []) or [])
    if domain_allow:
        return _decision(url, True, "URL host matched an in-scope domain rule.", domain_allow, scope)
    return _decision(url, False, "Unknown target is out of scope by default.", "", scope)


def _ip_decision(ip: str, scope: dict[str, Any]) -> dict[str, Any]:
    try:
        address = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return _decision(ip, False, "Target is not a valid IP address.", "", scope)
    for cidr in scope.get("out_of_scope", {}).get("ip_ranges", []) or []:
        if address in ipaddress.ip_network(cidr, strict=False):
            return _decision(ip, False, "IP matched an out-of-scope range.", cidr, scope)
    for cidr in scope.get("in_scope", {}).get("ip_ranges", []) or []:
        if address in ipaddress.ip_network(cidr, strict=False):
            return _decision(ip, True, "IP matched an in-scope range.", cidr, scope)
    return _decision(ip, False, "Unknown target is out of scope by default.", "", scope)


def _decision(
    target: str,
    in_scope: bool,
    reason: str,
    matched_rule: str,
    scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    scope = scope or {}
    return {
        "target": str(target or ""),
        "in_scope": bool(in_scope),
        "reason": reason,
        "matched_rule": str(matched_rule or ""),
        "program_id": scope.get("program_id") or "",
        "program_name": scope.get("program_name") or "",
    }


def _match_domain_rules(domain: str, rules: list[str]) -> str:
    domain = _normalise_domain(domain)
    for rule in rules:
        normalised_rule = _normalise_domain(rule)
        if normalised_rule.startswith("*."):
            suffix = normalised_rule[2:]
            if domain.endswith(f".{suffix}") and domain != suffix:
                return rule
        elif domain == normalised_rule:
            return rule
    return ""


def _url_rule_matches(url: str, rule: str, allow_prefix: bool = False) -> bool:
    normalised_rule = _normalise_url(rule)
    if url == normalised_rule:
        return True
    return allow_prefix and url.startswith(normalised_rule)


def _normalise_domain(value: Any) -> str:
    domain = str(value or "").strip().lower().rstrip(".")
    if "://" in domain:
        domain = urlsplit(domain).hostname or ""
    return domain


def _normalise_url(value: Any) -> str:
    raw = str(value or "").strip()
    parsed = urlsplit(raw)
    if not parsed.scheme and not parsed.netloc:
        parsed = urlsplit(f"https://{raw}")
    scheme = (parsed.scheme or "https").lower()
    netloc = parsed.netloc.lower().rstrip(".")
    path = parsed.path or "/"
    return urlunsplit((scheme, netloc, path, "", ""))


def _normalise_token(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_")


def _looks_like_url(value: str) -> bool:
    return "://" in value
