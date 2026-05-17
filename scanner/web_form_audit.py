"""Passive Web DAST form discovery audit."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from scanner.finding import Finding, create_finding


SOURCE = "web_form_audit"
LIMITATIONS = [
    "Forms are discovered only and are never submitted.",
    "Version 13.3 does not authenticate, send payloads, fuzz, test SQL injection, or test XSS.",
    "JavaScript-rendered forms may not be fully discovered by static HTML parsing.",
]


def audit_web_forms(pages: list[dict[str, Any]]) -> dict[str, Any]:
    forms: list[dict[str, Any]] = []
    for page in pages:
        for form in page.get("forms") or []:
            result = _form_result(dict(form))
            forms.append(result)

    findings = _build_findings(forms=forms, pages_checked=len(pages))
    summary = {
        "enabled": True,
        "pages_checked": len(pages),
        "forms_discovered": len(forms),
        "login_forms": _classification_count(forms, "login_form"),
        "search_forms": _classification_count(forms, "search_form"),
        "contact_forms": _classification_count(forms, "contact_form"),
        "upload_forms": _classification_count(forms, "upload_form"),
        "newsletter_forms": _classification_count(forms, "newsletter_form"),
        "generic_forms": _classification_count(forms, "generic_form"),
        "forms_missing_csrf_indicator": _issue_count(forms, "Form Missing CSRF Token Indicator"),
        "forms_submitting_to_http": _issue_count(forms, "HTTPS Page Form Submits to HTTP"),
        "external_form_actions": _issue_count(forms, "External Form Action Discovered"),
        "sensitive_hidden_field_forms": _issue_count(forms, "Form Contains Sensitive-Looking Hidden Fields"),
        "findings_count": len(findings),
        "limitations": list(LIMITATIONS),
    }
    return {
        "enabled": True,
        "source": SOURCE,
        "status": "success",
        "web_form_summary": summary,
        "web_form_results": forms,
        "findings": findings,
    }


def _form_result(form: dict[str, Any]) -> dict[str, Any]:
    classification = _classify_form(form)
    sensitive_fields = [
        str(field.get("name") or field.get("id") or "")
        for field in form.get("input_fields") or []
        if field.get("looks_sensitive")
    ]
    issues: list[str] = []
    if classification == "login_form":
        issues.append("Login Form Discovered")
    if classification == "login_form" and not form.get("is_https_context"):
        issues.append("Login Form Served Over HTTP")
    if form.get("sends_to_http_from_https"):
        issues.append("HTTPS Page Form Submits to HTTP")
    if form.get("has_file_upload"):
        issues.append("File Upload Form Discovered")
    if _state_changing(form) and not form.get("csrf_token_like_fields"):
        issues.append("Form Missing CSRF Token Indicator")
    if _sensitive_hidden_fields(form):
        issues.append("Form Contains Sensitive-Looking Hidden Fields")
    if not form.get("is_internal_action"):
        issues.append("External Form Action Discovered")

    return {
        "form_id": form.get("form_id") or "",
        "page_url": form.get("page_url") or "",
        "page_title": form.get("page_title") or "",
        "method": form.get("method") or "GET",
        "action": form.get("action") or "",
        "resolved_action_url": form.get("resolved_action_url") or form.get("action") or "",
        "action_host": form.get("action_host") or "",
        "classification": classification,
        "is_internal_action": bool(form.get("is_internal_action")),
        "is_https_context": bool(form.get("is_https_context")),
        "sends_to_http_from_https": bool(form.get("sends_to_http_from_https")),
        "has_password_field": bool(form.get("has_password_field")),
        "has_file_upload": bool(form.get("has_file_upload")),
        "csrf_token_like_fields": list(form.get("csrf_token_like_fields") or []),
        "sensitive_field_names": sensitive_fields,
        "input_count": int(form.get("input_count") or 0),
        "hidden_input_count": int(form.get("hidden_input_count") or 0),
        "password_input_count": int(form.get("password_input_count") or 0),
        "file_input_count": int(form.get("file_input_count") or 0),
        "textarea_count": int(form.get("textarea_count") or 0),
        "select_count": int(form.get("select_count") or 0),
        "submit_button_count": int(form.get("submit_button_count") or 0),
        "enctype": form.get("enctype") or "",
        "autocomplete": form.get("autocomplete") or "",
        "input_fields": list(form.get("input_fields") or []),
        "issues": issues,
    }


def _classify_form(form: dict[str, Any]) -> str:
    names = {str(name).lower() for name in form.get("input_names") or []}
    types = {str(input_type).lower() for input_type in form.get("input_types") or []}
    if form.get("has_password_field"):
        return "login_form"
    if form.get("has_file_upload") or str(form.get("enctype") or "").lower() == "multipart/form-data":
        return "upload_form"
    if str(form.get("method") or "").upper() == "GET" and (names & {"search", "q", "query"} or "search" in types):
        return "search_form"
    if {"email", "message", "name"}.issubset(names) or ("email" in names and "message" in names):
        return "contact_form"
    if "email" in names and int(form.get("input_count") or 0) <= 3:
        return "newsletter_form"
    if names or types:
        return "generic_form"
    return "unknown_form"


def _state_changing(form: dict[str, Any]) -> bool:
    return str(form.get("method") or "").upper() in {"POST", "PUT", "PATCH", "DELETE"}


def _sensitive_hidden_fields(form: dict[str, Any]) -> list[str]:
    return [
        str(field.get("name") or field.get("id") or "")
        for field in form.get("input_fields") or []
        if field.get("type") == "hidden" and field.get("looks_sensitive")
    ]


def _build_findings(forms: list[dict[str, Any]], pages_checked: int) -> list[Finding]:
    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for form in forms:
        for issue in form.get("issues") or []:
            grouped[(str(form.get("classification")), str(issue), str(form.get("page_url")), str(form.get("resolved_action_url")))].append(form)

    findings = [_issue_finding(issue=issue, forms=items) for (_classification, issue, _page, _action), items in grouped.items()]
    findings.append(
        create_finding(
            title="Web Form Discovery Completed",
            severity="Informational",
            category="Web Form Discovery",
            evidence=f"VulScan discovered {len(forms)} forms across {pages_checked} pages.",
            confidence="High",
            impact="Form inventory supports review before deeper authorised DAST checks.",
            recommendation="Review discovered forms before deeper authorised DAST checks.",
            verification="Review the Web Form Discovery report.",
            limitation="Forms were not submitted and JavaScript-rendered forms may not be fully discovered.",
            source=SOURCE,
        )
    )
    return findings


def _issue_finding(issue: str, forms: list[dict[str, Any]]) -> Finding:
    sample = forms[0]
    sample_url = str(sample.get("page_url") or "")
    affected_count = len({str(form.get("form_id") or "") for form in forms})
    definitions = {
        "Login Form Discovered": {
            "severity": "Informational",
            "category": "Web Form Discovery",
            "evidence": f"Login form with password field discovered at {sample_url}. Affected forms: {affected_count}.",
            "recommendation": "Ensure login form uses HTTPS, secure cookies, CSRF protection, and rate limiting.",
            "limitation": "This finding does not test authentication security.",
        },
        "Login Form Served Over HTTP": {
            "severity": "High",
            "category": "Web Form Security",
            "evidence": f"Login form with password field discovered over HTTP. Sample URL: {sample_url}. Affected forms: {affected_count}.",
            "recommendation": "Serve login forms only over HTTPS.",
            "limitation": "This finding is based on observed scheme and does not test transport security configuration.",
        },
        "HTTPS Page Form Submits to HTTP": {
            "severity": "High",
            "category": "Web Form Security",
            "evidence": f"Form on HTTPS page submits to HTTP action URL. Sample URL: {sample_url}. Affected forms: {affected_count}.",
            "recommendation": "Ensure form action uses HTTPS.",
            "limitation": "Some forms may be rewritten client-side, which static discovery cannot confirm.",
        },
        "File Upload Form Discovered": {
            "severity": "Low",
            "category": "Web Form Discovery",
            "evidence": f"File upload input discovered at {sample_url}. Affected forms: {affected_count}.",
            "recommendation": "Review file upload validation, size limits, content-type controls, malware scanning, and storage location.",
            "limitation": "VulScan does not upload files or test bypasses in Version 13.3.",
        },
        "Form Missing CSRF Token Indicator": {
            "severity": "Low",
            "category": "Web Form Security",
            "evidence": f"State-changing form appears to lack CSRF-like hidden token field. Sample URL: {sample_url}. Affected forms: {affected_count}.",
            "recommendation": "Review whether CSRF protection is implemented for state-changing forms.",
            "limitation": "CSRF protection can be implemented outside visible form fields, so this is only an indicator.",
        },
        "Form Contains Sensitive-Looking Hidden Fields": {
            "severity": "Low",
            "category": "Web Form Security",
            "evidence": f"Hidden fields with sensitive-looking names were discovered. Sample URL: {sample_url}. Affected forms: {affected_count}.",
            "recommendation": "Ensure sensitive hidden fields are not trusted server-side without validation.",
            "limitation": "Field names alone do not confirm exposure of sensitive data.",
        },
        "External Form Action Discovered": {
            "severity": "Low",
            "category": "Web Form Discovery",
            "evidence": f"Form action points to an external host. Sample URL: {sample_url}. Affected forms: {affected_count}.",
            "recommendation": "Review third-party form processing and data sharing requirements.",
            "limitation": "External form action may be expected for legitimate integrations.",
        },
    }
    definition = definitions[issue]
    return create_finding(
        title=issue,
        severity=definition["severity"],  # type: ignore[arg-type]
        category=str(definition["category"]),
        affected_url=sample_url,
        service="http",
        evidence=str(definition["evidence"]),
        confidence="High",
        impact="Form mapping identifies areas requiring manual security review.",
        recommendation=str(definition["recommendation"]),
        verification="Review the Web Form Discovery report.",
        limitation=str(definition["limitation"]),
        source=SOURCE,
        evidence_details={"affected_forms_count": affected_count, "sample_affected_url": sample_url},
    )


def _classification_count(forms: list[dict[str, Any]], classification: str) -> int:
    return sum(1 for form in forms if form.get("classification") == classification)


def _issue_count(forms: list[dict[str, Any]], issue: str) -> int:
    return sum(1 for form in forms if issue in (form.get("issues") or []))
