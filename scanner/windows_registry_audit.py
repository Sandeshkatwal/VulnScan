"""Narrow read-only Windows registry audit template support."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scanner.evidence import build_evidence, evidence_summary
from scanner.finding import Finding, create_finding


SOURCE = "windows_registry_audit"
DEFAULT_WINDOWS_REGISTRY_TEMPLATE = Path("templates") / "windows_registry" / "basic_security_indicators.json"
SUPPORTED_HIVES = {"HKLM"}
SUPPORTED_OPERATORS = {"equals", "not_equals", "greater_than", "less_than", "exists", "not_exists"}
REGISTRY_LIMITATION = "Registry checks are indicators and may be affected by Windows version, policy, and service state."


class WindowsRegistryTemplateError(ValueError):
    """Raised when a registry audit template cannot be used safely."""

    def __init__(self, message: str, error_code: str) -> None:
        super().__init__(message)
        self.error_code = error_code


@dataclass(frozen=True)
class RegistryCheck:
    id: str
    title: str
    enabled: bool
    hive: str
    path: str
    value_name: str
    expected: Any
    operator: str
    severity_if_mismatch: str
    category: str
    recommendation: str
    limitation: str


def empty_registry_audit(template_path: str | Path = DEFAULT_WINDOWS_REGISTRY_TEMPLATE) -> dict[str, Any]:
    return {
        "template_name": "",
        "template_version": "",
        "template_path": str(template_path),
        "checks_total": 0,
        "checks_executed": 0,
        "checks_failed": 0,
        "checks_skipped": 0,
        "checks_passed": 0,
        "checks_with_findings": 0,
        "check_results": [],
        "limitations": [
            "Windows registry audit was not requested.",
            "Version 12.6 supports only narrow HKLM template-defined exact value checks.",
        ],
    }


def load_registry_template(template_path: str | Path) -> dict[str, Any]:
    path = Path(template_path)
    if not path.exists():
        raise WindowsRegistryTemplateError(
            f"Windows registry template was not found: {path}",
            "WINDOWS_REGISTRY_TEMPLATE_NOT_FOUND",
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise WindowsRegistryTemplateError(
            f"Windows registry template is not valid JSON: {path}",
            "WINDOWS_REGISTRY_TEMPLATE_INVALID_JSON",
        ) from exc
    if not isinstance(data, dict):
        raise WindowsRegistryTemplateError(
            "Windows registry template must be a JSON object.",
            "WINDOWS_REGISTRY_TEMPLATE_INVALID",
        )
    checks = data.get("checks")
    if not isinstance(checks, list):
        raise WindowsRegistryTemplateError(
            "Windows registry template must contain a checks list.",
            "WINDOWS_REGISTRY_TEMPLATE_INVALID",
        )
    parsed_checks = [_parse_check(item) for item in checks]
    return {
        "template_name": _short(data.get("template_name") or "Windows Registry Audit Template"),
        "template_version": _short(data.get("template_version") or ""),
        "description": _short(data.get("description") or "", 300),
        "template_path": str(path),
        "checks": parsed_checks,
    }


def build_registry_query_command(check: RegistryCheck) -> str:
    registry_path = _registry_provider_path(check)
    escaped_path = _escape_powershell_single_quote(registry_path)
    escaped_name = _escape_powershell_single_quote(check.value_name)
    return (
        "$ErrorActionPreference = 'Stop'; "
        f"$item = Get-ItemProperty -Path '{escaped_path}' -Name '{escaped_name}'; "
        f"$value = $item.'{escaped_name}'; "
        "[pscustomobject]@{Present=$true;Value=$value} | ConvertTo-Json -Compress"
    )


def evaluate_registry_audit(template: dict[str, Any], observed_by_check_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    checks = list(template.get("checks") or [])
    results = []
    for check in checks:
        if not isinstance(check, RegistryCheck):
            continue
        if not check.enabled:
            results.append(_result_for_check(check, status="skipped", evidence_summary="Check disabled in template."))
            continue
        observed = observed_by_check_id.get(check.id) or {}
        results.append(_evaluate_check(check, observed))

    checks_total = len(checks)
    checks_executed = sum(1 for item in results if item["status"] not in {"skipped"})
    checks_passed = sum(1 for item in results if item["status"] == "passed")
    checks_skipped = sum(1 for item in results if item["status"] == "skipped")
    checks_with_findings = sum(1 for item in results if item.get("finding_created"))
    checks_failed = sum(1 for item in results if item["status"] in {"failed", "error", "unknown"})
    return {
        "template_name": template.get("template_name") or "",
        "template_version": template.get("template_version") or "",
        "template_path": template.get("template_path") or "",
        "checks_total": checks_total,
        "checks_executed": checks_executed,
        "checks_failed": checks_failed,
        "checks_skipped": checks_skipped,
        "checks_passed": checks_passed,
        "checks_with_findings": checks_with_findings,
        "check_results": results,
        "limitations": [
            "Version 12.6 performs narrow template-based registry checks only.",
            "Only exact HKLM paths and value names from the template are queried.",
            REGISTRY_LIMITATION,
        ],
    }


def build_registry_findings(target: str, registry_audit: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if not registry_audit.get("checks_total") and registry_audit.get("limitations"):
        details = _registry_evidence(
            "Windows registry audit template did not execute any checks.",
            observed_value="No registry checks executed",
            expected_value="Template-defined exact registry checks",
            limitation="Version 12.6 performs narrow template-based registry checks only.",
        )
        findings.append(
            create_finding(
                title="Windows Registry Audit Collection Failed",
                severity="Informational",
                category="Windows Registry Audit",
                affected_host=target,
                service="winrm",
                evidence=evidence_summary(details),
                evidence_details=details,
                confidence="Medium",
                impact="Registry indicators could not be reviewed.",
                recommendation="Verify the registry audit template path and contents.",
                verification="Load the template file and review exact registry checks manually.",
                limitation="Version 12.6 performs narrow template-based registry checks only.",
                source=SOURCE,
            )
        )
    for result in registry_audit.get("check_results") or []:
        if not result.get("finding_created"):
            continue
        limitation = f"{result.get('limitation') or ''} {REGISTRY_LIMITATION}".strip()
        details = _registry_evidence(
            str(result.get("evidence_summary") or ""),
            observed_value=result.get("observed_value"),
            expected_value=result.get("expected_value"),
            limitation=limitation,
        )
        findings.append(
            create_finding(
                title=str(result.get("title") or "Windows Registry Indicator Mismatch"),
                severity=str(result.get("severity") or "Low"),  # type: ignore[arg-type]
                category=str(result.get("category") or "Windows Registry Security Indicator"),
                affected_host=target,
                service="winrm",
                evidence=evidence_summary(details),
                evidence_details=details,
                confidence="Medium",
                impact="Registry security indicator differs from the template expectation.",
                recommendation=str(result.get("recommendation") or "Review the registry indicator in context."),
                verification="Review the exact registry value manually with authorised administrative tools.",
                limitation=limitation,
                source=SOURCE,
            )
        )

    completed_details = _registry_evidence(
        (
            f"Template executed with {registry_audit.get('checks_executed', 0)} checks, "
            f"{registry_audit.get('checks_passed', 0)} passed, "
            f"{registry_audit.get('checks_with_findings', 0)} findings."
        ),
        observed_value=(
            f"executed={registry_audit.get('checks_executed', 0)}, "
            f"passed={registry_audit.get('checks_passed', 0)}, "
            f"findings={registry_audit.get('checks_with_findings', 0)}"
        ),
        expected_value="Narrow template-defined registry indicators reviewed",
        limitation="Version 12.6 performs narrow template-based registry checks only.",
    )
    findings.append(
        create_finding(
            title="Windows Registry Audit Template Completed",
            severity="Informational",
            category="Windows Registry Audit",
            affected_host=target,
            service="winrm",
            evidence=evidence_summary(completed_details),
            evidence_details=completed_details,
            confidence="High",
            impact="Registry indicators support Windows configuration review.",
            recommendation="Review registry indicators in context with service exposure and policy.",
            verification="Review exact template-defined registry values manually where needed.",
            limitation="Version 12.6 performs narrow template-based registry checks only.",
            source=SOURCE,
        )
    )
    return findings


def _registry_evidence(
    summary: str,
    *,
    observed_value: Any,
    expected_value: Any,
    limitation: str,
) -> dict[str, Any]:
    return build_evidence(
        summary=summary,
        source="Registry template",
        command_name="Get-ItemProperty",
        command_used_safe_label="Exact HKLM registry value read from template",
        observed_value=observed_value,
        expected_value=expected_value,
        limitation=limitation,
        raw_output_included=False,
    )


def _parse_check(item: Any) -> RegistryCheck:
    if not isinstance(item, dict):
        raise WindowsRegistryTemplateError(
            "Each Windows registry check must be a JSON object.",
            "WINDOWS_REGISTRY_TEMPLATE_INVALID_CHECK",
        )
    hive = _short(item.get("hive")).upper()
    operator = _short(item.get("operator")).lower()
    path = _short(item.get("path"), 300)
    value_name = _short(item.get("value_name"), 120)
    if hive not in SUPPORTED_HIVES:
        raise WindowsRegistryTemplateError(
            f"Unsupported Windows registry hive '{hive}'. Version 12.6 supports HKLM only.",
            "WINDOWS_REGISTRY_UNSUPPORTED_HIVE",
        )
    if operator not in SUPPORTED_OPERATORS:
        raise WindowsRegistryTemplateError(
            f"Unsupported Windows registry operator '{operator}'.",
            "WINDOWS_REGISTRY_UNSUPPORTED_OPERATOR",
        )
    if "*" in path or "*" in value_name:
        raise WindowsRegistryTemplateError(
            "Windows registry templates must use exact paths and value names, not wildcards.",
            "WINDOWS_REGISTRY_TEMPLATE_WILDCARD_NOT_ALLOWED",
        )
    if not path or not value_name:
        raise WindowsRegistryTemplateError(
            "Windows registry checks require path and value_name.",
            "WINDOWS_REGISTRY_TEMPLATE_INVALID_CHECK",
        )
    return RegistryCheck(
        id=_short(item.get("id") or "WIN-REG-UNKNOWN"),
        title=_short(item.get("title") or "Windows Registry Indicator"),
        enabled=bool(item.get("enabled", True)),
        hive=hive,
        path=path.strip("\\"),
        value_name=value_name,
        expected=item.get("expected"),
        operator=operator,
        severity_if_mismatch=_severity(item.get("severity_if_mismatch")),
        category=_short(item.get("category") or "Windows Registry Security Indicator"),
        recommendation=_short(item.get("recommendation") or "Review this registry indicator in context.", 300),
        limitation=_short(item.get("limitation") or "Registry value is an indicator only.", 300),
    )


def _evaluate_check(check: RegistryCheck, observed: dict[str, Any]) -> dict[str, Any]:
    if observed.get("status") in {"error", "unknown"}:
        status = str(observed.get("status"))
        evidence = str(observed.get("evidence_summary") or f"Registry value {_display_path(check)} could not be read.")
        return _result_for_check(
            check,
            status=status,
            observed_value=observed.get("observed_value"),
            evidence_summary=evidence,
            error_code=str(observed.get("error_code") or ""),
        )

    present = bool(observed.get("present"))
    observed_value = observed.get("observed_value")
    matched = _compare(operator=check.operator, observed=observed_value, expected=check.expected, present=present)
    status = "passed" if matched else "failed"
    evidence = (
        f"Registry value {_display_path(check)} observed {_display_value(observed_value, present)}; "
        f"expected {check.expected}."
    )
    return _result_for_check(
        check,
        status=status,
        observed_value=observed_value if present else None,
        evidence_summary=evidence,
        finding_created=status == "failed",
    )


def _result_for_check(
    check: RegistryCheck,
    *,
    status: str,
    observed_value: Any = None,
    evidence_summary: str = "",
    finding_created: bool = False,
    error_code: str = "",
) -> dict[str, Any]:
    return {
        "id": check.id,
        "title": check.title,
        "status": status,
        "hive": check.hive,
        "path": check.path,
        "value_name": check.value_name,
        "observed_value": "" if observed_value is None else str(observed_value),
        "expected_value": "" if check.expected is None else str(check.expected),
        "operator": check.operator,
        "finding_created": bool(finding_created),
        "evidence_summary": evidence_summary,
        "limitation": check.limitation,
        "severity": check.severity_if_mismatch,
        "category": check.category,
        "recommendation": check.recommendation,
        "error_code": error_code,
    }


def _compare(*, operator: str, observed: Any, expected: Any, present: bool) -> bool:
    if operator == "exists":
        return present
    if operator == "not_exists":
        return not present
    if not present:
        return False
    if operator == "equals":
        return _coerce(observed) == _coerce(expected)
    if operator == "not_equals":
        return _coerce(observed) != _coerce(expected)
    if operator == "greater_than":
        return _number(observed) is not None and _number(expected) is not None and _number(observed) > _number(expected)
    if operator == "less_than":
        return _number(observed) is not None and _number(expected) is not None and _number(observed) < _number(expected)
    return False


def _registry_provider_path(check: RegistryCheck) -> str:
    return "Registry::HKEY_LOCAL_MACHINE\\" + check.path


def _display_path(check: RegistryCheck) -> str:
    return f"{check.hive}\\{check.path}\\{check.value_name}"


def _display_value(value: Any, present: bool) -> str:
    if not present:
        return "not present"
    return str(value)


def _coerce(value: Any) -> Any:
    number = _number(value)
    if number is not None:
        return number
    if isinstance(value, str):
        return value.strip().lower()
    return value


def _number(value: Any) -> float | None:
    try:
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value).strip()
        if text == "":
            return None
        return float(text)
    except (TypeError, ValueError):
        return None


def _severity(value: Any) -> str:
    text = _short(value or "Low").title()
    return text if text in {"Critical", "High", "Medium", "Low", "Informational"} else "Low"


def _short(value: Any, limit: int = 160) -> str:
    return " ".join(str(value or "").split())[:limit]


def _escape_powershell_single_quote(value: str) -> str:
    return value.replace("'", "''")
