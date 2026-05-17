"""Read-only Windows local security policy indicator parsing."""

from __future__ import annotations

import re
from typing import Any

from scanner.finding import Finding, create_finding


SOURCE = "windows_policy_audit"
CATEGORY = "Windows Local Security Policy"
NET_ACCOUNTS_COMMAND = "net accounts"
DOMAIN_POLICY_CONTEXT_NOTE = (
    "Domain Group Policy or enterprise identity controls may override or affect local values."
)
POLICY_LIMITATIONS = [
    "net accounts is an indicator and may not reflect all Group Policy or identity provider controls.",
    "Output format and language can vary by Windows version, domain context, and permissions.",
]


EMPTY_WINDOWS_POLICY_STATUS = {
    "checked": False,
    "source_command": NET_ACCOUNTS_COMMAND,
    "minimum_password_age_days": None,
    "maximum_password_age_days": None,
    "minimum_password_length": None,
    "password_history_length": None,
    "lockout_threshold": None,
    "lockout_duration_minutes": None,
    "lockout_observation_window_minutes": None,
    "force_logoff": "",
    "computer_role": "",
    "domain_policy_context_note": DOMAIN_POLICY_CONTEXT_NOTE,
    "limitations": list(POLICY_LIMITATIONS),
}


def parse_net_accounts_output(output: str) -> dict[str, Any]:
    """Parse safe indicators from English `net accounts` output."""
    values = dict(EMPTY_WINDOWS_POLICY_STATUS)
    lines = [line.strip() for line in str(output or "").splitlines() if line.strip()]
    fields = {_normalise_label(label): value.strip() for label, value in (_split_line(line) for line in lines) if label}

    values.update(
        {
            "checked": bool(fields),
            "force_logoff": _short(fields.get("force user logoff how long after time expires") or ""),
            "minimum_password_age_days": _days(fields.get("minimum password age")),
            "maximum_password_age_days": _days(fields.get("maximum password age")),
            "minimum_password_length": _integer(fields.get("minimum password length")),
            "password_history_length": _integer(fields.get("length of password history maintained")),
            "lockout_threshold": _lockout_threshold(fields.get("lockout threshold")),
            "lockout_duration_minutes": _minutes(fields.get("lockout duration")),
            "lockout_observation_window_minutes": _minutes(fields.get("lockout observation window")),
            "computer_role": _short(fields.get("computer role") or ""),
        }
    )
    return values


def build_windows_policy_findings(target: str, policy_status: dict[str, Any]) -> list[Finding]:
    """Create standard findings for Windows local security policy indicators."""
    findings: list[Finding] = []
    if not policy_status.get("checked"):
        findings.append(_collection_failed(target))
        return findings

    findings.append(
        create_finding(
            title="Windows Local Security Policy Reviewed",
            severity="Informational",
            category=CATEGORY,
            affected_host=target,
            service="winrm",
            evidence="net accounts output was collected and parsed using read-only WinRM command.",
            confidence="High",
            impact="Local password and lockout indicators support account security review.",
            recommendation="Review values against organisational policy and domain policy context.",
            verification="Run net accounts manually.",
            limitation="net accounts is an indicator and may not reflect all Group Policy or identity provider controls.",
            source=SOURCE,
        )
    )

    minimum_length = policy_status.get("minimum_password_length")
    if isinstance(minimum_length, int) and minimum_length < 12:
        findings.append(
            create_finding(
                title="Windows Minimum Password Length May Be Weak",
                severity="Medium",
                category=CATEGORY,
                affected_host=target,
                service="winrm",
                evidence="Minimum password length is below 12.",
                confidence="Medium",
                impact="Shorter passwords can reduce resistance to guessing or cracking.",
                recommendation="Set minimum password length to at least 12 or according to organisational policy.",
                verification="Run net accounts and review minimum password length.",
                limitation="Password policy may be enforced by domain or identity provider controls.",
                source=SOURCE,
            )
        )

    maximum_age = policy_status.get("maximum_password_age_days")
    if maximum_age == 0 or (isinstance(maximum_age, int) and maximum_age > 365):
        findings.append(
            create_finding(
                title="Windows Maximum Password Age May Be Weak",
                severity="Medium" if maximum_age == 0 else "Low",
                category=CATEGORY,
                affected_host=target,
                service="winrm",
                evidence="Maximum password age is unlimited or greater than 365 days.",
                confidence="Medium",
                impact="Stale credentials may remain valid for extended periods.",
                recommendation="Review password ageing policy in context of MFA, passwordless, and enterprise controls.",
                verification="Run net accounts and review maximum password age.",
                limitation="Modern guidance may vary depending on MFA/passwordless strategy.",
                source=SOURCE,
            )
        )

    history_length = policy_status.get("password_history_length")
    if isinstance(history_length, int) and history_length < 5:
        findings.append(
            create_finding(
                title="Windows Password History Requirement May Be Weak",
                severity="Low",
                category=CATEGORY,
                affected_host=target,
                service="winrm",
                evidence="Password history length is less than 5.",
                confidence="Medium",
                impact="Users may be able to reuse recent passwords too quickly.",
                recommendation="Configure password history according to organisational policy.",
                verification="Run net accounts and review password history length.",
                limitation="Domain or identity provider policies may override local values.",
                source=SOURCE,
            )
        )

    threshold = policy_status.get("lockout_threshold")
    if threshold == 0:
        findings.append(
            create_finding(
                title="Windows Account Lockout Threshold Not Configured",
                severity="Medium",
                category=CATEGORY,
                affected_host=target,
                service="winrm",
                evidence="Lockout threshold is 0, Never, or not configured.",
                confidence="Medium",
                impact="Accounts may be more exposed to repeated password attempts.",
                recommendation="Configure account lockout policy according to organisational policy.",
                verification="Run net accounts and review lockout threshold.",
                limitation="Account lockout should be balanced against denial-of-service risk and MFA controls.",
                source=SOURCE,
            )
        )

    if isinstance(threshold, int) and threshold > 0:
        if not policy_status.get("lockout_duration_minutes"):
            findings.append(
                create_finding(
                    title="Windows Account Lockout Duration May Be Weak",
                    severity="Low",
                    category=CATEGORY,
                    affected_host=target,
                    service="winrm",
                    evidence="Lockout duration appears weak or unavailable while lockout threshold is configured.",
                    confidence="Medium",
                    impact="Weak lockout duration may reduce account lockout effectiveness.",
                    recommendation="Review lockout duration policy according to organisational standards.",
                    verification="Run net accounts and review lockout duration.",
                    limitation="Lockout policy interpretation depends on organisational risk appetite.",
                    source=SOURCE,
                )
            )
        if not policy_status.get("lockout_observation_window_minutes"):
            findings.append(
                create_finding(
                    title="Windows Lockout Observation Window May Be Weak",
                    severity="Low",
                    category=CATEGORY,
                    affected_host=target,
                    service="winrm",
                    evidence="Lockout observation window appears weak or unavailable while lockout threshold is configured.",
                    confidence="Medium",
                    impact="A weak reset counter window may reduce account lockout effectiveness.",
                    recommendation="Review reset counter / observation window policy.",
                    verification="Run net accounts and review lockout observation window.",
                    limitation="Domain policy and identity provider controls may affect interpretation.",
                    source=SOURCE,
                )
            )

    if _appears_domain_context(policy_status.get("computer_role")):
        findings.append(
            create_finding(
                title="Windows Policy May Be Controlled by Domain",
                severity="Informational",
                category=CATEGORY,
                affected_host=target,
                service="winrm",
                evidence="Computer role or domain context suggests policy may be managed centrally.",
                confidence="Medium",
                impact="Local indicators may not fully describe effective account policy.",
                recommendation="Interpret local policy indicators in the context of Group Policy or enterprise identity controls.",
                verification="Confirm domain policy with authorised administrative tools.",
                limitation="VulScan 12.5 does not perform full Group Policy analysis.",
                source=SOURCE,
            )
        )

    if _has_incomplete_policy_values(policy_status):
        findings.append(_collection_failed(target))

    return findings


def _collection_failed(target: str) -> Finding:
    return create_finding(
        title="Windows Local Security Policy Collection Failed",
        severity="Informational",
        category=CATEGORY,
        affected_host=target,
        service="winrm",
        evidence="net accounts command failed or returned incomplete data.",
        confidence="Medium",
        impact="Windows local security policy indicators could not be fully reviewed.",
        recommendation="Verify permissions and run net accounts manually.",
        verification="Run net accounts manually.",
        limitation="Command output can vary by Windows version, language, policy, or permissions.",
        source=SOURCE,
    )


def _split_line(line: str) -> tuple[str, str]:
    match = re.match(r"^(.*?\S)\s{2,}(.+)$", line)
    if not match:
        return "", ""
    return match.group(1), match.group(2)


def _normalise_label(value: str) -> str:
    label = re.sub(r"\([^)]*\)", "", value.strip().rstrip("?").lower())
    return re.sub(r"\s+", " ", label).strip()


def _integer(value: str | None) -> int | None:
    if not value:
        return None
    if value.strip().lower() in {"never", "unlimited"}:
        return 0
    match = re.search(r"-?\d+", value)
    return int(match.group(0)) if match else None


def _days(value: str | None) -> int | None:
    return _integer(value)


def _minutes(value: str | None) -> int | None:
    return _integer(value)


def _lockout_threshold(value: str | None) -> int | None:
    return _integer(value)


def _short(value: Any, limit: int = 160) -> str:
    return " ".join(str(value or "").split())[:limit]


def _appears_domain_context(value: Any) -> bool:
    text = str(value or "").lower()
    return any(token in text for token in ("domain", "member", "controller", "backup", "primary"))


def _has_incomplete_policy_values(policy_status: dict[str, Any]) -> bool:
    keys = [
        "minimum_password_age_days",
        "maximum_password_age_days",
        "minimum_password_length",
        "password_history_length",
        "lockout_threshold",
        "lockout_duration_minutes",
        "lockout_observation_window_minutes",
    ]
    return any(policy_status.get(key) is None for key in keys)
