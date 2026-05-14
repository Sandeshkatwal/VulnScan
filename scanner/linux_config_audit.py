"""Read-only Linux configuration audit checks for authenticated SSH sessions."""

from __future__ import annotations

from typing import Any

from scanner.finding import Finding, create_finding


SOURCE = "linux_config_audit"


def build_linux_config_audit_summary(
    commands: list[dict[str, Any]],
    os_family: str,
    open_ports: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build structured Linux configuration audit output."""
    command_by_name = {str(command["command"]): command for command in commands}
    password_policy = _password_policy_indicators(command_by_name)
    temp_permissions = _temp_directory_permissions(command_by_name)
    firewall_status = _firewall_status(command_by_name)
    logging_status = _logging_status(command_by_name)

    return {
        "linux_config_audit_checked": True,
        "firewall_status": firewall_status,
        "logging_status": logging_status,
        "password_policy_indicators": password_policy,
        "temp_directory_permissions": temp_permissions,
        "system_info": {
            "hostname": _first_line(_command_output(command_by_name.get("hostname", {}))),
            "os_family": os_family,
        },
        "cleartext_services": _cleartext_services(open_ports or []),
    }


def build_linux_config_findings(
    host: str,
    port: int,
    config_summary: dict[str, Any],
) -> list[Finding]:
    """Create standard findings from Linux configuration audit output."""
    findings: list[Finding] = []
    findings.extend(_system_info_findings(host, port, config_summary))
    findings.extend(_firewall_findings(host, port, config_summary["firewall_status"]))
    findings.extend(_logging_findings(host, port, config_summary["logging_status"]))
    findings.extend(_password_policy_findings(host, port, config_summary["password_policy_indicators"]))
    findings.extend(_temp_permission_findings(host, port, config_summary["temp_directory_permissions"]))
    findings.extend(_cleartext_service_findings(config_summary["cleartext_services"]))
    return findings


def _system_info_findings(
    host: str,
    port: int,
    config_summary: dict[str, Any],
) -> list[Finding]:
    system_info = config_summary["system_info"]
    hostname = system_info.get("hostname") or "Unavailable"
    return [
        create_finding(
            title="Linux Configuration Audit Completed",
            severity="Informational",
            category="Linux Configuration",
            affected_host=host,
            affected_port=port,
            service="ssh",
            evidence=f"OS family: {system_info.get('os_family')}; hostname: {hostname}.",
            confidence="High",
            impact="Read-only Linux configuration indicators were collected for review.",
            recommendation="Review configuration indicators in operational context and against local policy.",
            verification="Run VulScan SSH audit again or manually review the same read-only host configuration commands.",
            limitation="This is not a full CIS benchmark implementation and does not evaluate every control.",
            source=SOURCE,
        )
    ]


def _firewall_findings(host: str, port: int, firewall_status: dict[str, Any]) -> list[Finding]:
    if firewall_status["state"] == "inactive":
        return [
            create_finding(
                title="Firewall Appears Inactive",
                severity="Medium",
                category="Linux Configuration",
                affected_host=host,
                affected_port=port,
                service="ssh",
                evidence=firewall_status["evidence"],
                confidence="Medium",
                impact="A disabled host firewall can increase exposure if network controls are incomplete.",
                recommendation="Enable and configure a host firewall where appropriate.",
                verification="Review systemctl, ufw, or firewalld status using read-only commands.",
                limitation="This check does not evaluate external firewalls, cloud security groups, or all host policy details.",
                source=SOURCE,
            )
        ]

    return [
        create_finding(
            title="Firewall Status Reviewed",
            severity="Informational",
            category="Linux Configuration",
            affected_host=host,
            affected_port=port,
            service="ssh",
            evidence=firewall_status["evidence"],
            confidence=firewall_status["confidence"],
            impact="Host firewall status was reviewed using available read-only indicators.",
            recommendation="Confirm host firewall policy is appropriate for the system role.",
            verification="Review systemctl, ufw, or firewalld status using read-only commands.",
            limitation="This check is an indicator and does not fully validate firewall rules or external filtering.",
            source=SOURCE,
        )
    ]


def _logging_findings(host: str, port: int, logging_status: dict[str, Any]) -> list[Finding]:
    if logging_status["state"] in {"inactive", "partial"}:
        severity = "Medium" if logging_status["state"] == "inactive" else "Low"
        return [
            create_finding(
                title="Audit Logging Service May Be Inactive",
                severity=severity,
                category="Logging and Monitoring",
                affected_host=host,
                affected_port=port,
                service="ssh",
                evidence=logging_status["evidence"],
                confidence="Medium",
                impact="Inactive audit or logging services can reduce detection and investigation capability.",
                recommendation="Ensure audit/logging services are enabled according to security policy.",
                verification="Review auditd, rsyslog, and systemd-journald service status.",
                limitation="Logging architecture varies; central logging agents or alternative services may be in use.",
                source=SOURCE,
            )
        ]

    return [
        create_finding(
            title="Logging Service Status Reviewed",
            severity="Informational",
            category="Logging and Monitoring",
            affected_host=host,
            affected_port=port,
            service="ssh",
            evidence=logging_status["evidence"],
            confidence=logging_status["confidence"],
            impact="Available audit and logging service indicators were reviewed.",
            recommendation="Confirm logging configuration matches security monitoring requirements.",
            verification="Review auditd, rsyslog, and systemd-journald service status.",
            limitation="This does not verify log forwarding, retention, alerting, or SIEM ingestion.",
            source=SOURCE,
        )
    ]


def _password_policy_findings(
    host: str,
    port: int,
    indicators: dict[str, Any],
) -> list[Finding]:
    findings: list[Finding] = []
    age_issues = indicators["age_policy_issues"]
    if age_issues:
        severity = "Medium" if any("PASS_MAX_DAYS" in issue for issue in age_issues) else "Low"
        findings.append(
            create_finding(
                title="Weak Password Age Policy Indicator",
                severity=severity,
                category="Account Policy",
                affected_host=host,
                affected_port=port,
                service="ssh",
                evidence="; ".join(age_issues),
                confidence="Medium",
                impact="Weak local password age indicators may increase account compromise risk.",
                recommendation="Review local and enterprise account policy settings for appropriate password aging controls.",
                verification="Review /etc/login.defs and identity provider policy.",
                limitation="These checks are indicators only and may not reflect all PAM or enterprise identity policy.",
                source=SOURCE,
            )
        )

    quality_issues = indicators["quality_policy_issues"]
    if quality_issues:
        findings.append(
            create_finding(
                title="Password Quality Policy May Be Weak",
                severity="Low",
                category="Account Policy",
                affected_host=host,
                affected_port=port,
                service="ssh",
                evidence="; ".join(quality_issues),
                confidence="Medium",
                impact="Weak local password quality indicators may allow easier-to-guess local passwords.",
                recommendation="Review password quality settings and require sufficient password length where appropriate.",
                verification="Review /etc/security/pwquality.conf and PAM configuration.",
                limitation="These checks are indicators only and may not reflect all PAM or enterprise identity policy.",
                source=SOURCE,
            )
        )

    return findings


def _temp_permission_findings(
    host: str,
    port: int,
    temp_permissions: dict[str, Any],
) -> list[Finding]:
    findings: list[Finding] = []
    for path, info in temp_permissions.items():
        if info["exists"] and not info["sticky_bit"]:
            findings.append(
                create_finding(
                    title="Sticky Bit Missing on Temporary Directory",
                    severity="Medium",
                    category="File Permissions",
                    affected_host=host,
                    affected_port=port,
                    service="ssh",
                    evidence=f"{path}: {info['evidence']}",
                    confidence="Medium",
                    impact="Missing sticky bit on shared temporary directories can allow users to delete or rename others' files.",
                    recommendation="Set the sticky bit on shared temporary directories where appropriate.",
                    verification=f"Run ls -ld {path} and confirm the directory mode includes the sticky bit.",
                    limitation="This check reviews only common temporary directories and does not modify permissions.",
                    source=SOURCE,
                )
            )
    return findings


def _cleartext_service_findings(cleartext_services: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for service in cleartext_services:
        service_name = service["service"]
        severity = "Medium" if service_name == "ftp" else "High"
        findings.append(
            create_finding(
                title="Cleartext Remote Access Service Detected",
                severity=severity,
                category="Service Exposure",
                affected_host=str(service.get("host") or ""),
                affected_port=int(service.get("port") or 0),
                service=service_name,
                evidence=f"{service_name} detected on {service.get('port')}/tcp.",
                confidence="Medium",
                impact="Cleartext remote access services may expose credentials or session data on the network.",
                recommendation="Replace with SSH, SFTP, or other encrypted alternatives.",
                verification="Review exposed services and confirm whether encrypted alternatives are available.",
                limitation="This finding is based on detected service inventory and does not inspect application configuration.",
                source=SOURCE,
            )
        )
    return findings


def _firewall_status(command_by_name: dict[str, dict[str, Any]]) -> dict[str, Any]:
    evidence_parts: list[str] = []
    active_seen = False
    inactive_seen = False
    reviewed = False

    for command in (
        "systemctl is-active ufw",
        "ufw status",
        "systemctl is-active firewalld",
        "firewall-cmd --state",
    ):
        result = command_by_name.get(command)
        if not result:
            continue
        reviewed = True
        output = _combined_output(result).strip()
        if output:
            evidence_parts.append(f"{command}: {_short(output)}")
        elif result.get("exit_status") not in (0, None):
            evidence_parts.append(f"{command}: unavailable")

        normalized = output.lower()
        if "active" in normalized and "inactive" not in normalized and "not running" not in normalized:
            active_seen = True
        if "inactive" in normalized or "not running" in normalized or normalized == "failed":
            inactive_seen = True

    if active_seen:
        state = "active"
    elif inactive_seen:
        state = "inactive"
    elif reviewed:
        state = "unknown"
    else:
        state = "unavailable"

    return {
        "state": state,
        "evidence": "; ".join(evidence_parts) or "Firewall status commands were unavailable or returned no output.",
        "confidence": "Medium" if reviewed else "Low",
    }


def _logging_status(command_by_name: dict[str, dict[str, Any]]) -> dict[str, Any]:
    states: dict[str, str] = {}
    for service in ("auditd", "rsyslog", "systemd-journald"):
        command = f"systemctl is-active {service}"
        result = command_by_name.get(command)
        if not result:
            states[service] = "unavailable"
            continue
        output = _combined_output(result).strip().lower()
        states[service] = output or "unknown"

    active_count = sum(1 for value in states.values() if value == "active")
    inactive_count = sum(1 for value in states.values() if value in {"inactive", "failed"})
    unavailable_count = sum(1 for value in states.values() if value == "unavailable")

    if active_count:
        state = "active" if inactive_count == 0 else "partial"
    elif inactive_count:
        state = "inactive"
    elif unavailable_count == len(states):
        state = "unavailable"
    else:
        state = "unknown"

    evidence = "; ".join(f"{service}: {status}" for service, status in states.items())
    return {
        "state": state,
        "services": states,
        "evidence": evidence,
        "confidence": "Medium" if state != "unavailable" else "Low",
    }


def _password_policy_indicators(command_by_name: dict[str, dict[str, Any]]) -> dict[str, Any]:
    login_defs = _command_output(command_by_name.get("cat /etc/login.defs", {}))
    pwquality = _command_output(command_by_name.get("cat /etc/security/pwquality.conf", {}))

    login_values = _parse_key_value_file(login_defs)
    quality_values = _parse_key_value_file(pwquality)
    age_issues: list[str] = []
    quality_issues: list[str] = []

    pass_max_days = _int_or_none(login_values.get("PASS_MAX_DAYS"))
    if pass_max_days is not None and pass_max_days > 365:
        age_issues.append(f"PASS_MAX_DAYS is {pass_max_days}, greater than 365.")

    pass_min_days = _int_or_none(login_values.get("PASS_MIN_DAYS"))
    if pass_min_days is None or pass_min_days == 0:
        age_issues.append("PASS_MIN_DAYS is missing or 0.")

    pass_warn_age = _int_or_none(login_values.get("PASS_WARN_AGE"))
    if pass_warn_age is None or pass_warn_age == 0:
        age_issues.append("PASS_WARN_AGE is missing or 0.")

    minlen = _int_or_none(quality_values.get("minlen"))
    if pwquality and (minlen is None or minlen < 12):
        quality_issues.append("minlen in pwquality.conf is missing or less than 12.")

    return {
        "login_defs_read": bool(login_defs),
        "pwquality_conf_read": bool(pwquality),
        "age_policy_issues": age_issues,
        "quality_policy_issues": quality_issues,
    }


def _temp_directory_permissions(command_by_name: dict[str, dict[str, Any]]) -> dict[str, Any]:
    results: dict[str, dict[str, Any]] = {}
    for path in ("/tmp", "/var/tmp"):
        test_result = command_by_name.get(f"test -d {path}")
        ls_result = command_by_name.get(f"ls -ld {path}")
        exists = bool(test_result and test_result.get("exit_status") == 0)
        ls_output = _command_output(ls_result or {})
        mode = ls_output.split()[0] if ls_output.split() else ""
        results[path] = {
            "exists": exists,
            "mode": mode,
            "sticky_bit": len(mode) >= 10 and mode[-1] in {"t", "T"},
            "evidence": _short(ls_output) if ls_output else "Directory unavailable or ls output empty.",
        }
    return results


def _cleartext_services(open_ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cleartext = {"telnet", "ftp", "rlogin", "rexec"}
    services: list[dict[str, Any]] = []
    for item in open_ports:
        service = str(item.get("service") or "").lower()
        if service in cleartext:
            services.append(
                {
                    "host": item.get("host"),
                    "port": item.get("port"),
                    "service": service,
                }
            )
    return services


def _parse_key_value_file(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" in stripped:
            key, value = stripped.split("=", 1)
            values[key.strip()] = value.strip()
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            values[parts[0].strip()] = parts[1].strip()
    return values


def _int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value).split()[0])
    except (TypeError, ValueError):
        return None


def _command_output(result: dict[str, Any]) -> str:
    return str(result.get("raw_stdout") or result.get("stdout") or "")


def _combined_output(result: dict[str, Any]) -> str:
    stdout = str(result.get("raw_stdout") or result.get("stdout") or "")
    stderr = str(result.get("raw_stderr") or result.get("stderr") or "")
    return stdout or stderr


def _short(value: str, limit: int = 240) -> str:
    cleaned = " ".join(value.split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 15].rstrip() + " ... [truncated]"


def _first_line(value: str) -> str:
    for line in value.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""
