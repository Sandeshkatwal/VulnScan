"""Authenticated read-only SSH auditing for authorised Linux systems."""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

try:
    import paramiko
except ImportError:  # pragma: no cover - exercised only when dependency is absent.
    paramiko = None  # type: ignore[assignment]

from scanner.finding import Finding, create_finding


SOURCE = "ssh_audit"
DEFAULT_TIMEOUT_SECONDS = 8.0
COMMAND_TIMEOUT_SECONDS = 10.0
MAX_OUTPUT_CHARS = 1200


class SshAuditConfigurationError(ValueError):
    """Raised when SSH audit options are incomplete or unsafe."""


def validate_ssh_audit_options(
    ssh_audit: bool,
    ssh_user: str | None,
    ssh_password: str | None,
    ssh_key: Path | None,
) -> None:
    """Validate SSH audit options without exposing credential values."""
    if not ssh_audit:
        return

    if not ssh_user or not ssh_user.strip():
        raise SshAuditConfigurationError(
            "SSH audit requires --ssh-user. Provide a least-privilege account for an authorised Linux system."
        )

    if not ssh_password and ssh_key is None:
        raise SshAuditConfigurationError(
            "SSH audit requires either --ssh-password or --ssh-key. Interactive password prompts are not supported in Version 11.0."
        )

    if ssh_key is not None and not ssh_key.expanduser().is_file():
        raise SshAuditConfigurationError("SSH key file was not found or is not readable.")


def audit_ssh_host(
    host: str,
    resolved_ip: str,
    username: str,
    password: str | None = None,
    key_path: Path | None = None,
    port: int = 22,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Run one authenticated SSH login and read-only Linux configuration checks."""
    result: dict[str, Any] = {
        "enabled": True,
        "target": host,
        "port": port,
        "status": "not_run",
        "authenticated": False,
        "commands": [],
        "findings": [],
        "notes": [],
    }

    if paramiko is None:
        result["status"] = "dependency_missing"
        result["notes"].append("Paramiko is required for SSH audit but is not installed.")
        return result

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        connect_kwargs: dict[str, Any] = {
            "hostname": resolved_ip,
            "port": port,
            "username": username,
            "timeout": timeout,
            "banner_timeout": timeout,
            "auth_timeout": timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if key_path is not None:
            connect_kwargs["key_filename"] = str(key_path.expanduser())
        else:
            connect_kwargs["password"] = password

        client.connect(**connect_kwargs)
        result["authenticated"] = True
        result["status"] = "completed"
        commands = _collect_linux_audit_data(client)
        result["commands"] = [_command_report(command) for command in commands]
        if not _linux_details_available(commands):
            result["status"] = "unsupported_non_linux"
            result["notes"].append(
                "Authenticated SSH succeeded, but Linux OS details were not available. Linux-specific checks were skipped."
            )
        result["findings"] = _build_findings(host=host, port=port, commands=commands)
        return result
    except paramiko.AuthenticationException:
        result["status"] = "authentication_failed"
        result["notes"].append("SSH authentication failed. No audit commands were run.")
        return result
    except (socket.timeout, TimeoutError):
        result["status"] = "timeout"
        result["notes"].append("SSH connection timed out. No audit commands were run.")
        return result
    except (paramiko.SSHException, OSError) as exc:
        result["status"] = "connection_failed"
        result["notes"].append(f"SSH audit could not complete safely: {exc.__class__.__name__}.")
        return result
    finally:
        client.close()


def _collect_linux_audit_data(client: Any) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []

    uname = _run_command(client, "uname -a")
    os_release = _run_command(client, "cat /etc/os-release")
    commands.extend([uname, os_release])

    is_linux = "linux" in uname["stdout"].lower() or bool(os_release["stdout"].strip())
    if not is_linux:
        return commands

    if _command_exists(client, "sshd", commands):
        commands.append(_run_command(client, "sshd -T"))

    if _command_exists(client, "systemctl", commands):
        commands.append(_run_command(client, "systemctl is-active firewalld"))

    if _command_exists(client, "ufw", commands):
        commands.append(_run_command(client, "ufw status"))

    apt_exists = _command_exists(client, "apt", commands)
    dnf_exists = _command_exists(client, "dnf", commands)
    yum_exists = _command_exists(client, "yum", commands)

    if apt_exists:
        commands.append(_run_command(client, "apt list --upgradable"))
    if dnf_exists:
        commands.append(_run_command(client, "dnf check-update"))
    if yum_exists:
        commands.append(_run_command(client, "yum check-update"))

    return commands


def _command_exists(client: Any, executable: str, commands: list[dict[str, Any]]) -> bool:
    command = f"command -v {executable}"
    result = _run_command(client, command)
    commands.append(result)
    return result["exit_status"] == 0 and bool(result["stdout"].strip())


def _run_command(client: Any, command: str) -> dict[str, Any]:
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=COMMAND_TIMEOUT_SECONDS)
        stdin.close()
        stdout_text = stdout.read().decode("utf-8", errors="replace")
        stderr_text = stderr.read().decode("utf-8", errors="replace")
        exit_status = stdout.channel.recv_exit_status()
        return {
            "command": command,
            "exit_status": exit_status,
            "stdout": _truncate(stdout_text.strip()),
            "stderr": _truncate(stderr_text.strip()),
            "timed_out": False,
        }
    except socket.timeout:
        return {
            "command": command,
            "exit_status": None,
            "stdout": "",
            "stderr": "Command timed out.",
            "timed_out": True,
        }


def _build_findings(host: str, port: int, commands: list[dict[str, Any]]) -> list[Finding]:
    findings = [
        create_finding(
            title="SSH Login Successful",
            severity="Informational",
            category="Credentialed Access",
            affected_host=host,
            affected_port=port,
            service="ssh",
            evidence="Authenticated SSH session established",
            confidence="High",
            impact="Credentialed auditing can reduce false positives by checking system state directly.",
            recommendation="Use least-privilege read-only credentials for routine audits.",
            verification="VulScan established one SSH session using credentials explicitly provided for this run.",
            limitation="Checks are limited by the permission level of the provided account.",
            source=SOURCE,
        )
    ]

    command_by_name = {command["command"]: command for command in commands}
    uname = command_by_name.get("uname -a", {})
    os_release = command_by_name.get("cat /etc/os-release", {})

    os_evidence = _os_evidence(uname, os_release)
    if os_evidence:
        findings.append(
            create_finding(
                title="OS Information Collected",
                severity="Informational",
                category="System Information",
                affected_host=host,
                affected_port=port,
                service="ssh",
                evidence=os_evidence,
                confidence="High",
                impact="OS and kernel metadata can support patch verification and asset inventory.",
                recommendation="Use OS and kernel information for patch verification and asset inventory.",
                verification="Review uname -a and /etc/os-release output collected through the authenticated SSH session.",
                limitation="Reported values depend on what the provided account can read.",
                source=SOURCE,
            )
        )

    sshd_config = command_by_name.get("sshd -T")
    if sshd_config:
        findings.extend(_sshd_findings(host, port, sshd_config))

    firewall_finding = _firewall_finding(host, port, command_by_name)
    if firewall_finding is not None:
        findings.append(firewall_finding)

    updates_finding = _package_updates_finding(host, port, command_by_name)
    if updates_finding is not None:
        findings.append(updates_finding)

    return findings


def _linux_details_available(commands: list[dict[str, Any]]) -> bool:
    command_by_name = {command["command"]: command for command in commands}
    uname = str(command_by_name.get("uname -a", {}).get("stdout") or "").lower()
    os_release = str(command_by_name.get("cat /etc/os-release", {}).get("stdout") or "")
    return "linux" in uname or bool(os_release.strip())


def _sshd_findings(host: str, port: int, sshd_config: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    config = _parse_sshd_t(sshd_config["stdout"])

    if config.get("passwordauthentication") == "yes":
        findings.append(
            create_finding(
                title="SSH Password Authentication Enabled",
                severity="Medium",
                category="SSH Configuration",
                affected_host=host,
                affected_port=port,
                service="ssh",
                evidence="PasswordAuthentication yes from sshd -T",
                confidence="High",
                impact="Password-based SSH access may increase exposure to credential misuse and password attacks.",
                recommendation="Disable password authentication where possible and use SSH keys.",
                verification="Run sshd -T and check passwordauthentication.",
                limitation="Effective SSH configuration may vary by match blocks or service-specific deployment context.",
                source=SOURCE,
            )
        )

    if config.get("permitrootlogin") == "yes":
        findings.append(
            create_finding(
                title="SSH Root Login Enabled",
                severity="High",
                category="SSH Configuration",
                affected_host=host,
                affected_port=port,
                service="ssh",
                evidence="PermitRootLogin yes from sshd -T",
                confidence="High",
                impact="Direct root SSH login increases the impact of credential compromise.",
                recommendation="Disable direct root login and use a named user with privilege escalation where required.",
                verification="Run sshd -T and check permitrootlogin.",
                limitation="Effective SSH configuration may vary by match blocks or service-specific deployment context.",
                source=SOURCE,
            )
        )

    return findings


def _firewall_finding(
    host: str,
    port: int,
    command_by_name: dict[str, dict[str, Any]],
) -> Finding | None:
    firewalld = command_by_name.get("systemctl is-active firewalld")
    if firewalld and firewalld["stdout"].strip().lower() in {"inactive", "failed", "unknown"}:
        return create_finding(
            title="Firewall Appears Inactive",
            severity="Medium",
            category="Host Configuration",
            affected_host=host,
            affected_port=port,
            service="ssh",
            evidence=f"firewalld status indicates {firewalld['stdout'].strip().lower()}.",
            confidence="Medium",
            impact="A disabled host firewall can increase exposure if network controls are incomplete.",
            recommendation="Enable and configure a host firewall if appropriate.",
            verification="Run systemctl is-active firewalld and review host firewall policy.",
            limitation="This check does not evaluate external network firewalls or host-specific policy exceptions.",
            source=SOURCE,
        )

    ufw = command_by_name.get("ufw status")
    ufw_output = ufw["stdout"].lower() if ufw else ""
    if ufw and ("status: inactive" in ufw_output or ufw_output.strip() == "inactive"):
        return create_finding(
            title="Firewall Appears Inactive",
            severity="Medium",
            category="Host Configuration",
            affected_host=host,
            affected_port=port,
            service="ssh",
            evidence="ufw status indicates inactive.",
            confidence="Medium",
            impact="A disabled host firewall can increase exposure if network controls are incomplete.",
            recommendation="Enable and configure a host firewall if appropriate.",
            verification="Run ufw status and review host firewall policy.",
            limitation="This check does not evaluate external network firewalls or host-specific policy exceptions.",
            source=SOURCE,
        )

    return None


def _package_updates_finding(
    host: str,
    port: int,
    command_by_name: dict[str, dict[str, Any]],
) -> Finding | None:
    package_commands = (
        "apt list --upgradable",
        "dnf check-update",
        "yum check-update",
    )
    evidence_parts: list[str] = []

    for command in package_commands:
        result = command_by_name.get(command)
        if not result:
            continue
        if _updates_available(command, result):
            evidence_parts.append(f"{command} reports available updates.")

    if not evidence_parts:
        return None

    return create_finding(
        title="Package Updates Available",
        severity="Medium",
        category="Patch Management",
        affected_host=host,
        affected_port=port,
        service="ssh",
        evidence=" ".join(evidence_parts),
        confidence="Medium",
        impact="Missing package updates can leave known defects or vulnerabilities unpatched.",
        recommendation="Review and apply security updates according to change management.",
        verification="Run the available package manager update-check command and review pending updates.",
        limitation="This check does not distinguish security updates from general package updates.",
        source=SOURCE,
    )


def _updates_available(command: str, result: dict[str, Any]) -> bool:
    stdout = result["stdout"].strip()
    if command == "apt list --upgradable":
        lines = [
            line
            for line in stdout.splitlines()
            if line.strip() and not line.lower().startswith("listing...")
        ]
        return bool(lines)

    if command in {"dnf check-update", "yum check-update"}:
        return result["exit_status"] == 100

    return False


def _parse_sshd_t(output: str) -> dict[str, str]:
    config: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            config[parts[0].lower()] = parts[1].strip().lower()
    return config


def _os_evidence(uname: dict[str, Any], os_release: dict[str, Any]) -> str:
    parts: list[str] = []
    if uname.get("stdout"):
        parts.append(f"uname -a: {uname['stdout']}")

    os_release_output = str(os_release.get("stdout") or "")
    pretty_name = _os_release_value(os_release_output, "PRETTY_NAME")
    os_name = pretty_name or _os_release_value(os_release_output, "NAME")
    if os_name:
        parts.append(f"/etc/os-release: {os_name}")

    return _truncate("; ".join(parts), max_chars=MAX_OUTPUT_CHARS)


def _os_release_value(output: str, key: str) -> str:
    prefix = f"{key}="
    for line in output.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].strip().strip('"')
    return ""


def _command_report(command: dict[str, Any]) -> dict[str, Any]:
    return {
        "command": command["command"],
        "exit_status": command["exit_status"],
        "stdout": command["stdout"],
        "stderr": command["stderr"],
        "timed_out": command["timed_out"],
    }


def _truncate(value: str, max_chars: int = MAX_OUTPUT_CHARS) -> str:
    if len(value) <= max_chars:
        return value
    return value[: max_chars - 15].rstrip() + " ... [truncated]"
