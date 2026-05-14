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
from scanner.linux_config_audit import (
    build_linux_config_audit_summary,
    build_linux_config_findings,
)
from scanner.package_audit import (
    PACKAGE_MANAGER_COMMANDS,
    build_package_audit_summary,
    build_package_findings,
    detect_os_family,
)


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
            "SSH audit requires either --ssh-password or --ssh-key. Interactive password prompts are not supported."
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
    open_ports: list[dict[str, Any]] | None = None,
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
        "os_family": "Unknown Linux",
        "package_manager": None,
        "package_update_count": None,
        "package_update_sample": [],
        "package_check_status": "not_run",
        "linux_config_audit_checked": False,
        "linux_config_audit_findings_count": 0,
        "firewall_status": {},
        "logging_status": {},
        "password_policy_indicators": {},
        "temp_directory_permissions": {},
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
        package_summary = build_package_audit_summary(commands)
        linux_config_summary = build_linux_config_audit_summary(
            commands=commands,
            os_family=str(package_summary["os_family"]),
            open_ports=open_ports or [],
        )
        result.update(
            {
                "os_family": package_summary["os_family"],
                "package_manager": package_summary["package_manager"],
                "package_update_count": package_summary["package_update_count"],
                "package_update_sample": package_summary["package_update_sample"],
                "package_check_status": package_summary["package_check_status"],
                "linux_config_audit_checked": linux_config_summary["linux_config_audit_checked"],
                "firewall_status": linux_config_summary["firewall_status"],
                "logging_status": linux_config_summary["logging_status"],
                "password_policy_indicators": linux_config_summary["password_policy_indicators"],
                "temp_directory_permissions": linux_config_summary["temp_directory_permissions"],
            }
        )
        if not _linux_details_available(commands):
            result["status"] = "unsupported_non_linux"
            result["notes"].append(
                "Authenticated SSH succeeded, but Linux OS details were not available. Linux-specific checks were skipped."
            )
        result["findings"] = _build_findings(
            host=host,
            port=port,
            commands=commands,
            package_summary=package_summary,
            linux_config_summary=linux_config_summary,
        )
        result["linux_config_audit_findings_count"] = sum(
            1 for finding in result["findings"] if finding.source == "linux_config_audit"
        )
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
        commands.append(_run_command(client, "systemctl is-active ufw"))
        commands.append(_run_command(client, "systemctl is-active firewalld"))
        commands.append(_run_command(client, "systemctl is-active auditd"))
        commands.append(_run_command(client, "systemctl is-active rsyslog"))
        commands.append(_run_command(client, "systemctl is-active systemd-journald"))

    if _command_exists(client, "ufw", commands):
        commands.append(_run_command(client, "ufw status"))
    if _command_exists(client, "firewall-cmd", commands):
        commands.append(_run_command(client, "firewall-cmd --state"))

    commands.append(_run_command(client, "hostname"))
    commands.append(_run_command(client, "cat /etc/login.defs"))
    commands.append(_run_command(client, "cat /etc/security/pwquality.conf"))
    commands.append(_run_command(client, "test -d /tmp"))
    commands.append(_run_command(client, "test -d /var/tmp"))
    commands.append(_run_command(client, "ls -ld /tmp"))
    commands.append(_run_command(client, "ls -ld /var/tmp"))

    manager_availability = {
        "apt": _command_exists(client, "apt", commands),
        "apt-get": _command_exists(client, "apt-get", commands),
        "dnf": _command_exists(client, "dnf", commands),
        "yum": _command_exists(client, "yum", commands),
        "pacman": _command_exists(client, "pacman", commands),
        "zypper": _command_exists(client, "zypper", commands),
    }
    package_manager = _select_package_manager_for_commands(
        os_release_output=os_release["stdout"],
        manager_availability=manager_availability,
    )
    if package_manager is not None:
        commands.append(_run_command(client, PACKAGE_MANAGER_COMMANDS[package_manager]))

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
            "raw_stdout": stdout_text.strip(),
            "raw_stderr": stderr_text.strip(),
            "timed_out": False,
        }
    except socket.timeout:
        return {
            "command": command,
            "exit_status": None,
            "stdout": "",
            "stderr": "Command timed out.",
            "raw_stdout": "",
            "raw_stderr": "Command timed out.",
            "timed_out": True,
        }


def _build_findings(
    host: str,
    port: int,
    commands: list[dict[str, Any]],
    package_summary: dict[str, Any],
    linux_config_summary: dict[str, Any],
) -> list[Finding]:
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

    if _linux_details_available(commands):
        findings.extend(build_package_findings(host, port, package_summary))
        findings.extend(build_linux_config_findings(host, port, linux_config_summary))

    return findings


def _linux_details_available(commands: list[dict[str, Any]]) -> bool:
    command_by_name = {command["command"]: command for command in commands}
    uname = str(command_by_name.get("uname -a", {}).get("stdout") or "").lower()
    os_release = str(command_by_name.get("cat /etc/os-release", {}).get("stdout") or "")
    return "linux" in uname or bool(os_release.strip())


def _select_package_manager_for_commands(
    os_release_output: str,
    manager_availability: dict[str, bool],
) -> str | None:
    os_family = detect_os_family(os_release_output)

    if os_family == "Debian/Kali/Parrot/Ubuntu":
        if manager_availability.get("apt"):
            return "apt"
        if manager_availability.get("apt-get"):
            return "apt-get"
    if os_family == "Fedora/RHEL/Rocky/Alma":
        if manager_availability.get("dnf"):
            return "dnf"
        if manager_availability.get("yum"):
            return "yum"
    if os_family == "Arch" and manager_availability.get("pacman"):
        return "pacman"
    if os_family == "openSUSE/SUSE" and manager_availability.get("zypper"):
        return "zypper"

    for manager in ("apt", "dnf", "yum", "pacman", "zypper", "apt-get"):
        if manager_availability.get(manager):
            return manager
    return None


def _sshd_findings(host: str, port: int, sshd_config: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    config = _parse_sshd_t(str(sshd_config.get("raw_stdout") or sshd_config.get("stdout") or ""))

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
