"""Authenticated read-only SSH auditing for authorised Linux systems."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    import paramiko
except ImportError:  # pragma: no cover - exercised only when dependency is absent.
    paramiko = None  # type: ignore[assignment]

from scanner.audit_profiles import AuditProfile, get_audit_profile
from scanner.credentialed_result import (
    CredentialedAuditResult,
    CredentialedCheckResult,
    build_error,
)
from scanner.evidence import STDERR_MAX_CHARS, build_evidence, evidence_summary, safe_truncate
from scanner.finding import Finding, create_finding, finding_to_dict
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
MAX_CONNECTION_TIMEOUT_SECONDS = 60.0
MAX_COMMAND_TIMEOUT_SECONDS = 120.0
MAX_AUDIT_TIMEOUT_SECONDS = 600.0
MAX_OUTPUT_CHARS = 1200

STATUS_SUCCESS = "success"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"
STATUS_PARTIAL = "partial"

ERROR_AUTH_FAILED = "SSH_AUTH_FAILED"
ERROR_TIMEOUT = "SSH_TIMEOUT"
ERROR_CONNECTION_FAILED = "SSH_CONNECTION_FAILED"
ERROR_KEY_NOT_FOUND = "SSH_KEY_NOT_FOUND"
ERROR_KEY_LOAD_FAILED = "SSH_KEY_LOAD_FAILED"
ERROR_UNSUPPORTED_TARGET = "SSH_UNSUPPORTED_TARGET"
ERROR_COMMAND_TIMEOUT = "SSH_COMMAND_TIMEOUT"
ERROR_COMMAND_FAILED = "SSH_COMMAND_FAILED"
ERROR_AUDIT_TIME_BUDGET_EXCEEDED = "SSH_AUDIT_TIME_BUDGET_EXCEEDED"
ERROR_CREDENTIALS_MISSING = "SSH_CREDENTIALS_MISSING"
ERROR_UNKNOWN = "SSH_UNKNOWN_ERROR"


class SshAuditConfigurationError(ValueError):
    """Raised when SSH audit options are incomplete or unsafe."""

    def __init__(self, message: str, error_code: str = ERROR_UNKNOWN) -> None:
        super().__init__(message)
        self.error_code = error_code


def validate_ssh_audit_options(
    ssh_audit: bool,
    ssh_user: str | None,
    ssh_password: str | None,
    ssh_key: Path | None,
    ssh_timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ssh_command_timeout: float = COMMAND_TIMEOUT_SECONDS,
    ssh_audit_timeout: float | None = None,
) -> None:
    """Validate SSH audit options without exposing credential values."""
    if not ssh_audit:
        return

    if not ssh_user or not ssh_user.strip():
        raise SshAuditConfigurationError(
            "SSH audit requires --ssh-user. Provide a least-privilege account for an authorised Linux system.",
            ERROR_CREDENTIALS_MISSING,
        )

    if not ssh_password and ssh_key is None:
        raise SshAuditConfigurationError(
            "SSH audit requires either --ssh-password or --ssh-key. Interactive password prompts are not supported.",
            ERROR_CREDENTIALS_MISSING,
        )

    if ssh_key is not None and not ssh_key.expanduser().is_file():
        raise SshAuditConfigurationError(
            "SSH key file was not found or is not readable.",
            ERROR_KEY_NOT_FOUND,
        )

    _validate_timeout_value(
        "--ssh-timeout",
        ssh_timeout,
        maximum=MAX_CONNECTION_TIMEOUT_SECONDS,
    )
    _validate_timeout_value(
        "--ssh-command-timeout",
        ssh_command_timeout,
        maximum=MAX_COMMAND_TIMEOUT_SECONDS,
    )
    if ssh_audit_timeout is not None:
        _validate_timeout_value(
            "--ssh-audit-timeout",
            ssh_audit_timeout,
            maximum=MAX_AUDIT_TIMEOUT_SECONDS,
        )


def _validate_timeout_value(option_name: str, value: float, *, maximum: float) -> None:
    try:
        numeric_value = float(value)
    except (TypeError, ValueError) as exc:
        raise SshAuditConfigurationError(
            f"{option_name} must be a number greater than 0 and no more than {maximum:g} seconds."
        ) from exc
    if numeric_value <= 0 or numeric_value > maximum:
        raise SshAuditConfigurationError(
            f"{option_name} must be greater than 0 and no more than {maximum:g} seconds."
        )


@dataclass
class _AuditRuntime:
    command_timeout_seconds: float
    audit_timeout_seconds: float
    started_at: float = field(default_factory=time.perf_counter)
    skipped_checks: list[str] = field(default_factory=list)

    def elapsed(self) -> float:
        return time.perf_counter() - self.started_at

    def remaining(self) -> float:
        return max(0.0, self.audit_timeout_seconds - self.elapsed())

    def has_budget(self) -> bool:
        return self.remaining() > 0

    def skip_command(self, command: str) -> dict[str, Any]:
        if command not in self.skipped_checks:
            self.skipped_checks.append(command)
        return _skipped_command(command, self.elapsed())


def audit_ssh_host(
    host: str,
    resolved_ip: str,
    username: str,
    password: str | None = None,
    key_path: Path | None = None,
    port: int = 22,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    command_timeout: float = COMMAND_TIMEOUT_SECONDS,
    audit_timeout: float | None = None,
    open_ports: list[dict[str, Any]] | None = None,
    audit_profile: AuditProfile | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Run one authenticated SSH login and read-only Linux configuration checks."""
    profile = audit_profile or get_audit_profile(None)
    audit_timeout_seconds = (
        float(audit_timeout)
        if audit_timeout is not None
        else float(profile.default_audit_timeout_seconds)
    )
    runtime = _AuditRuntime(
        command_timeout_seconds=float(command_timeout),
        audit_timeout_seconds=audit_timeout_seconds,
    )
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result: dict[str, Any] = {
        "enabled": True,
        "source": SOURCE,
        "module_name": "Authenticated SSH Audit",
        "target": host,
        "port": port,
        "audit_profile": profile.name,
        "profile_description": profile.description,
        "checks_enabled": profile.checks_enabled,
        "profile_checks_skipped": profile.checks_skipped,
        "status": STATUS_SKIPPED,
        "error_code": None,
        "error_message": "",
        "debug_details": "",
        "authenticated": False,
        "commands": [],
        "checks_completed": 0,
        "checks_failed": 0,
        "checks_planned": 0,
        "checks_skipped": 0,
        "partial_failures": 0,
        "command_timeout_seconds": float(command_timeout),
        "connection_timeout_seconds": timeout,
        "audit_timeout_seconds": audit_timeout_seconds,
        "total_duration_seconds": 0.0,
        "timed_out_commands": 0,
        "slowest_command_name": None,
        "slowest_command_duration_seconds": None,
        "performance_notes": [],
        "findings": [],
        "notes": [],
        "os_family": "Unknown Linux",
        "package_manager": None,
        "package_update_count": None,
        "package_update_sample": [],
        "package_check_status": "not_run",
        "hostname": "",
        "kernel_summary": "",
        "ssh_hardening_checked": False,
        "linux_config_audit_checked": False,
        "linux_config_audit_findings_count": 0,
        "firewall_status": {},
        "logging_status": {},
        "password_policy_indicators": {},
        "temp_directory_permissions": {},
    }

    if key_path is not None and not key_path.expanduser().is_file():
        result["status"] = STATUS_FAILED
        result["error_code"] = ERROR_KEY_NOT_FOUND
        result["error_message"] = "SSH key file was not found or is not readable."
        result["notes"].append(result["error_message"])
        return _finalize_credentialed_result(result, username=username, auth_method=_auth_method(key_path), started_at=started_at)

    if paramiko is None:
        result["status"] = STATUS_FAILED
        result["error_code"] = ERROR_CONNECTION_FAILED
        result["error_message"] = "Paramiko is required for SSH audit but is not installed."
        result["notes"].append(result["error_message"])
        return _finalize_credentialed_result(result, username=username, auth_method=_auth_method(key_path), started_at=started_at)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        _progress(progress_callback, "Connecting to SSH service...")
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
        result["status"] = STATUS_SUCCESS
        _progress(progress_callback, "Authenticated successfully.")
        commands = _collect_linux_audit_data(client, profile, runtime, progress_callback)
        result["commands"] = [_command_report(command) for command in commands]
        _apply_performance_summary(result, commands, runtime)
        _apply_command_status(result, commands)
        package_summary = (
            build_package_audit_summary(commands)
            if profile.checks["package_checks"]
            else _skipped_package_summary(commands)
        )
        linux_config_summary = build_linux_config_audit_summary(
            commands=commands,
            os_family=str(package_summary["os_family"]),
            open_ports=open_ports or [],
            checks=profile.checks,
        )
        result.update(
            {
                "os_family": package_summary["os_family"],
                "hostname": _hostname_from_commands(commands),
                "kernel_summary": _kernel_summary_from_commands(commands),
                "package_manager": package_summary["package_manager"],
                "package_update_count": package_summary["package_update_count"],
                "package_update_sample": package_summary["package_update_sample"],
                "package_check_status": package_summary["package_check_status"],
                "ssh_hardening_checked": _command_was_successful(commands, "sshd -T")
                or _command_was_successful(commands, "cat /etc/ssh/sshd_config"),
                "linux_config_audit_checked": linux_config_summary["linux_config_audit_checked"],
                "firewall_status": linux_config_summary["firewall_status"],
                "logging_status": linux_config_summary["logging_status"],
                "password_policy_indicators": linux_config_summary["password_policy_indicators"],
                "temp_directory_permissions": linux_config_summary["temp_directory_permissions"],
            }
        )
        if not _linux_details_available(commands):
            result["status"] = STATUS_PARTIAL
            if not result["error_code"] and not runtime.skipped_checks:
                result["error_code"] = ERROR_UNSUPPORTED_TARGET
                result["error_message"] = (
                    "Authenticated SSH succeeded, but Linux OS details were not available."
                )
            result["notes"].append("Linux-specific checks were skipped.")
        if runtime.skipped_checks:
            result["status"] = STATUS_PARTIAL
            result["error_code"] = result["error_code"] or ERROR_AUDIT_TIME_BUDGET_EXCEEDED
            result["error_message"] = result["error_message"] or (
                "SSH audit time budget was exceeded before all checks completed."
            )
            result["notes"].append("Some SSH audit checks were skipped because the audit time budget was exceeded.")
        result["findings"] = _build_findings(
            host=host,
            port=port,
            commands=commands,
            package_summary=package_summary,
            linux_config_summary=linux_config_summary,
            profile=profile,
        )
        result["linux_config_audit_findings_count"] = sum(
            1 for finding in result["findings"] if finding.source == "linux_config_audit"
        )
        result["total_duration_seconds"] = round(runtime.elapsed(), 3)
        _progress(progress_callback, f"SSH audit completed with status: {result['status']}")
        return _finalize_credentialed_result(result, username=username, auth_method=_auth_method(key_path), started_at=started_at)
    except paramiko.AuthenticationException:
        result["status"] = STATUS_FAILED
        result["error_code"] = ERROR_AUTH_FAILED
        result["error_message"] = "SSH authentication failed. No audit commands were run."
        result["notes"].append(result["error_message"])
        return _finalize_credentialed_result(result, username=username, auth_method=_auth_method(key_path), started_at=started_at)
    except (socket.timeout, TimeoutError):
        result["status"] = STATUS_FAILED
        result["error_code"] = ERROR_TIMEOUT
        result["error_message"] = "SSH connection timed out. No audit commands were run."
        result["notes"].append(result["error_message"])
        return _finalize_credentialed_result(result, username=username, auth_method=_auth_method(key_path), started_at=started_at)
    except (paramiko.SSHException, OSError) as exc:
        result["status"] = STATUS_FAILED
        result["error_code"] = ERROR_KEY_LOAD_FAILED if key_path is not None else ERROR_CONNECTION_FAILED
        result["error_message"] = "SSH audit could not complete safely."
        result["debug_details"] = exc.__class__.__name__
        result["notes"].append(result["error_message"])
        return _finalize_credentialed_result(result, username=username, auth_method=_auth_method(key_path), started_at=started_at)
    except Exception as exc:  # pragma: no cover - defensive safety net.
        result["status"] = STATUS_FAILED
        result["error_code"] = ERROR_UNKNOWN
        result["error_message"] = "SSH audit failed unexpectedly but safely."
        result["debug_details"] = exc.__class__.__name__
        result["notes"].append(result["error_message"])
        return _finalize_credentialed_result(result, username=username, auth_method=_auth_method(key_path), started_at=started_at)
    finally:
        result["total_duration_seconds"] = round(runtime.elapsed(), 3)
        client.close()


def _collect_linux_audit_data(
    client: Any,
    profile: AuditProfile,
    runtime: _AuditRuntime,
    progress_callback: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []

    _progress(progress_callback, "Collecting OS information...")
    uname = _run_command(client, "uname -a", timeout=runtime.command_timeout_seconds, runtime=runtime)
    os_release = _run_command(
        client,
        "cat /etc/os-release",
        timeout=runtime.command_timeout_seconds,
        runtime=runtime,
    )
    commands.extend([uname, os_release])

    is_linux = "linux" in uname["stdout"].lower() or bool(os_release["stdout"].strip())
    if not is_linux:
        return commands

    if profile.checks["ssh_hardening"] and _command_exists(client, "sshd", commands, runtime):
        _progress(progress_callback, "Checking SSH hardening...")
        sshd_effective = _run_command(client, "sshd -T", timeout=runtime.command_timeout_seconds, runtime=runtime)
        commands.append(sshd_effective)
        if sshd_effective["exit_status"] != 0:
            commands.append(_run_command(client, "cat /etc/ssh/sshd_config", timeout=runtime.command_timeout_seconds, runtime=runtime))
    elif profile.checks["ssh_hardening"]:
        _progress(progress_callback, "Checking SSH hardening...")
        commands.append(_run_command(client, "cat /etc/ssh/sshd_config", timeout=runtime.command_timeout_seconds, runtime=runtime))

    needs_systemctl = profile.checks["firewall_checks"] or profile.checks["logging_checks"]
    if needs_systemctl and _command_exists(client, "systemctl", commands, runtime):
        if profile.checks["firewall_checks"]:
            _progress(progress_callback, "Checking Linux configuration indicators...")
            commands.append(_run_command(client, "systemctl is-active ufw", timeout=runtime.command_timeout_seconds, runtime=runtime))
            commands.append(_run_command(client, "systemctl is-active firewalld", timeout=runtime.command_timeout_seconds, runtime=runtime))
        if profile.checks["logging_checks"]:
            _progress(progress_callback, "Checking Linux configuration indicators...")
            commands.append(_run_command(client, "systemctl is-active auditd", timeout=runtime.command_timeout_seconds, runtime=runtime))
            commands.append(_run_command(client, "systemctl is-active rsyslog", timeout=runtime.command_timeout_seconds, runtime=runtime))
            commands.append(_run_command(client, "systemctl is-active systemd-journald", timeout=runtime.command_timeout_seconds, runtime=runtime))

    if profile.checks["firewall_checks"] and _command_exists(client, "ufw", commands, runtime):
        commands.append(_run_command(client, "ufw status", timeout=runtime.command_timeout_seconds, runtime=runtime))
    if profile.checks["firewall_checks"] and _command_exists(client, "firewall-cmd", commands, runtime):
        commands.append(_run_command(client, "firewall-cmd --state", timeout=runtime.command_timeout_seconds, runtime=runtime))

    commands.append(_run_command(client, "hostname", timeout=runtime.command_timeout_seconds, runtime=runtime))
    if profile.checks["password_policy_checks"]:
        _progress(progress_callback, "Checking Linux configuration indicators...")
        commands.append(_run_command(client, "cat /etc/login.defs", timeout=runtime.command_timeout_seconds, runtime=runtime))
        commands.append(_run_command(client, "cat /etc/security/pwquality.conf", timeout=runtime.command_timeout_seconds, runtime=runtime))
    if profile.checks["temp_directory_checks"]:
        _progress(progress_callback, "Checking Linux configuration indicators...")
        commands.append(_run_command(client, "test -d /tmp", timeout=runtime.command_timeout_seconds, runtime=runtime))
        commands.append(_run_command(client, "test -d /var/tmp", timeout=runtime.command_timeout_seconds, runtime=runtime))
        commands.append(_run_command(client, "ls -ld /tmp", timeout=runtime.command_timeout_seconds, runtime=runtime))
        commands.append(_run_command(client, "ls -ld /var/tmp", timeout=runtime.command_timeout_seconds, runtime=runtime))

    if profile.checks["package_checks"]:
        _progress(progress_callback, "Checking package status...")
        manager_availability = {
            "apt": _command_exists(client, "apt", commands, runtime),
            "apt-get": _command_exists(client, "apt-get", commands, runtime),
            "dnf": _command_exists(client, "dnf", commands, runtime),
            "yum": _command_exists(client, "yum", commands, runtime),
            "pacman": _command_exists(client, "pacman", commands, runtime),
            "zypper": _command_exists(client, "zypper", commands, runtime),
        }
        package_manager = _select_package_manager_for_commands(
            os_release_output=os_release["stdout"],
            manager_availability=manager_availability,
        )
        if package_manager is not None:
            commands.append(_run_command(client, PACKAGE_MANAGER_COMMANDS[package_manager], timeout=runtime.command_timeout_seconds, runtime=runtime))

    return commands


def _command_exists(
    client: Any,
    executable: str,
    commands: list[dict[str, Any]],
    runtime: _AuditRuntime | None = None,
) -> bool:
    command = f"command -v {executable}"
    result = _run_command(
        client,
        command,
        timeout=runtime.command_timeout_seconds if runtime else COMMAND_TIMEOUT_SECONDS,
        runtime=runtime,
    )
    commands.append(result)
    return result["exit_status"] == 0 and bool(result["stdout"].strip())


def _apply_command_status(result: dict[str, Any], commands: list[dict[str, Any]]) -> None:
    completed = sum(1 for command in commands if command.get("success"))
    failed_commands = [
        command for command in commands if _is_actionable_command_failure(command)
    ]
    result["checks_completed"] = completed
    result["checks_failed"] = len(failed_commands)
    result["partial_failures"] = len(failed_commands)
    if not failed_commands:
        return

    result["status"] = STATUS_PARTIAL if completed else STATUS_FAILED
    if any(command.get("timed_out") for command in failed_commands):
        result["error_code"] = ERROR_COMMAND_TIMEOUT
        result["error_message"] = "One or more SSH audit commands timed out."
    else:
        result["error_code"] = ERROR_COMMAND_FAILED
        result["error_message"] = "One or more SSH audit commands could not complete."
    result["notes"].append(result["error_message"])


def _apply_performance_summary(
    result: dict[str, Any],
    commands: list[dict[str, Any]],
    runtime: _AuditRuntime,
) -> None:
    result["checks_planned"] = len(commands)
    result["checks_skipped"] = sum(1 for command in commands if command.get("skipped"))
    result["timed_out_commands"] = sum(1 for command in commands if command.get("timed_out"))
    result["total_duration_seconds"] = round(runtime.elapsed(), 3)
    completed_commands = [command for command in commands if not command.get("skipped")]
    slowest = max(
        completed_commands,
        key=lambda command: float(command.get("duration_seconds") or 0.0),
        default=None,
    )
    if slowest:
        result["slowest_command_name"] = slowest.get("command_name") or slowest.get("command")
        result["slowest_command_duration_seconds"] = slowest.get("duration_seconds")
    notes = result["performance_notes"]
    if result["timed_out_commands"]:
        notes.append(f"{result['timed_out_commands']} command(s) timed out.")
    if result["checks_skipped"]:
        notes.append(
            f"{result['checks_skipped']} check(s) skipped because the SSH audit time budget was exceeded."
        )


def _finalize_credentialed_result(
    result: dict[str, Any],
    *,
    username: str,
    auth_method: str,
    started_at: str,
) -> dict[str, Any]:
    ended_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result["credentialed_audit"] = _build_credentialed_audit_result(
        result=result,
        username=username,
        auth_method=auth_method,
        started_at=started_at,
        ended_at=ended_at,
    )
    return result


def _build_credentialed_audit_result(
    *,
    result: dict[str, Any],
    username: str,
    auth_method: str,
    started_at: str,
    ended_at: str,
) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    error = build_error(
        error_code=result.get("error_code"),
        message=str(result.get("error_message") or ""),
        source=SOURCE,
        check_name="Authenticated SSH Audit",
        safe_detail=str(result.get("debug_details") or ""),
    )
    if error:
        errors.append(error)

    commands = list(result.get("commands") or [])
    checks = [_normalised_check_from_command(index, command) for index, command in enumerate(commands, start=1)]
    findings = [finding_to_dict(finding) for finding in result.get("findings", [])]
    ssh_hardening_findings = [finding for finding in findings if finding.get("source") == "ssh_hardening"]

    audit_result = CredentialedAuditResult(
        source=SOURCE,
        module_name="Authenticated SSH Audit",
        status=str(result.get("status") or STATUS_SKIPPED),
        target=str(result.get("target") or ""),
        authenticated=bool(result.get("authenticated")),
        auth_method=auth_method,
        username=username,
        profile=str(result.get("audit_profile") or ""),
        started_at=started_at,
        ended_at=ended_at,
        duration_seconds=float(result.get("total_duration_seconds") or 0.0),
        checks_planned=int(result.get("checks_planned") or len(commands)),
        checks_completed=int(result.get("checks_completed") or 0),
        checks_failed=int(result.get("checks_failed") or 0),
        checks_skipped=int(result.get("checks_skipped") or 0),
        findings=findings,
        summary={
            "package_manager": result.get("package_manager"),
            "package_update_count": result.get("package_update_count"),
            "package_update_sample": result.get("package_update_sample") or [],
            "package_check_status": result.get("package_check_status"),
            "ssh_hardening_checked": bool(result.get("ssh_hardening_checked")),
            "ssh_hardening_source": _ssh_hardening_source(commands),
            "settings_checked": _sshd_settings_checked(commands),
            "risky_settings_count": len(ssh_hardening_findings),
            "linux_config_audit_checked": bool(result.get("linux_config_audit_checked")),
            "firewall_status": result.get("firewall_status") or {},
            "logging_status": result.get("logging_status") or {},
            "password_policy_indicators": result.get("password_policy_indicators") or {},
            "temp_directory_permissions": result.get("temp_directory_permissions") or {},
        },
        errors=errors,
        limitations=[
            "Authenticated SSH audit uses read-only commands and depends on the permissions of the provided account.",
            "Package and Linux configuration checks are indicators and should be reviewed in operational context.",
        ],
        performance={
            "connection_timeout_seconds": result.get("connection_timeout_seconds"),
            "command_timeout_seconds": result.get("command_timeout_seconds"),
            "audit_timeout_seconds": result.get("audit_timeout_seconds"),
            "total_duration_seconds": result.get("total_duration_seconds"),
            "timed_out_commands": result.get("timed_out_commands"),
            "slowest_command_name": result.get("slowest_command_name"),
            "slowest_command_duration_seconds": result.get("slowest_command_duration_seconds"),
            "performance_notes": result.get("performance_notes") or [],
        },
        metadata={
            "port": result.get("port"),
            "os_family": result.get("os_family"),
            "hostname": result.get("hostname"),
            "kernel_summary": result.get("kernel_summary"),
            "profile_description": result.get("profile_description"),
            "checks_enabled": result.get("checks_enabled") or [],
            "profile_checks_skipped": result.get("profile_checks_skipped") or [],
            "checks": checks,
        },
    )
    return audit_result.to_dict()


def _normalised_check_from_command(index: int, command: dict[str, Any]) -> dict[str, Any]:
    status = _normalised_command_status(command)
    return CredentialedCheckResult(
        check_id=f"ssh-command-{index:03d}",
        check_name=str(command.get("command_name") or command.get("command") or ""),
        source=_command_source(command),
        status=status,
        command_name=str(command.get("command_name") or command.get("command") or ""),
        duration_seconds=float(command.get("duration_seconds") or 0.0),
        findings_count=0,
        error_code=command.get("error_code"),
        error_message=str(command.get("stderr") or ""),
        evidence_summary=_command_evidence_summary(command),
        skipped_reason=str(command.get("stderr") or "") if status == STATUS_SKIPPED else "",
    ).to_dict()


def _normalised_command_status(command: dict[str, Any]) -> str:
    if command.get("skipped"):
        return "skipped"
    if command.get("timed_out"):
        return "timeout"
    if command.get("success"):
        return "success"
    return "failed"


def _command_source(command: dict[str, Any]) -> str:
    command_name = str(command.get("command") or "")
    if command_name in {"sshd -T", "cat /etc/ssh/sshd_config"}:
        return "ssh_hardening"
    if command_name in set(PACKAGE_MANAGER_COMMANDS.values()) or command_name.startswith("command -v "):
        return "package_audit"
    if command_name.startswith("systemctl ") or command_name in {
        "ufw status",
        "firewall-cmd --state",
        "cat /etc/login.defs",
        "cat /etc/security/pwquality.conf",
        "test -d /tmp",
        "test -d /var/tmp",
        "ls -ld /tmp",
        "ls -ld /var/tmp",
    }:
        return "linux_config_audit"
    return SOURCE


def _command_evidence_summary(command: dict[str, Any]) -> str:
    stdout = str(command.get("stdout") or "")
    stderr = str(command.get("stderr") or "")
    if stdout:
        return safe_truncate(stdout, max_chars=160)
    if stderr:
        return safe_truncate(stderr, max_chars=160)
    if command.get("success"):
        return "Command completed."
    return ""


def _auth_method(key_path: Path | None) -> str:
    return "key" if key_path is not None else "password"


def _ssh_hardening_source(commands: list[dict[str, Any]]) -> str:
    if _command_was_successful(commands, "sshd -T"):
        return "sshd -T"
    if _command_was_successful(commands, "cat /etc/ssh/sshd_config"):
        return "sshd_config fallback"
    return ""


def _sshd_settings_checked(commands: list[dict[str, Any]]) -> list[str]:
    command_by_name = {command["command"]: command for command in commands}
    sshd_config = command_by_name.get("sshd -T") or command_by_name.get("cat /etc/ssh/sshd_config")
    if not sshd_config:
        return []
    parsed = _parse_sshd_config(str(sshd_config.get("raw_stdout") or sshd_config.get("stdout") or ""))
    return sorted(key for key in parsed if key in {"passwordauthentication", "permitrootlogin"})


def _is_actionable_command_failure(command: dict[str, Any]) -> bool:
    if command.get("timed_out"):
        return True
    if command.get("exit_status") in (0, None):
        return False

    command_name = str(command.get("command") or "")
    if command_name.startswith("command -v "):
        return False
    if command_name.startswith("systemctl is-active "):
        return False
    if command_name.startswith("test -d "):
        return False
    if command_name in {"ufw status", "firewall-cmd --state", "cat /etc/security/pwquality.conf"}:
        return False
    if command_name in set(PACKAGE_MANAGER_COMMANDS.values()):
        return False
    return True


def _run_command(
    client: Any,
    command: str,
    timeout: float = COMMAND_TIMEOUT_SECONDS,
    runtime: _AuditRuntime | None = None,
) -> dict[str, Any]:
    if runtime is not None and not runtime.has_budget():
        return runtime.skip_command(command)

    started = time.perf_counter()
    stdout = None
    stderr = None
    try:
        effective_timeout = min(float(timeout), runtime.remaining()) if runtime is not None else float(timeout)
        if effective_timeout <= 0:
            return runtime.skip_command(command) if runtime is not None else _skipped_command(command, 0.0)
        stdin, stdout, stderr = client.exec_command(command, timeout=effective_timeout)
        if hasattr(stdout, "channel") and hasattr(stdout.channel, "settimeout"):
            stdout.channel.settimeout(effective_timeout)
        stdin.close()
        stdout_text = stdout.read().decode("utf-8", errors="replace")
        stderr_text = stderr.read().decode("utf-8", errors="replace")
        exit_status = stdout.channel.recv_exit_status()
        duration = round(time.perf_counter() - started, 3)
        return {
            "command": command,
            "command_name": command,
            "success": exit_status == 0,
            "exit_status": exit_status,
            "stdout": _truncate(stdout_text.strip()),
            "stderr": _truncate(stderr_text.strip(), max_chars=STDERR_MAX_CHARS),
            "raw_stdout": stdout_text.strip(),
            "raw_stderr": stderr_text.strip(),
            "error_code": None if exit_status == 0 else ERROR_COMMAND_FAILED,
            "duration_seconds": duration,
            "timed_out": False,
        }
    except (socket.timeout, TimeoutError):
        _close_command_stream(stdout)
        _close_command_stream(stderr)
        duration = round(time.perf_counter() - started, 3)
        return {
            "command": command,
            "command_name": command,
            "success": False,
            "exit_status": None,
            "stdout": "",
            "stderr": "Command timed out.",
            "raw_stdout": "",
            "raw_stderr": "Command timed out.",
            "error_code": ERROR_COMMAND_TIMEOUT,
            "duration_seconds": duration,
            "timed_out": True,
        }
    except Exception as exc:  # pragma: no cover - defensive wrapper.
        duration = round(time.perf_counter() - started, 3)
        return {
            "command": command,
            "command_name": command,
            "success": False,
            "exit_status": None,
            "stdout": "",
            "stderr": "Command failed.",
            "raw_stdout": "",
            "raw_stderr": "Command failed.",
            "error_code": ERROR_COMMAND_FAILED,
            "duration_seconds": duration,
            "timed_out": False,
            "debug_details": exc.__class__.__name__,
        }


def _skipped_command(command: str, elapsed_seconds: float) -> dict[str, Any]:
    return {
        "command": command,
        "command_name": command,
        "success": False,
        "exit_status": None,
        "stdout": "",
        "stderr": "Command skipped because the SSH audit time budget was exceeded.",
        "raw_stdout": "",
        "raw_stderr": "Command skipped because the SSH audit time budget was exceeded.",
        "error_code": ERROR_AUDIT_TIME_BUDGET_EXCEEDED,
        "duration_seconds": 0.0,
        "timed_out": False,
        "skipped": True,
        "elapsed_seconds": round(elapsed_seconds, 3),
    }


def _close_command_stream(stream: Any) -> None:
    if stream is None:
        return
    channel = getattr(stream, "channel", None)
    if channel is not None and hasattr(channel, "close"):
        try:
            channel.close()
        except Exception:
            return


def _build_findings(
    host: str,
    port: int,
    commands: list[dict[str, Any]],
    package_summary: dict[str, Any],
    linux_config_summary: dict[str, Any],
    profile: AuditProfile,
) -> list[Finding]:
    findings = [
        _create_evidence_finding(
            title="SSH Login Successful",
            severity="Informational",
            category="Credentialed Access",
            affected_host=host,
            affected_port=port,
            service="ssh",
            evidence_details=build_evidence(
                summary="Authenticated SSH session established using the provided username.",
                source=SOURCE,
                command_name="ssh authentication",
                command_used_safe_label="SSH authentication",
                observed_value="authenticated",
                expected_value="authenticated",
                confidence_reason="Paramiko established one SSH session with explicitly provided credentials.",
                limitation="Checks are limited by the permission level of the provided account.",
            ),
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
            _create_evidence_finding(
                title="OS Information Collected",
                severity="Informational",
                category="System Information",
                affected_host=host,
                affected_port=port,
                service="ssh",
                evidence_details=build_evidence(
                    summary=os_evidence,
                    source=SOURCE,
                    command_name="uname -a; cat /etc/os-release",
                    command_used_safe_label="OS identification commands",
                    observed_value=os_evidence,
                    expected_value="Linux OS information available",
                    confidence_reason="OS family and kernel summary were collected through the authenticated SSH session.",
                    limitation="Reported values depend on what the provided account can read.",
                ),
                confidence="High",
                impact="OS and kernel metadata can support patch verification and asset inventory.",
                recommendation="Use OS and kernel information for patch verification and asset inventory.",
                verification="Review uname -a and /etc/os-release output collected through the authenticated SSH session.",
                limitation="Reported values depend on what the provided account can read.",
                source=SOURCE,
            )
        )

    sshd_config = command_by_name.get("sshd -T")
    if sshd_config and sshd_config.get("exit_status") != 0:
        sshd_config = command_by_name.get("cat /etc/ssh/sshd_config")
    if not sshd_config:
        sshd_config = command_by_name.get("cat /etc/ssh/sshd_config")
    if sshd_config:
        findings.extend(_sshd_findings(host, port, sshd_config))

    if _linux_details_available(commands):
        if profile.checks["package_checks"]:
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
    config = _parse_sshd_config(
        str(sshd_config.get("raw_stdout") or sshd_config.get("stdout") or "")
    )
    source_label = "sshd -T" if sshd_config.get("command") == "sshd -T" else "sshd_config fallback"

    if config.get("passwordauthentication") == "yes":
        findings.append(
            _create_evidence_finding(
                title="SSH Password Authentication Enabled",
                severity="Medium",
                category="SSH Configuration",
                affected_host=host,
                affected_port=port,
                service="ssh",
                evidence_details=build_evidence(
                    summary="Effective SSH setting passwordauthentication=yes; expected no.",
                    source="ssh_hardening",
                    command_name=source_label,
                    command_used_safe_label=source_label,
                    observed_value="passwordauthentication=yes",
                    expected_value="passwordauthentication=no",
                    confidence_reason="The effective SSH configuration was parsed from a read-only SSH configuration command.",
                    limitation="Effective SSH configuration may vary by match blocks or service-specific deployment context.",
                ),
                confidence="High",
                impact="Password-based SSH access may increase exposure to credential misuse and password attacks.",
                recommendation="Disable password authentication where possible and use SSH keys.",
                verification="Run sshd -T and check passwordauthentication.",
                limitation="Effective SSH configuration may vary by match blocks or service-specific deployment context.",
                source="ssh_hardening",
            )
        )

    if config.get("permitrootlogin") == "yes":
        findings.append(
            _create_evidence_finding(
                title="SSH Root Login Enabled",
                severity="High",
                category="SSH Configuration",
                affected_host=host,
                affected_port=port,
                service="ssh",
                evidence_details=build_evidence(
                    summary="Effective SSH setting permitrootlogin=yes; expected no.",
                    source="ssh_hardening",
                    command_name=source_label,
                    command_used_safe_label=source_label,
                    observed_value="permitrootlogin=yes",
                    expected_value="permitrootlogin=no",
                    confidence_reason="The effective SSH configuration was parsed from a read-only SSH configuration command.",
                    limitation="Effective SSH configuration may vary by match blocks or service-specific deployment context.",
                ),
                confidence="High",
                impact="Direct root SSH login increases the impact of credential compromise.",
                recommendation="Disable direct root login and use a named user with privilege escalation where required.",
                verification="Run sshd -T and check permitrootlogin.",
                limitation="Effective SSH configuration may vary by match blocks or service-specific deployment context.",
                source="ssh_hardening",
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


def _parse_sshd_config(output: str) -> dict[str, str]:
    config: dict[str, str] = {}
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            config[parts[0].lower()] = parts[1].strip().lower()
    return config


def _skipped_package_summary(commands: list[dict[str, Any]]) -> dict[str, Any]:
    command_by_name = {str(command["command"]): command for command in commands}
    os_release = str(command_by_name.get("cat /etc/os-release", {}).get("stdout") or "")
    return {
        "os_family": detect_os_family(os_release),
        "package_manager": None,
        "available_package_managers": [],
        "package_update_count": None,
        "package_update_sample": [],
        "package_check_status": "skipped_by_profile",
        "package_check_command": None,
        "package_check_message": "Package checks were skipped by the selected audit profile.",
    }


def _os_evidence(uname: dict[str, Any], os_release: dict[str, Any]) -> str:
    os_release_output = str(os_release.get("stdout") or "")
    pretty_name = _os_release_value(os_release_output, "PRETTY_NAME")
    os_name = pretty_name or _os_release_value(os_release_output, "NAME")
    family = detect_os_family(os_release_output)
    kernel = safe_truncate(str(uname.get("stdout") or ""), max_chars=120)
    parts: list[str] = []
    if family and family != "Unknown Linux":
        parts.append(f"Linux host identified as {family}.")
    elif os_name:
        parts.append(f"Linux host identified as {safe_truncate(os_name, max_chars=80)}.")
    if kernel:
        parts.append("Kernel summary collected.")

    return safe_truncate(" ".join(parts), max_chars=300)


def _create_evidence_finding(
    *,
    title: str,
    severity: str,
    category: str,
    evidence_details: dict[str, Any],
    confidence: str,
    impact: str,
    recommendation: str,
    verification: str,
    limitation: str,
    source: str,
    affected_host: str | None = None,
    affected_port: int | None = None,
    affected_url: str | None = None,
    service: str | None = None,
) -> Finding:
    return create_finding(
        title=title,
        severity=severity,  # type: ignore[arg-type]
        category=category,
        affected_host=affected_host,
        affected_port=affected_port,
        affected_url=affected_url,
        service=service,
        evidence=evidence_summary(evidence_details),
        evidence_details=evidence_details,
        confidence=confidence,  # type: ignore[arg-type]
        impact=impact,
        recommendation=recommendation,
        verification=verification,
        limitation=limitation,
        source=source,
    )


def _os_release_value(output: str, key: str) -> str:
    prefix = f"{key}="
    for line in output.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].strip().strip('"')
    return ""


def _hostname_from_commands(commands: list[dict[str, Any]]) -> str:
    command_by_name = {command["command"]: command for command in commands}
    output = str(command_by_name.get("hostname", {}).get("stdout") or "")
    for line in output.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def _kernel_summary_from_commands(commands: list[dict[str, Any]]) -> str:
    command_by_name = {command["command"]: command for command in commands}
    output = str(command_by_name.get("uname -a", {}).get("stdout") or "")
    return _truncate(output.strip(), max_chars=240)


def _command_was_successful(commands: list[dict[str, Any]], command_name: str) -> bool:
    for command in commands:
        if command.get("command") == command_name:
            return command.get("exit_status") == 0
    return False


def _command_report(command: dict[str, Any]) -> dict[str, Any]:
    return {
        "command": command["command"],
        "command_name": command.get("command_name", command["command"]),
        "success": bool(command.get("success")),
        "exit_status": command["exit_status"],
        "stdout": command["stdout"],
        "stderr": command["stderr"],
        "error_code": command.get("error_code"),
        "duration_seconds": command.get("duration_seconds", 0.0),
        "timed_out": command["timed_out"],
        "skipped": bool(command.get("skipped")),
    }


def _truncate(value: str, max_chars: int = MAX_OUTPUT_CHARS) -> str:
    return safe_truncate(value, max_chars=max_chars)


def _progress(callback: Callable[[str], None] | None, message: str) -> None:
    if callback is not None:
        callback(message)
