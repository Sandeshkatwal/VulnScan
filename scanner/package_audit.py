"""Read-only Linux package and patch audit helpers."""

from __future__ import annotations

from typing import Any

from scanner.finding import Finding, create_finding


SOURCE = "package_audit"
SUPPORTED_PACKAGE_MANAGERS = ("apt", "dnf", "yum", "pacman", "zypper")
PACKAGE_MANAGER_COMMANDS = {
    "apt": "apt list --upgradable",
    "apt-get": "apt list --upgradable",
    "dnf": "dnf check-update",
    "yum": "yum check-update",
    "pacman": "pacman -Qu",
    "zypper": "zypper list-updates",
}


def detect_os_family(os_release_output: str) -> str:
    """Return a normalized Linux OS family from /etc/os-release."""
    values = _parse_os_release(os_release_output)
    identifiers = " ".join(
        [
            values.get("id", ""),
            values.get("id_like", ""),
            values.get("name", ""),
            values.get("pretty_name", ""),
        ]
    ).lower()

    if any(value in identifiers for value in ("debian", "ubuntu", "kali", "parrot")):
        return "Debian/Kali/Parrot/Ubuntu"
    if any(value in identifiers for value in ("fedora", "rhel", "rocky", "alma", "centos", "red hat")):
        return "Fedora/RHEL/Rocky/Alma"
    if "arch" in identifiers:
        return "Arch"
    if any(value in identifiers for value in ("opensuse", "suse", "sles")):
        return "openSUSE/SUSE"
    if identifiers.strip():
        return "Unknown Linux"
    return "Unknown Linux"


def build_package_audit_summary(commands: list[dict[str, Any]]) -> dict[str, Any]:
    """Build structured package-audit output from sanitized command results."""
    command_by_name = {str(command["command"]): command for command in commands}
    os_release = _command_output(command_by_name.get("cat /etc/os-release", {}))
    os_family = detect_os_family(os_release)
    available_managers = _available_package_managers(command_by_name)
    package_manager = _select_package_manager(os_family, available_managers)

    summary: dict[str, Any] = {
        "os_family": os_family,
        "package_manager": package_manager,
        "available_package_managers": available_managers,
        "package_update_count": None,
        "package_update_sample": [],
        "package_check_status": "not_run",
        "package_check_command": None,
        "package_check_message": "",
    }

    if package_manager is None:
        summary["package_check_status"] = "unsupported_package_manager"
        summary["package_check_message"] = "No supported package manager was detected."
        return summary

    check_command = PACKAGE_MANAGER_COMMANDS[package_manager]
    summary["package_check_command"] = check_command
    check_result = command_by_name.get(check_command)
    if check_result is None:
        summary["package_check_status"] = "command_not_run"
        summary["package_check_message"] = f"{check_command} was not run."
        return summary

    if check_result.get("timed_out"):
        summary["package_check_status"] = "timeout"
        summary["package_check_message"] = f"{check_command} timed out."
        return summary

    if _permission_denied(check_result):
        summary["package_check_status"] = "permission_denied"
        summary["package_check_message"] = f"{check_command} could not complete due to permissions."
        return summary

    updates = _parse_updates(package_manager, check_result)
    summary["package_update_count"] = len(updates)
    summary["package_update_sample"] = updates[:20]

    if updates:
        summary["package_check_status"] = "updates_available"
        summary["package_check_message"] = f"{len(updates)} package updates reported."
        return summary

    if _check_command_failed(package_manager, check_result):
        summary["package_check_status"] = "command_failed"
        summary["package_check_message"] = f"{check_command} returned exit status {check_result.get('exit_status')}."
        return summary

    summary["package_check_status"] = "no_updates"
    summary["package_check_message"] = "Package manager did not report available updates."

    return summary


def build_package_findings(
    host: str,
    port: int,
    package_summary: dict[str, Any],
) -> list[Finding]:
    """Create standard findings for package manager and patch status."""
    findings = [_package_manager_detected_finding(host, port, package_summary)]

    status = str(package_summary.get("package_check_status") or "")
    if status == "updates_available":
        findings.append(_updates_available_finding(host, port, package_summary))
    elif status == "no_updates":
        findings.append(_no_updates_finding(host, port, package_summary))
    elif status in {
        "unsupported_package_manager",
        "command_not_run",
        "timeout",
        "permission_denied",
        "command_failed",
    }:
        findings.append(_unable_to_complete_finding(host, port, package_summary))

    return findings


def _package_manager_detected_finding(
    host: str,
    port: int,
    package_summary: dict[str, Any],
) -> Finding:
    manager = package_summary.get("package_manager") or "none"
    available = package_summary.get("available_package_managers") or []
    evidence = (
        f"OS family: {package_summary.get('os_family')}; "
        f"selected package manager: {manager}; "
        f"detected managers: {', '.join(available) if available else 'none'}."
    )
    return create_finding(
        title="Package Manager Detected",
        severity="Informational",
        category="Patch Management",
        affected_host=host,
        affected_port=port,
        service="ssh",
        evidence=evidence,
        confidence="High" if manager != "none" else "Medium",
        impact="Package manager information supports patch verification and host inventory.",
        recommendation="Use package manager information for patch verification.",
        verification="Review /etc/os-release and command -v results from the authenticated SSH audit.",
        limitation="Package manager detection does not confirm whether all security patches are installed.",
        source=SOURCE,
    )


def _updates_available_finding(
    host: str,
    port: int,
    package_summary: dict[str, Any],
) -> Finding:
    update_count = int(package_summary.get("package_update_count") or 0)
    sample = [str(item) for item in package_summary.get("package_update_sample") or []]
    sample_text = ", ".join(sample) if sample else "sample unavailable"
    return create_finding(
        title="Package Updates Available",
        severity="Medium",
        category="Patch Management",
        affected_host=host,
        affected_port=port,
        service="ssh",
        evidence=f"{update_count} available updates reported by {package_summary.get('package_manager')}. Sample packages: {sample_text}.",
        confidence="Medium",
        impact="Available package updates may include reliability fixes and security patches.",
        recommendation="Review and apply updates according to change management.",
        verification="Re-run the package manager update check or run VulScan SSH audit again.",
        limitation="This check reports available package updates, not necessarily confirmed exploitable vulnerabilities.",
        source=SOURCE,
    )


def _no_updates_finding(
    host: str,
    port: int,
    package_summary: dict[str, Any],
) -> Finding:
    return create_finding(
        title="No Package Updates Detected",
        severity="Informational",
        category="Patch Management",
        affected_host=host,
        affected_port=port,
        service="ssh",
        evidence=f"{package_summary.get('package_manager')} did not report available updates.",
        confidence="Medium",
        impact="No package updates were reported by the selected package manager at scan time.",
        recommendation="Continue regular patch monitoring.",
        verification="Re-run the package manager update check or run VulScan SSH audit again.",
        limitation="Results depend on package metadata available on the host.",
        source=SOURCE,
    )


def _unable_to_complete_finding(
    host: str,
    port: int,
    package_summary: dict[str, Any],
) -> Finding:
    status = str(package_summary.get("package_check_status") or "unknown")
    message = str(package_summary.get("package_check_message") or "Package check did not complete.")
    severity = "Low" if status in {"permission_denied", "timeout", "command_failed"} else "Informational"
    return create_finding(
        title="Package Check Unable to Complete",
        severity=severity,
        category="Patch Management",
        affected_host=host,
        affected_port=port,
        service="ssh",
        evidence=f"{status}: {message}",
        confidence="Medium",
        impact="VulScan could not confirm package update status for this host.",
        recommendation="Verify patch status manually or provide an account with enough read-only access.",
        verification="Review package manager availability and the read-only package check command.",
        limitation="VulScan could not confirm package update status.",
        source=SOURCE,
    )


def _available_package_managers(command_by_name: dict[str, dict[str, Any]]) -> list[str]:
    available: list[str] = []
    if _command_available(command_by_name, "apt"):
        available.append("apt")
    if _command_available(command_by_name, "apt-get") and "apt" not in available:
        available.append("apt-get")
    for manager in ("dnf", "yum", "pacman", "zypper"):
        if _command_available(command_by_name, manager):
            available.append(manager)
    return available


def _select_package_manager(os_family: str, available: list[str]) -> str | None:
    if os_family == "Debian/Kali/Parrot/Ubuntu":
        if "apt" in available:
            return "apt"
        if "apt-get" in available:
            return "apt-get"
    if os_family == "Fedora/RHEL/Rocky/Alma":
        if "dnf" in available:
            return "dnf"
        if "yum" in available:
            return "yum"
    if os_family == "Arch" and "pacman" in available:
        return "pacman"
    if os_family == "openSUSE/SUSE" and "zypper" in available:
        return "zypper"

    for manager in SUPPORTED_PACKAGE_MANAGERS:
        if manager in available:
            return manager
    if "apt-get" in available:
        return "apt-get"
    return None


def _command_available(command_by_name: dict[str, dict[str, Any]], executable: str) -> bool:
    result = command_by_name.get(f"command -v {executable}")
    return bool(result and result.get("exit_status") == 0 and str(result.get("stdout") or "").strip())


def _parse_updates(package_manager: str, result: dict[str, Any]) -> list[str]:
    output = _command_output(result)
    if package_manager in {"apt", "apt-get"}:
        return _parse_apt_updates(output)
    if package_manager in {"dnf", "yum"}:
        return _parse_dnf_yum_updates(output)
    if package_manager == "pacman":
        return _parse_pacman_updates(output)
    if package_manager == "zypper":
        return _parse_zypper_updates(output)
    return []


def _parse_apt_updates(output: str) -> list[str]:
    packages: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("listing..."):
            continue
        package_name = stripped.split("/", 1)[0].strip()
        if package_name:
            packages.append(package_name)
    return packages


def _parse_dnf_yum_updates(output: str) -> list[str]:
    packages: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("Last metadata", "Loaded plugins", "Available Packages")):
            continue
        columns = stripped.split()
        if len(columns) < 3:
            continue
        first_column = columns[0]
        if "." in first_column:
            first_column = first_column.rsplit(".", 1)[0]
        if first_column and not first_column.startswith(("Obsoleting", "Security:")):
            packages.append(first_column)
    return packages


def _parse_pacman_updates(output: str) -> list[str]:
    packages: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        packages.append(stripped.split()[0])
    return packages


def _parse_zypper_updates(output: str) -> list[str]:
    packages: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("Repository", "--", "S |", "Loading", "Reading")):
            continue
        if "|" in stripped:
            parts = [part.strip() for part in stripped.split("|")]
            if len(parts) >= 3 and parts[2]:
                packages.append(parts[2])
            continue
        packages.append(stripped.split()[0])
    return packages


def _check_command_failed(package_manager: str, result: dict[str, Any]) -> bool:
    exit_status = result.get("exit_status")
    if package_manager in {"dnf", "yum", "zypper"}:
        return exit_status not in (0, 100)
    return exit_status not in (0,)


def _permission_denied(result: dict[str, Any]) -> bool:
    text = f"{_command_output(result)}\n{result.get('raw_stderr') or result.get('stderr') or ''}".lower()
    return "permission denied" in text or "not permitted" in text


def _command_output(result: dict[str, Any]) -> str:
    return str(result.get("raw_stdout") or result.get("stdout") or "")


def _parse_os_release(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip().lower()] = value.strip().strip('"').strip("'")
    return values
