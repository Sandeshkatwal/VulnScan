from pathlib import Path

from scanner.package_audit import build_package_audit_summary, build_package_findings


FIXTURES = Path(__file__).parent / "fixtures"


def _command(command: str, stdout: str, exit_status: int = 0) -> dict[str, object]:
    return {
        "command": command,
        "stdout": stdout,
        "raw_stdout": stdout,
        "stderr": "",
        "raw_stderr": "",
        "exit_status": exit_status,
        "timed_out": False,
    }


def test_apt_upgradable_output_counts_packages() -> None:
    os_release = (FIXTURES / "os_release_debian.txt").read_text(encoding="utf-8")
    updates = (FIXTURES / "apt_upgradable_sample.txt").read_text(encoding="utf-8")

    summary = build_package_audit_summary(
        [
            _command("cat /etc/os-release", os_release),
            _command("command -v apt", "/usr/bin/apt"),
            _command("apt list --upgradable", updates),
        ]
    )

    assert summary["os_family"] == "Debian/Kali/Parrot/Ubuntu"
    assert summary["package_manager"] == "apt"
    assert summary["package_update_count"] == 3
    assert summary["package_update_sample"][:2] == ["openssl", "curl"]
    assert summary["package_check_status"] == "updates_available"


def test_apt_no_updates_output_reports_no_updates() -> None:
    os_release = (FIXTURES / "os_release_debian.txt").read_text(encoding="utf-8")
    no_updates = (FIXTURES / "apt_no_updates_sample.txt").read_text(encoding="utf-8")

    summary = build_package_audit_summary(
        [
            _command("cat /etc/os-release", os_release),
            _command("command -v apt", "/usr/bin/apt"),
            _command("apt list --upgradable", no_updates),
        ]
    )

    assert summary["package_update_count"] == 0
    assert summary["package_check_status"] == "no_updates"


def test_package_update_finding_sample_is_limited_to_ten() -> None:
    summary = {
        "os_family": "Debian/Kali/Parrot/Ubuntu",
        "package_manager": "apt",
        "available_package_managers": ["apt"],
        "package_update_count": 12,
        "package_update_sample": [f"package-{index}" for index in range(12)],
        "package_check_status": "updates_available",
        "package_check_command": "apt list --upgradable",
        "package_check_message": "12 package updates reported.",
    }

    findings = build_package_findings("host.example", 22, summary)
    update_finding = next(finding for finding in findings if finding.title == "Package Updates Available")

    assert len(update_finding.evidence_details["sample"]) == 10
    assert "package-10" not in update_finding.evidence
