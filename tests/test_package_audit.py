from pathlib import Path

from scanner.package_audit import build_package_audit_summary


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
