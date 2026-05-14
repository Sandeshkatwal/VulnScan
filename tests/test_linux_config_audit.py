from pathlib import Path

from scanner.audit_profiles import get_audit_profile
from scanner.linux_config_audit import build_linux_config_audit_summary, build_linux_config_findings


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


def test_password_policy_indicators_find_weak_values() -> None:
    login_defs = (FIXTURES / "login_defs_weak.txt").read_text(encoding="utf-8")
    pwquality = (FIXTURES / "pwquality_weak.txt").read_text(encoding="utf-8")
    profile = get_audit_profile("detailed")

    summary = build_linux_config_audit_summary(
        commands=[
            _command("hostname", "lab-host"),
            _command("cat /etc/login.defs", login_defs),
            _command("cat /etc/security/pwquality.conf", pwquality),
        ],
        os_family="Debian/Kali/Parrot/Ubuntu",
        checks=profile.checks,
    )
    findings = build_linux_config_findings("host.example", 22, summary)
    titles = {finding.title for finding in findings}

    assert "Weak Password Age Policy Indicator" in titles
    assert "Password Quality Policy May Be Weak" in titles


def test_reasonable_password_policy_has_no_password_findings() -> None:
    login_defs = (FIXTURES / "login_defs_reasonable.txt").read_text(encoding="utf-8")
    pwquality = (FIXTURES / "pwquality_reasonable.txt").read_text(encoding="utf-8")
    profile = get_audit_profile("detailed")

    summary = build_linux_config_audit_summary(
        commands=[
            _command("hostname", "lab-host"),
            _command("cat /etc/login.defs", login_defs),
            _command("cat /etc/security/pwquality.conf", pwquality),
        ],
        os_family="Debian/Kali/Parrot/Ubuntu",
        checks=profile.checks,
    )
    findings = build_linux_config_findings("host.example", 22, summary)
    titles = {finding.title for finding in findings}

    assert "Weak Password Age Policy Indicator" not in titles
    assert "Password Quality Policy May Be Weak" not in titles


def test_standard_profile_skips_password_policy_findings() -> None:
    login_defs = (FIXTURES / "login_defs_weak.txt").read_text(encoding="utf-8")
    profile = get_audit_profile("standard")

    summary = build_linux_config_audit_summary(
        commands=[
            _command("hostname", "lab-host"),
            _command("cat /etc/login.defs", login_defs),
        ],
        os_family="Debian/Kali/Parrot/Ubuntu",
        checks=profile.checks,
    )
    findings = build_linux_config_findings("host.example", 22, summary)
    titles = {finding.title for finding in findings}

    assert "Weak Password Age Policy Indicator" not in titles
