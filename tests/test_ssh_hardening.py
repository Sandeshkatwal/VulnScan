from pathlib import Path

from scanner.ssh_audit import _sshd_findings


FIXTURES = Path(__file__).parent / "fixtures"


def _command(output: str) -> dict[str, object]:
    return {
        "command": "sshd -T",
        "stdout": output,
        "raw_stdout": output,
        "exit_status": 0,
    }


def test_secure_sshd_config_has_no_hardening_findings() -> None:
    output = (FIXTURES / "sshd_T_secure.txt").read_text(encoding="utf-8")

    findings = _sshd_findings("host.example", 22, _command(output))

    assert findings == []


def test_weak_sshd_config_reports_password_and_root_login() -> None:
    output = (FIXTURES / "sshd_T_weak.txt").read_text(encoding="utf-8")

    findings = _sshd_findings("host.example", 22, _command(output))
    titles = {finding.title for finding in findings}
    password_finding = next(
        finding for finding in findings if finding.title == "SSH Password Authentication Enabled"
    )

    assert "SSH Password Authentication Enabled" in titles
    assert "SSH Root Login Enabled" in titles
    assert password_finding.evidence_details["observed_value"] == "passwordauthentication=yes"
    assert password_finding.evidence_details["expected_value"] == "passwordauthentication=no"
    assert "expected no" in password_finding.evidence
