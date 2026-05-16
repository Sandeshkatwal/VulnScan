from scanner.credentialed_result import (
    CredentialedAuditResult,
    CredentialedCheckResult,
    build_error,
)


def test_credentialed_audit_result_serialises_to_dictionary() -> None:
    result = CredentialedAuditResult(
        source="ssh_audit",
        module_name="Authenticated SSH Audit",
        status="success",
        target="192.0.2.10",
        authenticated=True,
        auth_method="password",
        username="sadmin",
        profile="standard",
        started_at="2026-05-16T10:00:00+00:00",
        ended_at="2026-05-16T10:00:02+00:00",
        duration_seconds=2.0,
        checks_planned=2,
        checks_completed=2,
        checks_failed=0,
        checks_skipped=0,
    )

    data = result.to_dict()

    assert data["source"] == "ssh_audit"
    assert data["status"] == "success"
    assert data["auth_method"] == "password"


def test_credentialed_check_result_serialises_to_dictionary() -> None:
    result = CredentialedCheckResult(
        check_id="ssh-command-001",
        check_name="uname -a",
        source="ssh_audit",
        status="success",
        command_name="uname -a",
        duration_seconds=0.1,
        findings_count=0,
    )

    data = result.to_dict()

    assert data["check_id"] == "ssh-command-001"
    assert data["status"] == "success"
    assert data["duration_seconds"] == 0.1


def test_normalised_error_serialises_without_secret_detail() -> None:
    error = build_error(
        error_code="SSH_AUTH_FAILED",
        message="SSH authentication failed. No audit commands were run.",
        source="ssh_audit",
        check_name="Authenticated SSH Audit",
        safe_detail="AuthenticationException",
    )

    assert error is not None
    assert error["error_code"] == "SSH_AUTH_FAILED"
    assert "SENSITIVE_VALUE" not in str(error)
