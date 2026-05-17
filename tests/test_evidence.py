import json

from scanner.evidence import (
    WINDOWS_SAMPLE_MAX_ITEMS,
    build_evidence,
    evidence_summary,
    limited_sample,
    redact_secrets,
    safe_truncate,
)
from scanner.finding import create_finding, finding_to_dict


def test_secret_assignments_are_redacted() -> None:
    text, redacted = redact_secrets("password=hunter2 Password=Secret123 token=abc api_key=xyz passwd=test pwd=local")

    assert redacted is True
    assert "hunter2" not in text
    assert "Secret123" not in text
    assert "abc" not in text
    assert "xyz" not in text
    assert "local" not in text
    assert text.count("[REDACTED]") == 6


def test_authorization_schemes_are_redacted() -> None:
    value = "Authorization: Bearer fake-token\nAuthorization: Basic dXNlcjpwYXNz\nAuthorization: NTLM TlRMTVNTUAAB"

    text, redacted = redact_secrets(value)

    assert redacted is True
    assert "fake-token" not in text
    assert "dXNlcjpwYXNz" not in text
    assert "TlRMTVNTUAAB" not in text


def test_private_key_block_is_redacted() -> None:
    value = "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\nafter"

    text, redacted = redact_secrets(value)

    assert redacted is True
    assert "fake" not in text
    assert "[REDACTED]" in text


def test_windows_secret_patterns_are_redacted() -> None:
    value = (
        "Server=db;User Id=app;Password=Secret123;"
        "AccessToken=abc123 RefreshToken=def456 "
        "Credential: DOMAIN\\user:pass "
        "NTHASH=0123456789abcdef0123456789abcdef"
    )

    text, redacted = redact_secrets(value)

    assert redacted is True
    assert "Secret123" not in text
    assert "abc123" not in text
    assert "def456" not in text
    assert "DOMAIN\\user:pass" not in text
    assert "0123456789abcdef0123456789abcdef" not in text


def test_long_evidence_is_shortened() -> None:
    shortened = safe_truncate("a" * 400, max_chars=80)

    assert len(shortened) <= 80
    assert shortened.endswith("[truncated]")


def test_windows_hotfix_sample_can_be_limited_to_five_items() -> None:
    sample = limited_sample([f"KB{i}" for i in range(10)], limit=WINDOWS_SAMPLE_MAX_ITEMS)

    assert sample == ["KB0", "KB1", "KB2", "KB3", "KB4"]


def test_evidence_details_are_json_serializable_and_redacted() -> None:
    details = build_evidence(
        summary="Observed password=secret-value in fake output.",
        source="unit_test",
        observed_value="Authorization: Bearer fake-token",
        expected_value="no secrets",
    )
    finding = create_finding(
        title="Test Finding",
        severity="Informational",
        category="Testing",
        evidence=evidence_summary(details),
        evidence_details=details,
        confidence="High",
        impact="None.",
        recommendation="None.",
        verification="Unit test.",
        limitation="Unit test.",
        source="unit_test",
    )
    payload = finding_to_dict(finding)

    serialized = json.dumps(payload)
    assert "secret-value" not in serialized
    assert "fake-token" not in serialized
    assert payload["evidence_details"]["redacted"] is True
