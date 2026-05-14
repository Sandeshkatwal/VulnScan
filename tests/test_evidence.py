import json

from scanner.evidence import build_evidence, evidence_summary, redact_secrets, safe_truncate
from scanner.finding import create_finding, finding_to_dict


def test_secret_assignments_are_redacted() -> None:
    text, redacted = redact_secrets("password=hunter2 token=abc api_key=xyz passwd=test")

    assert redacted is True
    assert "hunter2" not in text
    assert "abc" not in text
    assert "xyz" not in text
    assert text.count("[REDACTED]") == 4


def test_private_key_block_is_redacted() -> None:
    value = "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\nafter"

    text, redacted = redact_secrets(value)

    assert redacted is True
    assert "fake" not in text
    assert "[REDACTED]" in text


def test_long_evidence_is_shortened() -> None:
    shortened = safe_truncate("a" * 400, max_chars=80)

    assert len(shortened) <= 80
    assert shortened.endswith("[truncated]")


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
