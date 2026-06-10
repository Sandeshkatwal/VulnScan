from scanner.evidence_redaction import detect_secret_patterns, redact_secrets, validate_redaction


def test_evidence_redaction_patterns() -> None:
    samples = [
        ("Authorization: Bearer secret-demo-token", "[REDACTED-BEARER]"),
        ("Authorization: Basic dXNlcjpwYXNz", "[REDACTED-BASIC]"),
        ("Cookie: sessionid=abcdef123456", "[REDACTED-COOKIE]"),
        ("Set-Cookie: csrftoken=abcdef123456", "[REDACTED-COOKIE]"),
        ("sessionid=abcdef123456", "[REDACTED-SESSION]"),
        ("csrftoken=abcdef123456", "[REDACTED-CSRF]"),
        ("X-API-Key: abcdef1234567890", "[REDACTED-API-KEY]"),
        ("access_token=abcdef1234567890", "[REDACTED-TOKEN]"),
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepart", "[REDACTED-JWT]"),
        ("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", "[REDACTED-PRIVATE-KEY]"),
        ("password=secretpass", "[REDACTED-PASSWORD]"),
    ]
    for text, marker in samples:
        assert marker in redact_secrets(text)
        assert validate_redaction(redact_secrets(text))["passed"] is True


def test_validate_redaction_fails_when_secret_remains() -> None:
    assert detect_secret_patterns("Authorization: Bearer secret-demo-token")
    assert validate_redaction("Authorization: Bearer secret-demo-token")["passed"] is False
