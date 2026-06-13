from pathlib import Path

from scanner.api_reports import decode_report_id
from scanner.evidence_redaction import redact_secrets, validate_redaction


ROOT = Path(__file__).resolve().parents[2]


def test_redaction_still_removes_bearer_tokens() -> None:
    redacted = redact_secrets("Authorization: Bearer raw-secret-token-12345")
    assert "raw-secret-token-12345" not in redacted
    assert validate_redaction(redacted)["passed"] is True


def test_report_id_path_traversal_download_blocked() -> None:
    assert decode_report_id("..") is None
    assert decode_report_id("..\\secret") is None


def test_gitignore_keeps_secret_and_generated_paths_ignored() -> None:
    text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in text
    assert ".venv311/" in text
    assert "dashboard/node_modules/" in text
    assert "reports/beta_issues/*" in text


def test_auth_profile_sample_is_redacted() -> None:
    text = (ROOT / "data" / "auth_profiles" / "sample_session_profile.redacted.json").read_text(encoding="utf-8")
    lowered = text.lower()
    assert "[redacted" in lowered
    assert "bearer [redacted]" in lowered
    assert "password=" not in lowered
