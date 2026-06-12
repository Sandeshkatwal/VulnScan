from pathlib import Path

from scripts.check_no_secrets import scan_paths


def test_no_secrets_allows_redacted_placeholders(tmp_path: Path) -> None:
    sample = tmp_path / "safe.md"
    sample.write_text("Authorization: Bearer [REDACTED-BEARER]\nsecret=placeholder\n", encoding="utf-8")
    assert scan_paths([sample]) == []


def test_no_secrets_flags_raw_bearer_token(tmp_path: Path) -> None:
    sample = tmp_path / "unsafe.md"
    token = "Bearer " + "abc123rawtokenvalue"
    sample.write_text(f"Authorization: {token}\n", encoding="utf-8")
    findings = scan_paths([sample])
    assert findings
    assert findings[0].kind == "bearer token"
    assert "abc123rawtokenvalue" not in findings[0].preview
