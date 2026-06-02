from typer.testing import CliRunner

from scanner.api_app import create_app
from scanner.api_security import API_KEY_ENV_VAR
from scanner.bug_bounty_scope import get_scope_decision, load_bug_bounty_scope
from scanner.bug_intelligence_metrics import build_bug_intelligence_metrics
from scanner.evidence import redact_secrets
from scanner.finding_fingerprint import build_finding_fingerprint
from scanner.main import app
from scanner.owasp_mapping import load_owasp_mapping


runner = CliRunner()


def test_release_smoke_imports_and_cli_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "VulScan" in result.output


def test_release_smoke_professional_scope_commands() -> None:
    listed = runner.invoke(app, ["scope", "list"])
    assert listed.exit_code == 0
    assert "Program Scope" in listed.output

    checked = runner.invoke(
        app,
        [
            "scope",
            "check",
            "--target",
            "127.0.0.1",
            "--scope-file",
            "data/programs/sample_program_scope.json",
        ],
    )
    assert checked.exit_code == 0
    assert "Program Scope Decision" in checked.output


def test_release_smoke_legacy_scope_alias_still_works() -> None:
    result = runner.invoke(
        app,
        [
            "scope",
            "check",
            "--target",
            "127.0.0.1",
            "--bug-bounty-scope",
            "data/bug_bounty/sample_program_scope.json",
        ],
    )
    assert result.exit_code == 0
    assert "Alias retained for compatibility" in result.output


def test_release_smoke_sample_scope_owasp_redaction_fingerprint_metrics(tmp_path) -> None:
    scope = load_bug_bounty_scope("data/programs/sample_program_scope.json")
    assert get_scope_decision("127.0.0.1", scope)["in_scope"] is True
    assert get_scope_decision("auth.thirdparty.local", scope)["in_scope"] is False

    assert load_owasp_mapping()
    redacted, changed = redact_secrets("Authorization: Bearer secret-token-value")
    assert changed is True
    assert "secret-token-value" not in redacted

    fingerprint = build_finding_fingerprint({"url": "http://127.0.0.1:8000/account?id=123", "issue_type": "idor_candidate"})
    assert fingerprint["fingerprint_hash"]
    assert "123" not in str(fingerprint)

    metrics = build_bug_intelligence_metrics(db_path=tmp_path / "release_smoke.db")
    assert metrics["bug_intelligence_metrics"]["enabled"] is True


def test_release_smoke_preferred_api_routes_require_key(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "release-key")
    client = create_app(remediation_db_path=tmp_path / "release_api.db")
    from fastapi.testclient import TestClient

    test_client = TestClient(client)
    missing = test_client.get("/program-scope/scopes")
    accepted = test_client.get("/program-scope/scopes", headers={"X-VulScan-API-Key": "release-key"})

    assert missing.status_code == 401
    assert accepted.status_code == 200
