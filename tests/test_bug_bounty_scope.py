from __future__ import annotations

import json

from typer.testing import CliRunner

from scanner.bug_bounty_scope import (
    BugBountyScopeError,
    get_scope_decision,
    is_domain_in_scope,
    is_ip_in_scope,
    is_url_in_scope,
    load_bug_bounty_scope,
)
from scanner.main import app


SAMPLE_SCOPE = "data/bug_bounty/sample_program_scope.json"


def test_load_valid_scope_file() -> None:
    scope = load_bug_bounty_scope(SAMPLE_SCOPE)

    assert scope["program_id"] == "demo-bug-bounty-program"
    assert scope["program_name"] == "Demo Bug Bounty Program"


def test_reject_malformed_scope_file(tmp_path) -> None:
    path = tmp_path / "bad_scope.json"
    path.write_text(json.dumps({"program_id": "missing-required-fields"}), encoding="utf-8")

    try:
        load_bug_bounty_scope(path)
    except BugBountyScopeError as exc:
        assert "missing required field" in str(exc)
    else:
        raise AssertionError("Malformed scope file should be rejected.")


def test_exact_domain_in_scope() -> None:
    scope = load_bug_bounty_scope(SAMPLE_SCOPE)

    assert is_domain_in_scope("demo-web.local", scope)


def test_wildcard_subdomain_in_scope() -> None:
    scope = load_bug_bounty_scope(SAMPLE_SCOPE)

    assert is_domain_in_scope("shop.demo-web.local", scope)


def test_wildcard_does_not_match_root_without_exact_rule(tmp_path) -> None:
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps(
            {
                "program_id": "demo",
                "program_name": "Demo",
                "in_scope": {"domains": ["*.example.local"], "urls": [], "api_base_urls": [], "ip_ranges": []},
                "out_of_scope": {"domains": [], "urls": [], "ip_ranges": []},
            }
        ),
        encoding="utf-8",
    )
    scope = load_bug_bounty_scope(path)

    assert not is_domain_in_scope("example.local", scope)
    assert is_domain_in_scope("www.example.local", scope)


def test_out_of_scope_overrides_in_scope() -> None:
    scope = load_bug_bounty_scope(SAMPLE_SCOPE)
    decision = get_scope_decision("payments.demo-web.local", scope)

    assert decision["in_scope"] is False
    assert "out-of-scope" in decision["reason"]


def test_url_in_scope() -> None:
    scope = load_bug_bounty_scope(SAMPLE_SCOPE)

    assert is_url_in_scope("http://127.0.0.1:8000/", scope)


def test_url_out_of_scope() -> None:
    scope = load_bug_bounty_scope(SAMPLE_SCOPE)

    assert not is_url_in_scope("https://demo-web.local/logout", scope)


def test_ip_range_in_scope() -> None:
    scope = load_bug_bounty_scope(SAMPLE_SCOPE)

    assert is_ip_in_scope("127.0.0.1", scope)


def test_unknown_target_out_of_scope_by_default() -> None:
    scope = load_bug_bounty_scope(SAMPLE_SCOPE)
    decision = get_scope_decision("unknown.example.local", scope)

    assert decision["in_scope"] is False
    assert "default" in decision["reason"]


def test_enforce_scope_blocks_out_of_scope_scan() -> None:
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "unknown.example.local",
            "--bug-bounty-scope",
            SAMPLE_SCOPE,
            "--enforce-scope",
        ],
    )

    assert result.exit_code == 1
    assert "blocked scan" in result.output
