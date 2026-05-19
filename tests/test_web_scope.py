from scanner.finding import Finding
from scanner.web_scope import build_scope_findings, build_web_scope


def test_allows_start_host_by_default() -> None:
    scope = build_web_scope(start_url="https://example.test/")

    allowed, reason, normalized = scope.decide_url("https://example.test/about")

    assert allowed is True
    assert reason == "allowed"
    assert normalized == "https://example.test/about"


def test_blocks_external_host_by_default() -> None:
    scope = build_web_scope(start_url="https://example.test/")

    allowed, reason, _normalized = scope.decide_url("https://other.test/")

    assert allowed is False
    assert reason == "skipped_external_host"


def test_allows_explicit_allow_host() -> None:
    scope = build_web_scope(start_url="https://example.test/", allow_hosts=["docs.example.test"])

    allowed, reason, _normalized = scope.decide_url("https://docs.example.test/help")

    assert allowed is True
    assert reason == "allowed"


def test_denies_explicit_deny_host() -> None:
    scope = build_web_scope(
        start_url="https://example.test/",
        allow_hosts=["analytics.example.test"],
        deny_hosts=["analytics.example.test"],
    )

    allowed, reason, _normalized = scope.decide_url("https://analytics.example.test/pixel")

    assert allowed is False
    assert reason == "skipped_denied_host"


def test_includes_subdomains_when_enabled() -> None:
    scope = build_web_scope(start_url="https://example.test/", include_subdomains=True)

    allowed, reason, _normalized = scope.decide_url("https://docs.example.test/page")

    assert allowed is True
    assert reason == "allowed"


def test_blocks_subdomains_when_disabled() -> None:
    scope = build_web_scope(start_url="https://example.test/", include_subdomains=False)

    allowed, reason, _normalized = scope.decide_url("https://docs.example.test/page")

    assert allowed is False
    assert reason == "skipped_external_host"


def test_allows_path_prefixes() -> None:
    scope = build_web_scope(start_url="https://example.test/docs/", allow_paths=["/docs"])

    allowed, reason, _normalized = scope.decide_url("https://example.test/docs/page")

    assert allowed is True
    assert reason == "allowed"


def test_blocks_paths_outside_allow_prefixes() -> None:
    scope = build_web_scope(start_url="https://example.test/docs/", allow_paths=["/docs"])

    allowed, reason, _normalized = scope.decide_url("https://example.test/admin")

    assert allowed is False
    assert reason == "skipped_not_allowed_path"


def test_denies_path_prefixes() -> None:
    scope = build_web_scope(start_url="https://example.test/", deny_paths=["/logout"])

    allowed, reason, _normalized = scope.decide_url("https://example.test/logout/confirm")

    assert allowed is False
    assert reason == "skipped_denied_path"


def test_denies_unsupported_schemes() -> None:
    scope = build_web_scope(start_url="https://example.test/")

    allowed, reason, _normalized = scope.decide_url("mailto:security@example.test")

    assert allowed is False
    assert reason == "skipped_unsupported_scheme"


def test_skips_static_file_extensions() -> None:
    scope = build_web_scope(start_url="https://example.test/")

    allowed, reason, _normalized = scope.decide_url("https://example.test/app.js")

    assert allowed is False
    assert reason == "skipped_static_file"


def test_ignores_url_fragments() -> None:
    scope = build_web_scope(start_url="https://example.test/")

    allowed, _reason, normalized = scope.decide_url("https://example.test/docs#section")

    assert allowed is True
    assert normalized == "https://example.test/docs"


def test_tracks_skipped_reason_counts() -> None:
    scope = build_web_scope(start_url="https://example.test/")
    scope.record_skip(url="https://other.test/", reason="skipped_external_host", source_url="https://example.test/", depth=1)
    summary = scope.summary()

    assert summary["skipped_external_hosts_count"] == 1
    assert summary["total_skipped_urls"] == 1
    assert scope.skipped_url_samples[0]["reason"] == "skipped_external_host"


def test_scope_findings_use_standard_model() -> None:
    scope = build_web_scope(start_url="https://example.test/")
    scope.record_skip(url="https://other.test/", reason="skipped_external_host", source_url="https://example.test/", depth=1)
    findings = build_scope_findings(scope.summary(), scope.skipped_url_samples)

    assert all(isinstance(finding, Finding) for finding in findings)
    assert {finding.source for finding in findings} == {"web_scope"}
    assert "External URLs Skipped by Scope" in {finding.title for finding in findings}
