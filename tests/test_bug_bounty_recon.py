from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import requests

from scanner.bug_bounty_recon import (
    build_recon_summary,
    classify_target_type,
    deduplicate_recon_targets,
    load_recon_targets,
    normalise_recon_target,
    probe_http_url,
    run_bug_bounty_recon,
)
from scanner.report_html import save_html_report
from scanner.report_json import save_json_report


SAMPLE_SCOPE = "data/bug_bounty/sample_program_scope.json"


class FakeHistory:
    def __init__(self, url: str) -> None:
        self.url = url


class FakeResponse:
    def __init__(
        self,
        body: bytes = b"",
        status_code: int = 200,
        url: str = "http://127.0.0.1/",
        headers: dict[str, str] | None = None,
        history: list[FakeHistory] | None = None,
    ) -> None:
        self._body = body
        self.status_code = status_code
        self.url = url
        self.headers = headers or {}
        self.history = history or []
        self.encoding = "utf-8"
        self.closed = False

    def iter_content(self, chunk_size: int = 8192, decode_unicode: bool = False):
        for index in range(0, len(self._body), chunk_size):
            yield self._body[index : index + chunk_size]

    def close(self) -> None:
        self.closed = True


def _decision() -> dict[str, object]:
    return {"in_scope": True, "reason": "matched test rule", "matched_rule": "test"}


def test_load_targets_file(tmp_path) -> None:
    path = tmp_path / "targets.txt"
    path.write_text("# comment\n127.0.0.1\n\nhttps://demo-web.local/\n", encoding="utf-8")

    assert load_recon_targets(path) == ["127.0.0.1", "https://demo-web.local/"]


def test_normalise_domain_into_http_and_https_candidates() -> None:
    target = normalise_recon_target("demo-web.local")

    assert target["target_type"] == "domain"
    assert target["probe_candidates"] == ["http://demo-web.local", "https://demo-web.local"]


def test_preserve_url_target() -> None:
    target = normalise_recon_target("https://demo-web.local/path?q=1")

    assert target["target_type"] == "url"
    assert target["probe_candidates"] == ["https://demo-web.local/path?q=1"]


def test_deduplicate_targets() -> None:
    assert deduplicate_recon_targets(["Demo-Web.local", "demo-web.local", "127.0.0.1"]) == ["Demo-Web.local", "127.0.0.1"]


def test_classify_target_type() -> None:
    assert classify_target_type("https://demo-web.local/") == "url"
    assert classify_target_type("127.0.0.1") == "ip"
    assert classify_target_type("demo-web.local") == "domain"
    assert classify_target_type("http://") == "unknown"


def test_enforce_scope_skips_out_of_scope_target() -> None:
    calls: list[str] = []

    result = run_bug_bounty_recon(
        ["payments.demo-web.local"],
        scope_file=SAMPLE_SCOPE,
        enforce_scope=True,
        request_delay=0,
        http_get=lambda url, **kwargs: calls.append(url),
    )

    assert calls == []
    assert result["bug_bounty_recon"]["skipped_count"] == 2
    assert result["bug_bounty_recon"]["out_of_scope_targets_count"] == 2


def test_out_of_scope_overrides_in_scope_for_recon() -> None:
    result = run_bug_bounty_recon(
        ["https://demo-web.local/logout"],
        scope_file=SAMPLE_SCOPE,
        enforce_scope=True,
        request_delay=0,
        http_get=lambda url, **kwargs: FakeResponse(),
    )

    assert result["bug_bounty_recon_results"] == []
    assert result["bug_bounty_recon_skipped"][0]["matched_rule"]


def test_http_probe_handles_200_and_extracts_title_and_technology() -> None:
    body = b"<html><head><title>Demo App</title></head><body>token-like-text</body></html>"
    response = FakeResponse(
        body=body,
        status_code=200,
        url="http://127.0.0.1/",
        headers={"Server": "nginx/1.24", "Content-Type": "text/html", "X-Powered-By": "PHP", "Set-Cookie": "session=redacted"},
    )

    result = probe_http_url(
        target="127.0.0.1",
        target_type="ip",
        probe_url="http://127.0.0.1",
        scope_decision=_decision(),
        http_get=lambda url, **kwargs: response,
    )

    assert result["status_code"] == 200
    assert result["live"] is True
    assert result["page_title"] == "Demo App"
    assert result["server_header"] == "nginx/1.24"
    assert {"name": "nginx", "source": "server_header", "confidence": "Medium"} in result["technology_hints"]
    assert "Set-Cookie" not in result
    assert "token-like-text" not in json.dumps(result)


def test_http_probe_tracks_redirect_chain() -> None:
    response = FakeResponse(
        body=b"<title>Final</title>",
        status_code=200,
        url="https://demo-web.local/",
        history=[FakeHistory("http://demo-web.local/")],
    )

    result = probe_http_url("demo-web.local", "domain", "http://demo-web.local", _decision(), http_get=lambda url, **kwargs: response)

    assert result["final_url"] == "https://demo-web.local/"
    assert result["redirect_chain"] == ["http://demo-web.local/"]


def test_http_probe_handles_timeout_gracefully() -> None:
    def raise_timeout(url, **kwargs):
        raise requests.Timeout("slow")

    result = probe_http_url("demo-web.local", "domain", "https://demo-web.local", _decision(), http_get=raise_timeout)

    assert result["live"] is False
    assert result["error_code"] == "timeout"
    assert "slow" not in result["error_message"]


def test_recon_summary_counts_live_errors_and_skipped() -> None:
    summary = build_recon_summary(
        scope=None,
        input_source="unit",
        input_targets_count=3,
        normalised_targets_count=3,
        results=[
            {"live": True, "in_scope": True, "status_code": 200, "content_type": "text/html", "technology_hints": [{"name": "nginx"}]},
            {"live": False, "in_scope": True, "error_code": "timeout", "technology_hints": []},
        ],
        skipped=[{"reason": "Out-of-scope target skipped."}],
    )

    assert summary["live_count"] == 1
    assert summary["error_count"] == 1
    assert summary["skipped_count"] == 1
    assert summary["technologies_observed"] == ["nginx"]


def test_json_and_html_reports_include_recon_fields(tmp_path) -> None:
    started = datetime.now()
    recon = run_bug_bounty_recon(
        ["http://127.0.0.1:8000/"],
        scope_file=SAMPLE_SCOPE,
        enforce_scope=True,
        request_delay=0,
        http_get=lambda url, **kwargs: FakeResponse(body=b"<title>Recon Demo</title>", status_code=200, url=url),
    )
    scan_result = {
        "host": "bug-bounty-recon",
        "resolved_ip": None,
        "scan_mode": "bug-bounty-recon",
        "duration_seconds": 1,
        "open_ports": [],
        "findings": recon["findings"],
        "bug_bounty_recon": recon["bug_bounty_recon"],
        "bug_bounty_recon_results": recon["bug_bounty_recon_results"],
        "bug_bounty_recon_skipped": recon["bug_bounty_recon_skipped"],
        "demo_mode": False,
        "demo_notice": "",
    }

    json_path = save_json_report(scan_result, "VulScan", "18.1", started, started, reports_dir=tmp_path)
    html_path = save_html_report(scan_result, "VulScan", "18.1", started, started, reports_dir=tmp_path)

    payload = json.loads(Path(json_path).read_text(encoding="utf-8"))
    html = Path(html_path).read_text(encoding="utf-8")
    assert payload["bug_bounty_recon"]["enabled"] is True
    assert payload["bug_bounty_recon_results"]
    assert "Bug Bounty Recon" in html
    assert "Recon Demo" in html
