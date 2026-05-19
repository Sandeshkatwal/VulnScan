from __future__ import annotations

from scanner.finding import Finding
from scanner.web_crawler import crawl_web
from scanner.web_rate_limit import build_web_rate_limiter
from scanner.web_robots import fetch_robots_policy
from scanner.web_scope import build_web_scope
from scanner.web_sitemap import discover_sitemaps, parse_sitemap_xml


class FakeResponse:
    def __init__(self, text: str, status_code: int = 200, content_type: str = "application/xml") -> None:
        self.text = text
        self.status_code = status_code
        self.headers = {"Content-Type": content_type}


class FakeSession:
    def __init__(self, responses: dict[str, FakeResponse]) -> None:
        self.responses = responses
        self.requested_urls: list[str] = []

    def get(self, url: str, **_kwargs: object) -> FakeResponse:
        self.requested_urls.append(url)
        return self.responses.get(url, FakeResponse("", status_code=404, content_type="text/plain"))


def _limiter():
    return build_web_rate_limiter(request_delay=0, retry_backoff=0)


def _scope(**kwargs):
    return build_web_scope(start_url="https://example.com/", **kwargs)


def _urlset(*urls: str) -> str:
    items = "".join(f"<url><loc>{url}</loc></url>" for url in urls)
    return f'<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{items}</urlset>'


def test_parse_urlset_sitemap_with_namespace() -> None:
    parsed = parse_sitemap_xml(
        sitemap_url="https://example.com/sitemap.xml",
        xml_text=_urlset("https://example.com/a"),
        max_urls=100,
    )

    assert parsed["sitemap_type"] == "urlset"
    assert parsed["url_entries"][0]["url"] == "https://example.com/a"


def test_parse_sitemap_index_with_namespace() -> None:
    xml = """<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <sitemap><loc>https://example.com/pages.xml</loc><lastmod>2026-05-01</lastmod></sitemap>
    </sitemapindex>"""

    parsed = parse_sitemap_xml(sitemap_url="https://example.com/sitemap.xml", xml_text=xml, max_urls=100)

    assert parsed["sitemap_type"] == "sitemapindex"
    assert parsed["nested_sitemaps"][0]["url"] == "https://example.com/pages.xml"


def test_parse_lastmod_changefreq_priority() -> None:
    xml = """<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url><loc>https://example.com/a</loc><lastmod>2026-05-01</lastmod><changefreq>weekly</changefreq><priority>0.7</priority></url>
    </urlset>"""

    entry = parse_sitemap_xml(sitemap_url="https://example.com/sitemap.xml", xml_text=xml, max_urls=100)["url_entries"][0]

    assert entry["lastmod"] == "2026-05-01"
    assert entry["changefreq"] == "weekly"
    assert entry["priority"] == "0.7"


def test_handle_malformed_xml_gracefully() -> None:
    parsed = parse_sitemap_xml(sitemap_url="https://example.com/sitemap.xml", xml_text="<urlset>", max_urls=100)

    assert parsed["sitemap_type"] == "error"
    assert parsed["error_code"] == "SITEMAP_PARSE_ERROR"


def test_enforce_max_sitemap_urls() -> None:
    xml = _urlset("https://example.com/a", "https://example.com/b", "https://example.com/c")

    parsed = parse_sitemap_xml(sitemap_url="https://example.com/sitemap.xml", xml_text=xml, max_urls=2)

    assert len(parsed["url_entries"]) == 2


def test_enforce_max_sitemap_depth() -> None:
    index = """<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <sitemap><loc>https://example.com/pages.xml</loc></sitemap>
    </sitemapindex>"""
    session = FakeSession({"https://example.com/sitemap.xml": FakeResponse(index)})

    result = discover_sitemaps(
        start_url="https://example.com/",
        session=session,
        headers={},
        timeout=1,
        limiter=_limiter(),
        scope=_scope(),
        explicit_sitemap_urls=["https://example.com/sitemap.xml"],
        enabled=True,
        max_sitemap_depth=0,
    )

    assert "https://example.com/pages.xml" not in session.requested_urls
    assert result["web_sitemap_summary"]["sitemap_indexes_found"] == 1


def test_filter_out_of_scope_sitemap_urls() -> None:
    session = FakeSession({"https://example.com/sitemap.xml": FakeResponse(_urlset("https://outside.test/a"))})

    result = discover_sitemaps(
        start_url="https://example.com/",
        session=session,
        headers={},
        timeout=1,
        limiter=_limiter(),
        scope=_scope(),
        explicit_sitemap_urls=["https://example.com/sitemap.xml"],
        enabled=True,
    )

    assert result["web_sitemap_summary"]["out_of_scope_urls"] == 1
    assert result["web_sitemap_url_samples"][0]["in_scope"] is False


def test_use_robots_txt_sitemap_entries() -> None:
    robots_text = "User-agent: *\nAllow: /\nSitemap: https://example.com/from-robots.xml\n"
    session = FakeSession(
        {
            "https://example.com/robots.txt": FakeResponse(robots_text, content_type="text/plain"),
            "https://example.com/from-robots.xml": FakeResponse(_urlset("https://example.com/a")),
        }
    )
    robots_policy = fetch_robots_policy(
        start_url="https://example.com/",
        session=session,
        headers={},
        timeout=1,
        limiter=_limiter(),
        enabled=True,
    )

    discover_sitemaps(
        start_url="https://example.com/",
        session=session,
        headers={},
        timeout=1,
        limiter=_limiter(),
        scope=_scope(),
        robots_policy=robots_policy,
        enabled=True,
    )

    assert "https://example.com/from-robots.xml" in session.requested_urls


def test_use_explicit_sitemap_url() -> None:
    session = FakeSession({"https://example.com/custom.xml": FakeResponse(_urlset("https://example.com/a"))})

    result = discover_sitemaps(
        start_url="https://example.com/",
        session=session,
        headers={},
        timeout=1,
        limiter=_limiter(),
        scope=_scope(),
        explicit_sitemap_urls=["https://example.com/custom.xml"],
        enabled=True,
    )

    assert "explicit" in result["web_sitemap_summary"]["discovery_sources"]
    assert "https://example.com/custom.xml" in session.requested_urls


def test_use_common_sitemap_paths() -> None:
    session = FakeSession({"https://example.com/sitemap.xml": FakeResponse(_urlset("https://example.com/a"))})

    discover_sitemaps(
        start_url="https://example.com/",
        session=session,
        headers={},
        timeout=1,
        limiter=_limiter(),
        scope=_scope(),
        enabled=True,
    )

    assert "https://example.com/sitemap.xml" in session.requested_urls


def test_add_in_scope_sitemap_urls_to_crawl_queue_only_when_enabled() -> None:
    session = FakeSession({"https://example.com/sitemap.xml": FakeResponse(_urlset("https://example.com/a"))})

    result = discover_sitemaps(
        start_url="https://example.com/",
        session=session,
        headers={},
        timeout=1,
        limiter=_limiter(),
        scope=_scope(),
        explicit_sitemap_urls=["https://example.com/sitemap.xml"],
        enabled=True,
        use_sitemap_for_crawl=True,
    )

    assert result["crawl_urls"] == ["https://example.com/a"]
    assert result["web_sitemap_summary"]["urls_added_to_crawl"] == 1


def test_do_not_add_sitemap_urls_to_crawl_queue_when_disabled() -> None:
    session = FakeSession({"https://example.com/sitemap.xml": FakeResponse(_urlset("https://example.com/a"))})

    result = discover_sitemaps(
        start_url="https://example.com/",
        session=session,
        headers={},
        timeout=1,
        limiter=_limiter(),
        scope=_scope(),
        explicit_sitemap_urls=["https://example.com/sitemap.xml"],
        enabled=True,
        use_sitemap_for_crawl=False,
    )

    assert result["crawl_urls"] == []
    assert result["web_sitemap_summary"]["urls_added_to_crawl"] == 0


def test_respect_deny_path_for_sitemap_urls() -> None:
    session = FakeSession({"https://example.com/sitemap.xml": FakeResponse(_urlset("https://example.com/admin/page"))})

    result = discover_sitemaps(
        start_url="https://example.com/",
        session=session,
        headers={},
        timeout=1,
        limiter=_limiter(),
        scope=_scope(deny_paths=["/admin"]),
        explicit_sitemap_urls=["https://example.com/sitemap.xml"],
        enabled=True,
    )

    assert result["web_sitemap_url_samples"][0]["skipped_reason"] == "skipped_denied_path"


def test_respect_deny_host_for_sitemap_urls() -> None:
    session = FakeSession(
        {"https://cdn.example.com/sitemap.xml": FakeResponse(_urlset("https://cdn.example.com/a"))}
    )

    result = discover_sitemaps(
        start_url="https://example.com/",
        session=session,
        headers={},
        timeout=1,
        limiter=_limiter(),
        scope=_scope(allow_hosts=["cdn.example.com"], deny_hosts=["cdn.example.com"]),
        explicit_sitemap_urls=["https://cdn.example.com/sitemap.xml"],
        enabled=True,
    )

    assert result["web_sitemap_summary"]["sitemap_urls_failed"] >= 1
    assert result["web_sitemap_results"][0]["error_code"] == "skipped_denied_host"


def test_generate_sitemap_summary_and_standard_findings() -> None:
    session = FakeSession({"https://example.com/sitemap.xml": FakeResponse(_urlset("https://example.com/a"))})

    result = discover_sitemaps(
        start_url="https://example.com/",
        session=session,
        headers={},
        timeout=1,
        limiter=_limiter(),
        scope=_scope(),
        explicit_sitemap_urls=["https://example.com/sitemap.xml"],
        enabled=True,
    )

    assert result["web_sitemap_summary"]["enabled"] is True
    assert result["web_sitemap_summary"]["url_entries_found"] == 1
    assert isinstance(result["findings"][0], Finding)
    assert result["findings"][0].source == "web_sitemap"


def test_crawler_fetches_sitemap_seed_only_when_supplied() -> None:
    session = FakeSession(
        {
            "https://example.com/": FakeResponse("<html></html>", content_type="text/html"),
            "https://example.com/from-sitemap": FakeResponse("<html></html>", content_type="text/html"),
        }
    )

    result = crawl_web(
        start_url="https://example.com/",
        crawl=True,
        max_pages=3,
        max_depth=1,
        session=session,
        scope=_scope(max_pages=3, max_depth=1),
        rate_limiter=_limiter(),
        seed_urls=["https://example.com/from-sitemap"],
    )

    assert {page["url"] for page in result["crawled_pages"]} == {
        "https://example.com/",
        "https://example.com/from-sitemap",
    }
