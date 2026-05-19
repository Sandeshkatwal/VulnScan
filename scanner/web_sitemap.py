"""Safe sitemap discovery for passive Web DAST."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit
import xml.etree.ElementTree as ET

from scanner.finding import Finding, create_finding
from scanner.web_rate_limit import safe_get


SOURCE = "web_sitemap"
COMMON_SITEMAP_PATHS = ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"]
URL_SAMPLE_LIMIT = 100
LIMITATIONS = [
    "Sitemap discovery is a passive discovery source and does not grant permission to test URLs.",
    "All sitemap URLs must remain within configured scope and written authorisation.",
    "Sitemap-assisted crawling still respects max pages, max depth, scope, robots, and rate limits.",
]


@dataclass
class SitemapEntry:
    url: str
    source_sitemap: str
    lastmod: str = ""
    changefreq: str = ""
    priority: str = ""
    in_scope: bool = False
    skipped_reason: str = ""

    def to_sample(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "source_sitemap": self.source_sitemap,
            "in_scope": self.in_scope,
            "skipped_reason": self.skipped_reason,
            "lastmod": self.lastmod,
            "changefreq": self.changefreq,
            "priority": self.priority,
        }


def discover_sitemaps(
    *,
    start_url: str,
    session: Any,
    headers: dict[str, str],
    timeout: float,
    limiter: Any,
    scope: Any,
    robots_policy: Any | None = None,
    explicit_sitemap_urls: list[str] | None = None,
    enabled: bool = False,
    use_sitemap_for_crawl: bool = False,
    max_sitemap_urls: int = 100,
    max_sitemap_depth: int = 2,
) -> dict[str, Any]:
    if not enabled:
        return _empty_result(
            enabled=False,
            max_sitemap_urls=max_sitemap_urls,
            max_sitemap_depth=max_sitemap_depth,
            use_sitemap_for_crawl=use_sitemap_for_crawl,
        )

    requested = _initial_sitemap_urls(
        start_url=start_url,
        robots_policy=robots_policy,
        explicit_sitemap_urls=explicit_sitemap_urls or [],
    )
    fetched: set[str] = set()
    queued: list[tuple[str, int, str]] = [(url, 0, source) for url, source in requested]
    results: list[dict[str, Any]] = []
    samples: list[dict[str, Any]] = []
    crawl_urls: list[str] = []
    discovery_sources = sorted({source for _url, source in requested})
    indexes_found = 0
    url_entries_found = 0
    in_scope_urls = 0
    out_of_scope_urls = 0
    failed_count = 0

    while queued and len(samples) < max_sitemap_urls:
        sitemap_url, depth, source = queued.pop(0)
        if sitemap_url in fetched or depth > max_sitemap_depth:
            continue
        fetched.add(sitemap_url)
        allowed, reason, normalized_sitemap_url = scope.decide_url(sitemap_url)
        robots_disallowed = _robots_disallows(robots_policy, normalized_sitemap_url)
        if not allowed or robots_disallowed:
            skipped_reason = reason if not allowed else "skipped_by_robots"
            scope.record_skip(url=normalized_sitemap_url, reason=skipped_reason, source_url="sitemap", depth=depth)
            if robots_disallowed and robots_policy is not None:
                robots_policy.record_skip(normalized_sitemap_url)
            failed_count += 1
            results.append(
                _result_row(
                    sitemap_url=normalized_sitemap_url,
                    fetch_status="skipped_scope",
                    sitemap_type="error",
                    error_code=skipped_reason,
                    error_message="Sitemap URL was outside scope or disallowed by robots.txt.",
                )
            )
            continue

        request_result = safe_get(
            session=session,
            url=normalized_sitemap_url,
            headers=headers,
            timeout=timeout,
            limiter=limiter,
        )
        if not request_result.get("success"):
            failed_count += 1
            results.append(
                _result_row(
                    sitemap_url=normalized_sitemap_url,
                    fetch_status="failed",
                    http_status_code=int(request_result.get("status_code") or 0),
                    sitemap_type="error",
                    error_code=str(request_result.get("error_code") or ""),
                    error_message=str(request_result.get("error_message") or ""),
                )
            )
            continue

        parsed = parse_sitemap_xml(
            sitemap_url=normalized_sitemap_url,
            xml_text=str(request_result.get("text") or ""),
            max_urls=max_sitemap_urls - len(samples),
        )
        if parsed["sitemap_type"] == "error":
            failed_count += 1
        if parsed["sitemap_type"] == "sitemapindex":
            indexes_found += 1

        nested_count = 0
        if parsed["sitemap_type"] == "sitemapindex" and depth < max_sitemap_depth:
            for nested in parsed["nested_sitemaps"]:
                if len(fetched) + len(queued) >= max_sitemap_urls:
                    break
                queued.append((nested["url"], depth + 1, normalized_sitemap_url))
                nested_count += 1

        sitemap_in_scope = 0
        sitemap_out_scope = 0
        for entry in parsed["url_entries"]:
            url_entries_found += 1
            allowed, skipped_reason, normalized_url = scope.decide_url(entry["url"])
            if allowed and _robots_disallows(robots_policy, normalized_url):
                allowed = False
                skipped_reason = "skipped_by_robots"
                if robots_policy is not None:
                    robots_policy.record_skip(normalized_url)
                scope.record_skip(url=normalized_url, reason=skipped_reason, source_url=normalized_sitemap_url, depth=depth + 1)
            sample = SitemapEntry(
                url=normalized_url,
                source_sitemap=normalized_sitemap_url,
                lastmod=str(entry.get("lastmod") or ""),
                changefreq=str(entry.get("changefreq") or ""),
                priority=str(entry.get("priority") or ""),
                in_scope=allowed,
                skipped_reason="" if allowed else skipped_reason,
            ).to_sample()
            if allowed:
                in_scope_urls += 1
                sitemap_in_scope += 1
                if use_sitemap_for_crawl and normalized_url not in crawl_urls:
                    crawl_urls.append(normalized_url)
            else:
                out_of_scope_urls += 1
                sitemap_out_scope += 1
            if len(samples) < URL_SAMPLE_LIMIT:
                samples.append(sample)
            if len(samples) >= max_sitemap_urls:
                break

        results.append(
            _result_row(
                sitemap_url=normalized_sitemap_url,
                fetch_status="success" if parsed["sitemap_type"] != "error" else "parse_error",
                http_status_code=int(request_result.get("status_code") or 0),
                sitemap_type=parsed["sitemap_type"],
                urls_found_count=len(parsed["url_entries"]),
                in_scope_count=sitemap_in_scope,
                out_of_scope_count=sitemap_out_scope,
                nested_sitemaps_found=nested_count,
                error_code=str(parsed.get("error_code") or ""),
                error_message=str(parsed.get("error_message") or ""),
            )
        )

    summary = {
        "enabled": True,
        "discovery_sources": discovery_sources,
        "sitemap_urls_requested": len(requested),
        "sitemap_urls_fetched": len([result for result in results if result["fetch_status"] in {"success", "parse_error"}]),
        "sitemap_urls_failed": failed_count,
        "sitemap_indexes_found": indexes_found,
        "url_entries_found": url_entries_found,
        "in_scope_urls": in_scope_urls,
        "out_of_scope_urls": out_of_scope_urls,
        "urls_added_to_crawl": len(crawl_urls) if use_sitemap_for_crawl else 0,
        "max_sitemap_urls": max_sitemap_urls,
        "max_sitemap_depth": max_sitemap_depth,
        "use_sitemap_for_crawl": use_sitemap_for_crawl,
        "limitations": list(LIMITATIONS),
    }
    return {
        "enabled": True,
        "web_sitemap_summary": summary,
        "web_sitemap_results": results,
        "web_sitemap_url_samples": samples,
        "crawl_urls": crawl_urls if use_sitemap_for_crawl else [],
        "findings": build_sitemap_findings(summary),
    }


def parse_sitemap_xml(*, sitemap_url: str, xml_text: str, max_urls: int) -> dict[str, Any]:
    try:
        root = ET.fromstring(xml_text[:5_000_000])
    except ET.ParseError as exc:
        return {
            "sitemap_type": "error",
            "url_entries": [],
            "nested_sitemaps": [],
            "error_code": "SITEMAP_PARSE_ERROR",
            "error_message": str(exc)[:200],
        }
    root_name = _local_name(root.tag)
    if root_name == "urlset":
        entries = []
        for url_node in root:
            if _local_name(url_node.tag) != "url" or len(entries) >= max_urls:
                continue
            entry = _url_entry(url_node)
            if entry["url"]:
                entries.append(entry)
        return {"sitemap_type": "urlset", "url_entries": entries, "nested_sitemaps": [], "error_code": "", "error_message": ""}
    if root_name == "sitemapindex":
        nested = []
        for sitemap_node in root:
            if _local_name(sitemap_node.tag) != "sitemap" or len(nested) >= max_urls:
                continue
            loc = _child_text(sitemap_node, "loc")
            if loc:
                nested.append({"url": loc, "lastmod": _child_text(sitemap_node, "lastmod")})
        return {"sitemap_type": "sitemapindex", "url_entries": [], "nested_sitemaps": nested, "error_code": "", "error_message": ""}
    return {"sitemap_type": "unknown", "url_entries": [], "nested_sitemaps": [], "error_code": "", "error_message": ""}


def build_sitemap_findings(summary: dict[str, Any]) -> list[Finding]:
    if not summary.get("enabled"):
        return []
    findings = [
        create_finding(
            title="Sitemap Discovery Completed",
            severity="Informational",
            category="Web Discovery",
            evidence=f"Sitemap discovery reviewed {summary.get('sitemap_urls_fetched', 0)} sitemap files and found {summary.get('url_entries_found', 0)} URL entries.",
            confidence="High",
            impact="Sitemap URLs can help understand authorised application coverage.",
            recommendation="Use sitemap URLs to understand authorised application coverage.",
            verification="Review the Web Sitemap Discovery report section.",
            limitation="Sitemap discovery does not confirm vulnerabilities and does not grant permission to test URLs.",
            source=SOURCE,
            service="http",
        )
    ]
    if int(summary.get("out_of_scope_urls") or 0):
        findings.append(
            create_finding(
                title="Sitemap Contains Out-of-Scope URLs",
                severity="Informational",
                category="Web DAST Scope",
                evidence="Sitemap contained URLs outside the configured VulScan scope.",
                confidence="High",
                impact="Sitemap content may reference URLs that are not authorised for testing.",
                recommendation="Review scope and only include hosts or paths with written authorisation.",
                verification="Review out-of-scope sitemap URL samples.",
                limitation="Sitemap content may include legacy, external, or marketing URLs.",
                source=SOURCE,
                service="http",
            )
        )
    if int(summary.get("sitemap_urls_failed") or 0):
        findings.append(
            create_finding(
                title="Sitemap Fetch Failed",
                severity="Low",
                category="Web Discovery",
                evidence="One or more sitemap files could not be fetched or parsed.",
                confidence="Medium",
                impact="Sitemap discovery coverage may be incomplete.",
                recommendation="Verify sitemap URL and target availability.",
                verification="Review sitemap result rows for fetch or parse failures.",
                limitation="Sitemap discovery coverage may be incomplete.",
                source=SOURCE,
                service="http",
            )
        )
    if int(summary.get("urls_added_to_crawl") or 0):
        findings.append(
            create_finding(
                title="Sitemap URLs Added to Crawl Queue",
                severity="Informational",
                category="Web Discovery",
                evidence="In-scope sitemap URLs were added to the crawl queue because --use-sitemap-for-crawl was enabled.",
                confidence="High",
                impact="Sitemap-assisted crawling can improve passive coverage within authorised scope.",
                recommendation="Confirm sitemap-assisted crawling remains within authorised scope.",
                verification="Review crawl pages and sitemap URL samples.",
                limitation="Sitemap-assisted crawling still respects max-pages, max-depth, scope, robots, and rate limits.",
                source=SOURCE,
                service="http",
            )
        )
    return findings


def _initial_sitemap_urls(
    *,
    start_url: str,
    robots_policy: Any | None,
    explicit_sitemap_urls: list[str],
) -> list[tuple[str, str]]:
    parts = urlsplit(start_url)
    origin = urlunsplit((parts.scheme.lower(), parts.netloc.lower(), "", "", ""))
    discovered: list[tuple[str, str]] = []
    for url in explicit_sitemap_urls:
        discovered.append((url, "explicit"))
    if robots_policy is not None:
        for url in robots_policy.summary().get("sitemap_urls") or []:
            discovered.append((str(url), "robots"))
    for path in COMMON_SITEMAP_PATHS:
        discovered.append((f"{origin}{path}", "common"))
    deduped: list[tuple[str, str]] = []
    seen: set[str] = set()
    for url, source in discovered:
        if url not in seen:
            seen.add(url)
            deduped.append((url, source))
    return deduped


def _empty_result(*, enabled: bool, max_sitemap_urls: int, max_sitemap_depth: int, use_sitemap_for_crawl: bool) -> dict[str, Any]:
    return {
        "enabled": enabled,
        "web_sitemap_summary": {
            "enabled": enabled,
            "discovery_sources": [],
            "sitemap_urls_requested": 0,
            "sitemap_urls_fetched": 0,
            "sitemap_urls_failed": 0,
            "sitemap_indexes_found": 0,
            "url_entries_found": 0,
            "in_scope_urls": 0,
            "out_of_scope_urls": 0,
            "urls_added_to_crawl": 0,
            "max_sitemap_urls": max_sitemap_urls,
            "max_sitemap_depth": max_sitemap_depth,
            "use_sitemap_for_crawl": use_sitemap_for_crawl,
            "limitations": list(LIMITATIONS),
        },
        "web_sitemap_results": [],
        "web_sitemap_url_samples": [],
        "crawl_urls": [],
        "findings": [],
    }


def _result_row(
    *,
    sitemap_url: str,
    fetch_status: str,
    http_status_code: int = 0,
    sitemap_type: str = "unknown",
    urls_found_count: int = 0,
    in_scope_count: int = 0,
    out_of_scope_count: int = 0,
    nested_sitemaps_found: int = 0,
    error_code: str = "",
    error_message: str = "",
) -> dict[str, Any]:
    return {
        "sitemap_url": sitemap_url,
        "fetch_status": fetch_status,
        "http_status_code": http_status_code,
        "sitemap_type": sitemap_type,
        "urls_found_count": urls_found_count,
        "in_scope_count": in_scope_count,
        "out_of_scope_count": out_of_scope_count,
        "nested_sitemaps_found": nested_sitemaps_found,
        "error_code": error_code,
        "error_message": error_message[:200],
    }


def _url_entry(node: Any) -> dict[str, str]:
    return {
        "url": _child_text(node, "loc"),
        "lastmod": _child_text(node, "lastmod"),
        "changefreq": _child_text(node, "changefreq"),
        "priority": _child_text(node, "priority"),
    }


def _child_text(node: Any, child_name: str) -> str:
    for child in node:
        if _local_name(child.tag) == child_name:
            return str(child.text or "").strip()
    return ""


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _robots_disallows(robots_policy: Any | None, url: str) -> bool:
    return robots_policy is not None and not robots_policy.can_fetch(url)
