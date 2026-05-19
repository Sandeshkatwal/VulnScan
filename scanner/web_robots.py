"""robots.txt awareness for passive Web DAST."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

from scanner.finding import Finding, create_finding
from scanner.web_rate_limit import safe_get


SOURCE = "web_robots"
DEFAULT_ROBOTS_USER_AGENT = "VulScan-WebDAST"
LIMITATIONS = [
    "robots.txt is advisory and is not an access control mechanism.",
    "robots.txt does not grant permission to scan.",
    "Sitemap URLs must still remain within written authorisation and configured scope.",
]


@dataclass
class WebRobotsPolicy:
    enabled: bool
    robots_url: str
    respect_robots: bool = True
    robots_user_agent: str = DEFAULT_ROBOTS_USER_AGENT
    fetch_status: str = "skipped"
    http_status_code: int = 0
    robots_found: bool = False
    user_agents_seen: list[str] = field(default_factory=list)
    disallow_rules_count: int = 0
    allow_rules_count: int = 0
    sitemap_urls: list[str] = field(default_factory=list)
    crawl_delay: float | None = None
    disallowed_samples: list[str] = field(default_factory=list)
    allowed_samples: list[str] = field(default_factory=list)
    urls_skipped_by_robots: int = 0
    robots_limitations: list[str] = field(default_factory=lambda: list(LIMITATIONS))
    parser: RobotFileParser | None = None
    _skipped_samples_seen: set[str] = field(default_factory=set)

    def can_fetch(self, url: str) -> bool:
        if not self.enabled or not self.respect_robots or not self.robots_found or self.parser is None:
            return True
        return bool(self.parser.can_fetch(self.robots_user_agent, url))

    def record_skip(self, url: str) -> None:
        self.urls_skipped_by_robots += 1
        if len(self.disallowed_samples) >= 20 or url in self._skipped_samples_seen:
            return
        self._skipped_samples_seen.add(url)
        self.disallowed_samples.append(url)

    def summary(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "robots_url": self.robots_url,
            "fetch_status": self.fetch_status,
            "http_status_code": self.http_status_code,
            "respect_robots": self.respect_robots,
            "robots_user_agent": self.robots_user_agent,
            "robots_found": self.robots_found,
            "user_agents_seen": list(self.user_agents_seen),
            "disallow_rules_count": self.disallow_rules_count,
            "allow_rules_count": self.allow_rules_count,
            "sitemap_urls": list(self.sitemap_urls),
            "crawl_delay": self.crawl_delay,
            "disallowed_samples": list(self.disallowed_samples),
            "allowed_samples": list(self.allowed_samples),
            "urls_skipped_by_robots": self.urls_skipped_by_robots,
            "robots_limitations": list(self.robots_limitations),
        }


def build_robots_url(start_url: str) -> str:
    parts = urlsplit(start_url)
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), "/robots.txt", "", ""))


def fetch_robots_policy(
    *,
    start_url: str,
    session: Any,
    headers: dict[str, str],
    timeout: float,
    limiter: Any,
    enabled: bool,
    respect_robots: bool,
    robots_user_agent: str = DEFAULT_ROBOTS_USER_AGENT,
) -> WebRobotsPolicy:
    robots_url = build_robots_url(start_url)
    policy = WebRobotsPolicy(
        enabled=enabled,
        robots_url=robots_url,
        respect_robots=respect_robots,
        robots_user_agent=robots_user_agent,
    )
    if not enabled:
        return policy

    result = safe_get(
        session=session,
        url=robots_url,
        headers=headers,
        timeout=timeout,
        limiter=limiter,
    )
    policy.http_status_code = int(result.get("status_code") or 0)
    if not result.get("success"):
        if policy.http_status_code == 404:
            policy.fetch_status = "not_found"
        elif policy.http_status_code == 403:
            policy.fetch_status = "forbidden"
        else:
            policy.fetch_status = str(result.get("error_code") or "fetch_error")
        return policy

    content_type = str(result.get("content_type") or "")
    text = str(result.get("text") or "")
    if "text" not in content_type.lower() and content_type:
        policy.fetch_status = "non_text"
        return policy
    if not text.strip():
        policy.fetch_status = "empty"
        return policy

    policy.fetch_status = "found"
    policy.robots_found = True
    parsed = parse_robots_text(robots_url=robots_url, text=text, robots_user_agent=robots_user_agent)
    policy.parser = parsed["parser"]
    policy.user_agents_seen = parsed["user_agents_seen"]
    policy.disallow_rules_count = parsed["disallow_rules_count"]
    policy.allow_rules_count = parsed["allow_rules_count"]
    policy.sitemap_urls = parsed["sitemap_urls"]
    policy.crawl_delay = parsed["crawl_delay"]
    policy.allowed_samples = parsed["allowed_samples"]
    policy.disallowed_samples = parsed["disallowed_samples"]
    return policy


def parse_robots_text(*, robots_url: str, text: str, robots_user_agent: str) -> dict[str, Any]:
    parser = RobotFileParser()
    parser.set_url(robots_url)
    lines = [line.strip() for line in text.splitlines()]
    parser.parse(lines)

    user_agents: list[str] = []
    sitemap_urls: list[str] = []
    allowed_samples: list[str] = []
    disallowed_samples: list[str] = []
    allow_count = 0
    disallow_count = 0
    crawl_delay: float | None = None

    for raw_line in lines:
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "user-agent" and value:
            if value not in user_agents:
                user_agents.append(value)
        elif key == "allow" and value:
            allow_count += 1
            if len(allowed_samples) < 20:
                allowed_samples.append(value)
        elif key == "disallow" and value:
            disallow_count += 1
            if len(disallowed_samples) < 20:
                disallowed_samples.append(value)
        elif key == "sitemap" and value:
            sitemap_urls.append(value)
        elif key == "crawl-delay" and value and crawl_delay is None:
            try:
                crawl_delay = float(value)
            except ValueError:
                crawl_delay = None

    parser_crawl_delay = parser.crawl_delay(robots_user_agent)
    if parser_crawl_delay is not None:
        crawl_delay = float(parser_crawl_delay)

    return {
        "parser": parser,
        "user_agents_seen": user_agents,
        "disallow_rules_count": disallow_count,
        "allow_rules_count": allow_count,
        "sitemap_urls": sitemap_urls,
        "crawl_delay": crawl_delay,
        "allowed_samples": allowed_samples,
        "disallowed_samples": disallowed_samples,
    }


def build_robots_findings(summary: dict[str, Any]) -> list[Finding]:
    if not summary.get("enabled"):
        return []
    findings: list[Finding] = []
    if summary.get("robots_found"):
        findings.append(
            create_finding(
                title="robots.txt Reviewed",
                severity="Informational",
                category="Web DAST Scope",
                affected_url=str(summary.get("robots_url") or ""),
                service="http",
                evidence="robots.txt was fetched and reviewed.",
                confidence="High",
                impact="robots.txt can guide polite crawling but does not define authorisation.",
                recommendation="Use robots.txt as crawl guidance, but rely on written authorisation for testing scope.",
                verification="Review the Robots.txt Awareness report section.",
                limitation="robots.txt is not an access control mechanism and does not grant permission.",
                source=SOURCE,
            )
        )
    else:
        findings.append(
            create_finding(
                title="robots.txt Not Found",
                severity="Informational",
                category="Web DAST Scope",
                affected_url=str(summary.get("robots_url") or ""),
                service="http",
                evidence="robots.txt was not found at the expected location.",
                confidence="Medium",
                impact="No robots.txt crawl guidance was available at the standard location.",
                recommendation="Consider publishing robots.txt if crawl guidance is required.",
                verification="Review the robots.txt fetch status.",
                limitation="Absence of robots.txt does not imply permission to scan.",
                source=SOURCE,
            )
        )
    if int(summary.get("urls_skipped_by_robots") or 0):
        findings.append(
            create_finding(
                title="URLs Skipped Due to robots.txt",
                severity="Informational",
                category="Web DAST Scope",
                affected_url=str(summary.get("robots_url") or ""),
                service="http",
                evidence="One or more URLs were skipped because robots.txt disallowed them.",
                confidence="High",
                impact="robots.txt guidance reduced crawl coverage.",
                recommendation="Review written authorisation before testing disallowed paths.",
                verification="Review skipped URL samples and robots.txt rules.",
                limitation="robots.txt is advisory and may not reflect security boundaries.",
                source=SOURCE,
            )
        )
    if summary.get("sitemap_urls"):
        findings.append(
            create_finding(
                title="robots.txt Contains Sitemap",
                severity="Informational",
                category="Web Discovery",
                affected_url=str(summary.get("robots_url") or ""),
                service="http",
                evidence="robots.txt referenced one or more sitemap URLs.",
                confidence="High",
                impact="Sitemaps may reveal additional URLs for authorised review.",
                recommendation="Use sitemaps only when authorised and within defined scope.",
                verification="Review sitemap URLs in the robots summary.",
                limitation="Sitemaps may include URLs outside testing scope.",
                source=SOURCE,
            )
        )
    if summary.get("robots_found") and not summary.get("respect_robots"):
        findings.append(
            create_finding(
                title="robots.txt Rules Not Enforced",
                severity="Informational",
                category="Web DAST Scope",
                affected_url=str(summary.get("robots_url") or ""),
                service="http",
                evidence="robots.txt was reviewed, but --no-respect-robots was used.",
                confidence="High",
                impact="robots.txt guidance was reported but not used to restrict crawling.",
                recommendation="Only ignore robots.txt when written authorisation explicitly allows it.",
                verification="Review CLI options and written authorisation.",
                limitation="robots.txt is advisory, but ignoring it may be inappropriate without permission.",
                source=SOURCE,
            )
        )
    return findings
