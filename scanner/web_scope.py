"""Web DAST scope and allowlist controls."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from scanner.finding import Finding, create_finding
from scanner.web_crawler import normalize_url, should_skip_url


SOURCE = "web_scope"
SKIPPED_SAMPLE_LIMIT = 100
SKIP_REASONS = {
    "skipped_external_host",
    "skipped_denied_host",
    "skipped_denied_path",
    "skipped_not_allowed_path",
    "skipped_unsupported_scheme",
    "skipped_static_file",
    "skipped_duplicate",
    "skipped_depth_limit",
    "skipped_page_limit",
}
LIMITATIONS = [
    "Scope controls depend on URL parsing and configured allow/deny rules.",
    "External hosts are not tested by default.",
    "Scope controls reduce crawl coverage when allow or deny rules exclude URLs.",
]


@dataclass
class WebScope:
    """Effective scope rules for passive Web DAST."""

    start_url: str
    allow_hosts: list[str] = field(default_factory=list)
    deny_hosts: list[str] = field(default_factory=list)
    allow_paths: list[str] = field(default_factory=list)
    deny_paths: list[str] = field(default_factory=list)
    include_subdomains: bool = False
    same_host_only: bool = True
    max_pages: int = 20
    max_depth: int = 2
    skipped_counts: dict[str, int] = field(default_factory=dict)
    skipped_url_samples: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.start_url = normalize_url(self.start_url)
        parts = urlsplit(self.start_url)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            raise ValueError("--url must be an absolute http or https URL.")
        self.start_host = parts.netloc.lower()
        self.start_hostname = (parts.hostname or self.start_host).lower()
        self.allow_hosts = _normalize_hosts(self.allow_hosts)
        self.deny_hosts = _normalize_hosts(self.deny_hosts)
        self.allow_paths = _normalize_paths(self.allow_paths)
        self.deny_paths = _normalize_paths(self.deny_paths)
        self.max_pages = int(self.max_pages)
        self.max_depth = int(self.max_depth)
        self.skipped_counts = {reason: int(self.skipped_counts.get(reason) or 0) for reason in SKIP_REASONS}

    @property
    def allowed_hosts(self) -> list[str]:
        return list(dict.fromkeys([self.start_host] + self.allow_hosts))

    def decide_url(self, url: str, base_url: str | None = None) -> tuple[bool, str, str]:
        """Return allowed flag, reason, and normalised URL."""
        normalized = normalize_url(url, base_url)
        parts = urlsplit(normalized)
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"}:
            return False, "skipped_unsupported_scheme", normalized
        if should_skip_url(normalized):
            return False, "skipped_static_file", normalized
        if _host_matches(parts.netloc, parts.hostname, self.deny_hosts):
            return False, "skipped_denied_host", normalized
        if not self._host_allowed(parts):
            return False, "skipped_external_host", normalized
        path = parts.path or "/"
        if any(path.startswith(prefix) for prefix in self.deny_paths):
            return False, "skipped_denied_path", normalized
        if self.allow_paths and not any(path.startswith(prefix) for prefix in self.allow_paths):
            return False, "skipped_not_allowed_path", normalized
        return True, "allowed", normalized

    def record_skip(
        self,
        *,
        url: str,
        reason: str,
        source_url: str = "",
        depth: int = 0,
    ) -> None:
        if reason not in self.skipped_counts:
            return
        self.skipped_counts[reason] += 1
        if len(self.skipped_url_samples) >= SKIPPED_SAMPLE_LIMIT:
            return
        self.skipped_url_samples.append(
            {
                "url": url,
                "reason": reason,
                "source_url": source_url,
                "depth": int(depth),
            }
        )

    def summary(self) -> dict[str, Any]:
        """Return report-safe scope summary."""
        total_skipped = sum(int(value or 0) for value in self.skipped_counts.values())
        return {
            "enabled": True,
            "start_url": self.start_url,
            "start_host": self.start_host,
            "same_host_only": bool(self.same_host_only),
            "include_subdomains": bool(self.include_subdomains),
            "allowed_hosts": self.allowed_hosts,
            "denied_hosts": list(self.deny_hosts),
            "allowed_paths": list(self.allow_paths),
            "denied_paths": list(self.deny_paths),
            "max_pages": self.max_pages,
            "max_depth": self.max_depth,
            "skipped_external_hosts_count": self.skipped_counts["skipped_external_host"],
            "skipped_denied_hosts_count": self.skipped_counts["skipped_denied_host"],
            "skipped_denied_paths_count": self.skipped_counts["skipped_denied_path"],
            "skipped_not_allowed_paths_count": self.skipped_counts["skipped_not_allowed_path"],
            "skipped_static_files_count": self.skipped_counts["skipped_static_file"],
            "skipped_unsupported_schemes_count": self.skipped_counts["skipped_unsupported_scheme"],
            "skipped_duplicates_count": self.skipped_counts["skipped_duplicate"],
            "skipped_depth_limit_count": self.skipped_counts["skipped_depth_limit"],
            "skipped_page_limit_count": self.skipped_counts["skipped_page_limit"],
            "total_skipped_urls": total_skipped,
            "limitations": list(LIMITATIONS),
        }

    def _host_allowed(self, parts: Any) -> bool:
        netloc = parts.netloc.lower()
        hostname = (parts.hostname or "").lower()
        if _host_matches(netloc, hostname, self.allowed_hosts):
            return True
        if self.include_subdomains and hostname.endswith(f".{self.start_hostname}"):
            return True
        if self.same_host_only:
            return False
        return True


def build_web_scope(
    *,
    start_url: str,
    allow_hosts: list[str] | None = None,
    deny_hosts: list[str] | None = None,
    allow_paths: list[str] | None = None,
    deny_paths: list[str] | None = None,
    include_subdomains: bool = False,
    same_host_only: bool = True,
    max_pages: int = 20,
    max_depth: int = 2,
) -> WebScope:
    return WebScope(
        start_url=start_url,
        allow_hosts=list(allow_hosts or []),
        deny_hosts=list(deny_hosts or []),
        allow_paths=list(allow_paths or []),
        deny_paths=list(deny_paths or []),
        include_subdomains=include_subdomains,
        same_host_only=same_host_only,
        max_pages=max_pages,
        max_depth=max_depth,
    )


def build_scope_findings(summary: dict[str, Any], skipped_samples: list[dict[str, Any]]) -> list[Finding]:
    """Create concise standard findings for applied scope controls."""
    findings = [
        create_finding(
            title="Web DAST Scope Applied",
            severity="Informational",
            category="Web DAST Scope",
            affected_url=str(summary.get("start_url") or ""),
            service="http",
            evidence="Web DAST scope rules were applied to crawling and passive checks.",
            confidence="High",
            impact="Scope controls help keep passive web testing within authorised boundaries.",
            recommendation="Review scope rules before deeper authorised testing.",
            verification="Review the Web DAST Scope report section.",
            limitation="Scope controls depend on URL parsing and configured allow/deny rules.",
            source=SOURCE,
        )
    ]
    if int(summary.get("skipped_external_hosts_count") or 0):
        findings.append(
            create_finding(
                title="External URLs Skipped by Scope",
                severity="Informational",
                category="Web DAST Scope",
                affected_url=str(summary.get("start_url") or ""),
                service="http",
                evidence=_scope_evidence(
                    count=int(summary.get("skipped_external_hosts_count") or 0),
                    message="External URLs were discovered but skipped according to scope.",
                    samples=skipped_samples,
                    reasons={"skipped_external_host"},
                ),
                confidence="High",
                impact="External linked hosts were not assessed unless explicitly allowed.",
                recommendation="Add allowed hosts only when authorised to test them.",
                verification="Review skipped URL samples in the Web DAST Scope report section.",
                limitation="External hosts are not tested by default.",
                source=SOURCE,
            )
        )
    denied_count = int(summary.get("skipped_denied_hosts_count") or 0) + int(summary.get("skipped_denied_paths_count") or 0)
    if denied_count:
        findings.append(
            create_finding(
                title="URLs Skipped by Deny Rules",
                severity="Informational",
                category="Web DAST Scope",
                affected_url=str(summary.get("start_url") or ""),
                service="http",
                evidence=_scope_evidence(
                    count=denied_count,
                    message="One or more URLs matched deny-host or deny-path rules.",
                    samples=skipped_samples,
                    reasons={"skipped_denied_host", "skipped_denied_path"},
                ),
                confidence="High",
                impact="Configured deny rules reduced crawl and passive check coverage.",
                recommendation="Confirm denied paths represent areas that should not be tested.",
                verification="Review denied host and path rules in the Web DAST Scope report section.",
                limitation="Deny rules may reduce scan coverage.",
                source=SOURCE,
            )
        )
    return findings


def _scope_evidence(
    *,
    count: int,
    message: str,
    samples: list[dict[str, Any]],
    reasons: set[str],
) -> str:
    sample_urls = [
        str(sample.get("url") or "")
        for sample in samples
        if str(sample.get("reason") or "") in reasons
    ][:3]
    if sample_urls:
        return f"{message} Count: {count}. Samples: {', '.join(sample_urls)}."
    return f"{message} Count: {count}."


def _normalize_hosts(hosts: list[str]) -> list[str]:
    normalized: list[str] = []
    for host in hosts:
        value = str(host or "").strip().lower()
        if not value:
            continue
        parsed = urlsplit(value if "://" in value else f"//{value}")
        candidate = (parsed.netloc or parsed.path).strip().lower()
        candidate = candidate.strip("/")
        if candidate and candidate not in normalized:
            normalized.append(candidate)
    return normalized


def _normalize_paths(paths: list[str]) -> list[str]:
    normalized: list[str] = []
    for path in paths:
        value = str(path or "").strip()
        if not value:
            continue
        if not value.startswith("/"):
            value = f"/{value}"
        if value not in normalized:
            normalized.append(value)
    return normalized


def _host_matches(netloc: str, hostname: str | None, rules: list[str]) -> bool:
    host = (hostname or "").lower()
    netloc = netloc.lower()
    return any(rule == netloc or rule == host for rule in rules)
