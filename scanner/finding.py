"""Standard finding model for VulScan."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal


Severity = Literal["Critical", "High", "Medium", "Low", "Informational"]
Confidence = Literal["High", "Medium", "Low"]

SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}


def _created_at() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Finding:
    """Standard VulScan finding record."""

    id: str
    title: str
    severity: Severity
    category: str
    evidence: str
    confidence: Confidence
    impact: str
    recommendation: str
    verification: str
    limitation: str
    source: str
    affected_host: str | None = None
    affected_port: int | None = None
    affected_url: str | None = None
    service: str | None = None
    created_at: str = field(default_factory=_created_at)


def make_finding_id(
    source: str,
    title: str,
    affected_host: str | None = None,
    affected_port: int | None = None,
    affected_url: str | None = None,
    service: str | None = None,
) -> str:
    """Create a stable finding ID from identifying finding fields."""
    raw_id = "|".join(
        [
            source,
            title,
            affected_host or "",
            str(affected_port or ""),
            affected_url or "",
            service or "",
        ]
    )
    digest = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:12]
    return f"VULSCAN-{digest}"


def finding_to_dict(finding: Finding | dict[str, Any]) -> dict[str, Any]:
    """Convert a Finding to a report-safe dictionary."""
    if isinstance(finding, Finding):
        return asdict(finding)
    return finding


def findings_to_dicts(findings: list[Finding | dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert a list of findings to dictionaries sorted by severity."""
    return sorted(
        [finding_to_dict(finding) for finding in findings],
        key=lambda item: (SEVERITY_ORDER.get(str(item["severity"]), 99), str(item["title"])),
    )


def create_finding(
    title: str,
    severity: Severity,
    category: str,
    evidence: str,
    confidence: Confidence,
    impact: str,
    recommendation: str,
    verification: str,
    limitation: str,
    source: str,
    affected_host: str | None = None,
    affected_port: int | None = None,
    affected_url: str | None = None,
    service: str | None = None,
) -> Finding:
    """Create a standard finding with a stable ID."""
    return Finding(
        id=make_finding_id(
            source=source,
            title=title,
            affected_host=affected_host,
            affected_port=affected_port,
            affected_url=affected_url,
            service=service,
        ),
        title=title,
        severity=severity,
        category=category,
        affected_host=affected_host,
        affected_port=affected_port,
        affected_url=affected_url,
        service=service,
        evidence=evidence,
        confidence=confidence,
        impact=impact,
        recommendation=recommendation,
        verification=verification,
        limitation=limitation,
        source=source,
    )


def create_port_exposure_findings(open_ports: list[dict[str, Any]]) -> list[Finding]:
    """Create informational service exposure findings from open port inventory."""
    findings: list[Finding] = []

    for port_result in open_ports:
        service = str(port_result.get("service") or "unknown")
        port = int(port_result["port"])
        title = f"{service.upper()} Service Exposed" if service != "unknown" else f"Port {port} Exposed"
        findings.append(
            create_finding(
                title=title,
                severity="Informational",
                category="Service Exposure",
                affected_host=str(port_result["host"]),
                affected_port=port,
                service=service,
                evidence=str(port_result["evidence"]),
                confidence="High",
                impact="The service is reachable from the scanned network.",
                recommendation=str(port_result["recommendation"]),
                verification=f"Re-run VulScan or manually test TCP connectivity to port {port}.",
                limitation="An open port does not confirm a vulnerability by itself.",
                source="port_scan",
            )
        )

    return findings
