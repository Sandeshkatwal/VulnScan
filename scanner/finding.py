"""Standard finding model for VulScan."""

from __future__ import annotations

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
    risk_score: int = 0
    risk_label: str = "Informational"
    fix_priority: str = "Document and monitor"
    evidence_details: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_created_at)


def make_finding_id(sequence_number: int) -> str:
    """Create a sequential finding ID such as FINDING-0001."""
    return f"FINDING-{sequence_number:04d}"


def finding_to_dict(finding: Finding | dict[str, Any]) -> dict[str, Any]:
    """Convert a Finding to a report-safe dictionary."""
    if isinstance(finding, Finding):
        return asdict(finding)
    return finding


def findings_to_dicts(findings: list[Finding | dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert a list of findings to dictionaries sorted by risk score."""
    return sorted(
        [finding_to_dict(finding) for finding in findings],
        key=lambda item: (
            -int(item.get("risk_score", 0)),
            SEVERITY_ORDER.get(str(item["severity"]), 99),
            str(item["title"]),
        ),
    )


def assign_sequential_finding_ids(findings: list[Finding | dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert findings to dictionaries and assign sequential IDs after sorting."""
    from scanner.risk_score import apply_risk_scores

    numbered_findings = findings_to_dicts(apply_risk_scores(findings))
    for index, finding in enumerate(numbered_findings, start=1):
        finding["id"] = make_finding_id(index)
    return numbered_findings


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
    evidence_details: dict[str, Any] | None = None,
) -> Finding:
    """Create a standard finding with a temporary ID before scan-level numbering."""
    temporary_id = make_finding_id(0)
    return Finding(
        id=temporary_id,
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
        evidence_details=evidence_details or {},
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
