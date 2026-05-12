"""Passive TLS certificate auditing."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any


HTTPS_PORTS = {443, 8443}
CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


def audit_tls_services(
    open_ports: list[dict[str, Any]],
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """Run passive TLS certificate checks against detected HTTPS services."""
    findings: list[dict[str, Any]] = []

    for port_result in open_ports:
        port = int(port_result["port"])
        if port not in HTTPS_PORTS:
            continue

        findings.extend(
            _audit_tls_certificate(
                host=str(port_result["host"]),
                resolved_ip=str(port_result["resolved_ip"]),
                port=port,
                timeout=timeout,
            )
        )

    return findings


def _audit_tls_certificate(
    host: str,
    resolved_ip: str,
    port: int,
    timeout: float,
) -> list[dict[str, Any]]:
    context = ssl.create_default_context()

    try:
        with socket.create_connection((resolved_ip, port), timeout=timeout) as tcp_socket:
            with context.wrap_socket(tcp_socket, server_hostname=host) as tls_socket:
                certificate = tls_socket.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return [_certificate_validation_error(host, port, exc)]
    except ssl.SSLError as exc:
        return [
            _finding(
                title="Unable to validate certificate",
                severity="Medium",
                category="TLS certificate",
                affected_host=host,
                affected_port=port,
                evidence=f"TLS error: {exc.__class__.__name__}",
                recommendation="Review the TLS certificate chain and server TLS configuration.",
                verification="VulScan attempted a normal TLS handshake using Python ssl default validation.",
                limitation="Certificate details may be unavailable when the TLS handshake fails.",
            )
        ]
    except (TimeoutError, OSError, socket.timeout) as exc:
        return [
            _finding(
                title="Unable to validate certificate",
                severity="Medium",
                category="TLS certificate",
                affected_host=host,
                affected_port=port,
                evidence=f"Connection error: {exc.__class__.__name__}",
                recommendation="Confirm the HTTPS service is reachable and presenting a valid certificate.",
                verification="VulScan attempted a TCP connection followed by a normal TLS handshake.",
                limitation="Certificate details are unavailable because the TLS connection could not be completed.",
            )
        ]

    return _certificate_findings(host, port, certificate)


def _certificate_findings(
    host: str,
    port: int,
    certificate: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    valid_until = str(certificate.get("notAfter", ""))
    valid_from = str(certificate.get("notBefore", ""))
    subject = _name_tuple_to_string(certificate.get("subject", ()))
    issuer = _name_tuple_to_string(certificate.get("issuer", ()))
    days_remaining = _days_remaining(valid_until)

    evidence_parts = [
        f"Subject: {subject or 'Unavailable'}",
        f"Issuer: {issuer or 'Unavailable'}",
        f"Valid from: {valid_from or 'Unavailable'}",
        f"Valid until: {valid_until or 'Unavailable'}",
    ]
    if days_remaining is not None:
        evidence_parts.append(f"Days remaining: {days_remaining}")

    findings.append(
        _finding(
            title="Certificate information retrieved successfully",
            severity="Informational",
            category="TLS certificate",
            affected_host=host,
            affected_port=port,
            evidence="; ".join(evidence_parts),
            recommendation="Review certificate subject, issuer, validity dates, and renewal process.",
            verification="VulScan completed a normal TLS handshake and retrieved peer certificate information.",
            limitation="This check does not test weak ciphers, protocol downgrade behavior, or full PKI policy compliance.",
        )
    )

    if days_remaining is None:
        return findings

    if days_remaining < 0:
        findings.append(
            _finding(
                title="Expired certificate",
                severity="High",
                category="TLS certificate",
                affected_host=host,
                affected_port=port,
                evidence=f"Certificate expired on {valid_until}.",
                recommendation="Renew and deploy a valid TLS certificate immediately.",
                verification="VulScan parsed the certificate notAfter value from the TLS peer certificate.",
                limitation="System clock accuracy affects expiry calculations.",
            )
        )
    elif days_remaining <= 30:
        findings.append(
            _finding(
                title="Certificate expires within 30 days",
                severity="Medium",
                category="TLS certificate",
                affected_host=host,
                affected_port=port,
                evidence=f"Certificate expires on {valid_until}; days remaining: {days_remaining}.",
                recommendation="Plan certificate renewal before expiry.",
                verification="VulScan parsed the certificate notAfter value from the TLS peer certificate.",
                limitation="System clock accuracy affects expiry calculations.",
            )
        )

    return findings


def _certificate_validation_error(
    host: str,
    port: int,
    exc: ssl.SSLCertVerificationError,
) -> dict[str, Any]:
    message = str(exc)
    lower_message = message.lower()

    if "hostname" in lower_message or "not match" in lower_message:
        return _finding(
            title="Hostname mismatch",
            severity="High",
            category="TLS certificate",
            affected_host=host,
            affected_port=port,
            evidence=f"Certificate validation failed: {message}",
            recommendation="Deploy a certificate whose subject alternative names match the scanned hostname.",
            verification="Python ssl default certificate validation rejected the certificate during a normal TLS handshake.",
            limitation="Certificate details may be unavailable when validation fails before certificate retrieval.",
        )

    if "expired" in lower_message:
        return _finding(
            title="Expired certificate",
            severity="High",
            category="TLS certificate",
            affected_host=host,
            affected_port=port,
            evidence=f"Certificate validation failed: {message}",
            recommendation="Renew and deploy a valid TLS certificate immediately.",
            verification="Python ssl default certificate validation rejected the certificate during a normal TLS handshake.",
            limitation="Certificate details may be unavailable when validation fails before certificate retrieval.",
        )

    return _finding(
        title="Unable to validate certificate",
        severity="Medium",
        category="TLS certificate",
        affected_host=host,
        affected_port=port,
        evidence=f"Certificate validation failed: {message}",
        recommendation="Review certificate trust chain, hostname coverage, and validity dates.",
        verification="Python ssl default certificate validation rejected the certificate during a normal TLS handshake.",
        limitation="Certificate details may be unavailable when validation fails before certificate retrieval.",
    )


def _days_remaining(valid_until: str) -> int | None:
    if not valid_until:
        return None

    try:
        expiry = datetime.strptime(valid_until, CERT_DATE_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None

    return (expiry - datetime.now(timezone.utc)).days


def _name_tuple_to_string(name: object) -> str:
    if not isinstance(name, tuple):
        return ""

    parts: list[str] = []
    for relative_distinguished_name in name:
        if not isinstance(relative_distinguished_name, tuple):
            continue
        for item in relative_distinguished_name:
            if isinstance(item, tuple) and len(item) == 2:
                parts.append(f"{item[0]}={item[1]}")

    return ", ".join(parts)


def _finding(
    title: str,
    severity: str,
    category: str,
    affected_host: str,
    affected_port: int,
    evidence: str,
    recommendation: str,
    verification: str,
    limitation: str,
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "category": category,
        "affected_host": affected_host,
        "affected_port": affected_port,
        "evidence": evidence,
        "confidence": "medium",
        "recommendation": recommendation,
        "verification": verification,
        "limitation": limitation,
    }
