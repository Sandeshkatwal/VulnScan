"""Safe service detection based on common TCP port mappings."""

from __future__ import annotations

from typing import Any


COMMON_TCP_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
}


SERVICE_RECOMMENDATIONS = {
    "ftp": "FTP sends data in clear text. Use SFTP or FTPS where possible.",
    "ssh": "Ensure SSH is required. Use key-based authentication and restrict access to trusted IP addresses.",
    "telnet": "Telnet is insecure. Disable it and use SSH where possible.",
    "http": "Ensure the web service is intended to be exposed and review HTTP security headers.",
    "https": "Ensure the HTTPS service is intended to be exposed and validate TLS certificate and configuration.",
    "smb": "Ensure SMB is required. Restrict access to trusted internal networks and block port 445 from public or untrusted networks.",
    "rdp": "Ensure RDP is required. Restrict access using VPN, firewall rules, or trusted IP addresses.",
    "mysql": "Database services should not be publicly exposed. Restrict access to trusted hosts only.",
    "postgresql": "Database services should not be publicly exposed. Restrict access to trusted hosts only.",
    "redis": "Database services should not be publicly exposed. Restrict access to trusted hosts only.",
    "http-alt": "Ensure the web service is intended to be exposed and review HTTP security headers.",
    "https-alt": "Ensure the HTTPS service is intended to be exposed and validate TLS certificate and configuration.",
}


def identify_service(port: int) -> str:
    """Return a likely service name from a safe static port mapping."""
    return COMMON_TCP_SERVICES.get(port, "unknown")


def recommendation_for_service(service: str) -> str:
    """Return defensive guidance for a likely service."""
    return SERVICE_RECOMMENDATIONS.get(
        service,
        "Review whether this service should be exposed.",
    )


def add_service_to_result(result: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a scan result with a passive service name attached."""
    enriched_result = result.copy()
    service = identify_service(int(enriched_result["port"]))
    enriched_result["service"] = service

    if enriched_result.get("status") == "open":
        enriched_result["recommendation"] = recommendation_for_service(service)

    return enriched_result
