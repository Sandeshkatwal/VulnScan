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


def identify_service(port: int) -> str:
    """Return a likely service name from a safe static port mapping."""
    return COMMON_TCP_SERVICES.get(port, "unknown")


def add_service_to_result(result: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a scan result with a passive service name attached."""
    enriched_result = result.copy()
    enriched_result["service"] = identify_service(int(enriched_result["port"]))
    return enriched_result
