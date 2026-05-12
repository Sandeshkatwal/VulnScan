"""Defensive TCP connect port scanning utilities."""

from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from scanner.service_detect import add_service_to_result


DEFAULT_TCP_PORTS = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    139,
    143,
    443,
    445,
    3306,
    3389,
    5432,
    6379,
    8080,
    8443,
)


class PortScanError(ValueError):
    """Raised when a target cannot be safely scanned."""


def validate_target(target: str) -> str:
    """Validate and normalize a hostname or IP address."""
    normalized = target.strip()
    if not normalized:
        raise PortScanError("Target is required.")

    if any(character.isspace() for character in normalized):
        raise PortScanError("Target must not contain whitespace.")

    if "://" in normalized or "/" in normalized:
        raise PortScanError("Target must be a hostname or IP address, not a URL or path.")

    try:
        ipaddress.ip_address(normalized)
        return normalized
    except ValueError:
        pass

    labels = normalized.rstrip(".").split(".")
    if not all(_is_valid_hostname_label(label) for label in labels):
        raise PortScanError("Target must be a valid hostname or IP address.")

    return normalized


def resolve_target(target: str) -> str:
    """Resolve a validated target to an IP address."""
    try:
        address_info = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise PortScanError(f"Could not resolve target: {target}") from exc

    for family, _, _, _, sockaddr in address_info:
        if family in (socket.AF_INET, socket.AF_INET6):
            return str(sockaddr[0])

    raise PortScanError(f"Could not resolve target to an IP address: {target}")


def scan_tcp_ports(
    target: str,
    ports: tuple[int, ...] = DEFAULT_TCP_PORTS,
    timeout: float = 1.0,
    max_workers: int = 32,
    open_only: bool = True,
) -> dict[str, Any]:
    """Scan common TCP ports with standard socket connections."""
    validated_target = validate_target(target)
    resolved_ip = resolve_target(validated_target)
    started_at = time.perf_counter()

    results: list[dict[str, Any]] = []
    worker_count = min(max_workers, len(ports))

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_port = {
            executor.submit(_scan_tcp_port, validated_target, resolved_ip, port, timeout): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            result = add_service_to_result(future.result())
            if not open_only or result["status"] == "open":
                results.append(result)

    results.sort(key=lambda item: item["port"])
    duration_seconds = round(time.perf_counter() - started_at, 3)

    return {
        "host": validated_target,
        "resolved_ip": resolved_ip,
        "protocol": "tcp",
        "scan_mode": "safe",
        "duration_seconds": duration_seconds,
        "ports_scanned": list(ports),
        "open_ports": results,
    }


def _scan_tcp_port(host: str, resolved_ip: str, port: int, timeout: float) -> dict[str, Any]:
    try:
        with socket.create_connection((resolved_ip, port), timeout=timeout):
            return {
                "host": host,
                "resolved_ip": resolved_ip,
                "port": port,
                "protocol": "tcp",
                "status": "open",
                "confidence": "high",
                "evidence": "TCP connection successful",
                "recommendation": "Review whether this service should be exposed",
            }
    except (ConnectionRefusedError, TimeoutError, OSError):
        return {
            "host": host,
            "resolved_ip": resolved_ip,
            "port": port,
            "protocol": "tcp",
            "status": "closed_or_filtered",
            "confidence": "medium",
            "evidence": "TCP connection was not established",
            "recommendation": "No action required from this result alone",
        }


def _is_valid_hostname_label(label: str) -> bool:
    if not label or len(label) > 63:
        return False

    if label.startswith("-") or label.endswith("-"):
        return False

    return all(character.isalnum() or character == "-" for character in label)
