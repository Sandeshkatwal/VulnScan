"""Safe TLS certificate metadata collection for A04 evidence."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any


def get_tls_certificate_metadata(hostname: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    """Collect certificate metadata with one normal TLS handshake.

    This does not test ciphers, protocol downgrade behaviour, or exploitability.
    """
    host = str(hostname or "").strip()
    result: dict[str, Any] = {
        "enabled": True,
        "host": host,
        "port": int(port),
        "metadata_available": False,
        "subject_common_name": "",
        "issuer_common_name": "",
        "not_before": "",
        "not_after": "",
        "expired": None,
        "days_until_expiry": None,
        "hostname_match": None,
        "self_signed_indicator": None,
        "error": "",
        "limitations": [
            "TLS metadata uses a normal certificate handshake only.",
            "Weak cipher, protocol downgrade, and exploit testing are not performed.",
        ],
    }
    if not host:
        result["error"] = "Hostname was not provided."
        return result
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
        return metadata_from_certificate(cert, hostname=host, port=port)
    except Exception as exc:
        result["error"] = str(exc)[:240]
        return result


def metadata_from_certificate(cert: dict[str, Any], hostname: str = "", port: int = 443) -> dict[str, Any]:
    not_after = str(cert.get("notAfter") or "")
    not_before = str(cert.get("notBefore") or "")
    expires_at = _parse_cert_time(not_after)
    now = datetime.now(timezone.utc)
    days_until_expiry = None
    expired = None
    if expires_at:
        delta = expires_at - now
        days_until_expiry = delta.days
        expired = delta.total_seconds() < 0
    subject_cn = _common_name(cert.get("subject") or ())
    issuer_cn = _common_name(cert.get("issuer") or ())
    hostname_match = None
    if hostname:
        try:
            ssl.match_hostname(cert, hostname)
            hostname_match = True
        except Exception:
            hostname_match = False
    return {
        "enabled": True,
        "host": hostname,
        "port": int(port),
        "metadata_available": True,
        "subject_common_name": subject_cn,
        "issuer_common_name": issuer_cn,
        "not_before": not_before,
        "not_after": not_after,
        "expired": expired,
        "days_until_expiry": days_until_expiry,
        "hostname_match": hostname_match,
        "self_signed_indicator": bool(subject_cn and issuer_cn and subject_cn == issuer_cn),
        "error": "",
        "limitations": [
            "TLS metadata uses a normal certificate handshake only.",
            "Weak cipher, protocol downgrade, and exploit testing are not performed.",
        ],
    }


def _parse_cert_time(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _common_name(parts: Any) -> str:
    for group in parts or []:
        for key, value in group:
            if str(key).lower() == "commonname":
                return str(value)
    return ""
