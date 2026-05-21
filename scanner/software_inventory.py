"""Software and service inventory normalisation for VulScan."""

from __future__ import annotations

from typing import Any

from scanner.service_fingerprint import (
    extract_product_version_from_banner,
    merge_fingerprint_metadata,
    normalise_cpe,
    normalise_product,
    normalise_vendor,
)


INVENTORY_LIMITATIONS = [
    "Service names from port scanning are inferred from common port mappings unless richer module evidence is available.",
    "Product and version are null when VulScan has no explicit evidence for them.",
    "Inventory entries are indicators for defensive review and do not confirm vulnerability by themselves.",
]


def build_software_inventory(scan_result: dict[str, Any]) -> dict[str, Any]:
    """Build a normalised software/service inventory from available scan evidence."""
    items: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()

    for port_result in scan_result.get("open_ports", []) or []:
        item = _inventory_item_from_port(scan_result, port_result)
        _append_unique(items, seen, item)

    ssh_item = _inventory_item_from_ssh_audit(scan_result)
    if ssh_item:
        _append_unique(items, seen, ssh_item)

    for item in _inventory_items_from_windows_audit(scan_result):
        _append_unique(items, seen, item)

    sources_used = sorted({str(item["source"]) for item in items if item.get("source")})
    return {
        "items": items,
        "total_items": len(items),
        "sources_used": sources_used,
        "limitations": list(INVENTORY_LIMITATIONS),
    }


def _inventory_item_from_port(scan_result: dict[str, Any], port_result: dict[str, Any]) -> dict[str, Any]:
    service_name = _normalise_service_name(port_result.get("service"))
    confidence = _normalise_confidence(port_result.get("confidence"), default="Medium")
    if port_result.get("status") == "open" and service_name != "unknown":
        confidence = "Medium"
    fingerprint = merge_fingerprint_metadata(
        dict(port_result.get("fingerprint") or {}),
        dict(port_result.get("service_fingerprint") or {}),
        dict(port_result.get("metadata") or {}),
        extract_product_version_from_banner(port_result.get("banner") or port_result.get("evidence")),
    )

    return {
        "asset": str(scan_result.get("host") or port_result.get("host") or ""),
        "host": str(port_result.get("host") or scan_result.get("host") or ""),
        "port": _safe_int(port_result.get("port")),
        "protocol": str(port_result.get("protocol") or "tcp").lower(),
        "service_name": service_name,
        "vendor": fingerprint.get("vendor"),
        "product": fingerprint.get("product"),
        "version": fingerprint.get("version"),
        "cpe": fingerprint.get("cpe"),
        "cpe_prefix": fingerprint.get("cpe_prefix"),
        "source": "service_detect" if service_name != "unknown" else "port_scan",
        "evidence": str(port_result.get("evidence") or "TCP port scan result."),
        "confidence": confidence,
        "metadata": {
            "status": port_result.get("status"),
            "resolved_ip": port_result.get("resolved_ip") or scan_result.get("resolved_ip"),
            "recommendation": port_result.get("recommendation"),
        },
    }


def _inventory_item_from_ssh_audit(scan_result: dict[str, Any]) -> dict[str, Any] | None:
    ssh_audit = scan_result.get("ssh_audit") or {}
    if not ssh_audit.get("enabled") and str(ssh_audit.get("status") or "") in {"", "skipped"}:
        return None

    return {
        "asset": str(scan_result.get("host") or ""),
        "host": str(scan_result.get("host") or ""),
        "port": _safe_int(ssh_audit.get("ssh_port") or 22),
        "protocol": "tcp",
        "service_name": "ssh",
        "vendor": normalise_vendor(ssh_audit.get("vendor")),
        "product": normalise_product(ssh_audit.get("product") or ssh_audit.get("ssh_product")),
        "version": ssh_audit.get("version") or ssh_audit.get("ssh_version"),
        "cpe": normalise_cpe(ssh_audit.get("cpe")),
        "cpe_prefix": normalise_cpe(ssh_audit.get("cpe_prefix")),
        "source": "ssh_audit",
        "evidence": "Credentialed SSH audit metadata was available.",
        "confidence": "Medium" if ssh_audit.get("authenticated") else "Low",
        "metadata": {
            "status": ssh_audit.get("status"),
            "authenticated": bool(ssh_audit.get("authenticated")),
            "os_family": ssh_audit.get("os_family"),
            "hostname": ssh_audit.get("hostname"),
            "kernel_summary": ssh_audit.get("kernel_summary"),
            "package_manager": ssh_audit.get("package_manager"),
        },
    }


def _inventory_items_from_windows_audit(scan_result: dict[str, Any]) -> list[dict[str, Any]]:
    summary = scan_result.get("windows_audit_summary") or {}
    if not summary.get("enabled"):
        return []

    host_info = summary.get("windows_host_info") or {}
    base = {
        "asset": str(scan_result.get("host") or ""),
        "host": str(scan_result.get("host") or ""),
        "protocol": "tcp",
        "vendor": normalise_vendor("microsoft") if host_info.get("os_caption") else None,
        "product": normalise_product(host_info.get("product") or host_info.get("os_caption")),
        "version": host_info.get("os_version") or host_info.get("os_build"),
        "cpe": normalise_cpe(host_info.get("cpe")),
        "cpe_prefix": normalise_cpe(host_info.get("cpe_prefix")),
        "source": "windows_audit",
        "confidence": "Medium" if summary.get("winrm_authenticated") or summary.get("windows_host_info_collected") else "Low",
        "metadata": {
            "status": summary.get("status"),
            "hostname": host_info.get("hostname"),
            "os_build": host_info.get("os_build"),
            "auth_method": summary.get("auth_method"),
        },
    }
    services = [
        ("smb", 445, summary.get("smb_reachable")),
        ("rdp", 3389, summary.get("rdp_reachable")),
        ("winrm", 5985, summary.get("winrm_http_reachable")),
        ("winrm", 5986, summary.get("winrm_https_reachable")),
    ]
    items = []
    for service_name, port, reachable in services:
        if not _is_reachable(reachable):
            continue
        item = dict(base)
        item.update(
            {
                "port": port,
                "service_name": service_name,
                "evidence": f"Windows audit reported {service_name} reachability as {reachable}.",
            }
        )
        item["metadata"] = dict(base["metadata"])
        item["metadata"]["reachable"] = reachable
        items.append(item)
    return items


def _append_unique(items: list[dict[str, Any]], seen: set[tuple[Any, ...]], item: dict[str, Any]) -> None:
    key = (
        item.get("host"),
        item.get("port"),
        item.get("protocol"),
        item.get("service_name"),
        item.get("product"),
        item.get("version"),
        item.get("source"),
    )
    if key in seen:
        return
    seen.add(key)
    items.append(item)


def _normalise_service_name(value: Any) -> str:
    service = str(value or "unknown").strip().lower()
    aliases = {
        "http-alt": "http",
        "https-alt": "https",
        "microsoft-ds": "smb",
    }
    return aliases.get(service, service or "unknown")


def _normalise_confidence(value: Any, *, default: str) -> str:
    confidence = str(value or default).strip().lower()
    if confidence == "high":
        return "High"
    if confidence == "low":
        return "Low"
    return "Medium"


def _safe_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_reachable(value: Any) -> bool:
    if value is True:
        return True
    return str(value).strip().lower() in {"true", "yes", "reachable"}
