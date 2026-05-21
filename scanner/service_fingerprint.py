"""Local service fingerprint helpers for VulScan inventory normalisation."""

from __future__ import annotations

import re
from typing import Any


PRODUCT_ALIASES = {
    "apache": "apache_http_server",
    "apache httpd": "apache_http_server",
    "apache_httpd": "apache_http_server",
    "openssh": "openssh",
    "open ssh": "openssh",
    "nginx": "nginx",
    "ssh_server": "ssh_server",
}


def normalise_product(value: Any) -> str | None:
    """Return a conservative product identifier from local evidence."""
    product = str(value or "").strip().lower()
    if not product:
        return None
    product = product.replace("-", "_").replace(" ", "_")
    return PRODUCT_ALIASES.get(product, product)


def normalise_vendor(value: Any) -> str | None:
    """Return a conservative vendor identifier from local evidence."""
    vendor = str(value or "").strip().lower()
    if not vendor:
        return None
    return vendor.replace(" ", "_")


def normalise_cpe(value: Any) -> str | None:
    """Return a lower-case CPE string when local evidence provides one."""
    cpe = str(value or "").strip().lower()
    return cpe or None


def extract_product_version_from_banner(value: Any) -> dict[str, str | None]:
    """Extract a narrow product/version pair from common passive banner strings."""
    banner = str(value or "").strip()
    if not banner:
        return {"product": None, "version": None}
    patterns = [
        (r"\bOpenSSH[_/\s-]?([0-9][A-Za-z0-9._+-]*)", "openssh"),
        (r"\bApache(?:/| httpd[/\s])([0-9][A-Za-z0-9._+-]*)", "apache_http_server"),
        (r"\bnginx/([0-9][A-Za-z0-9._+-]*)", "nginx"),
    ]
    for pattern, product in patterns:
        match = re.search(pattern, banner, flags=re.IGNORECASE)
        if match:
            return {"product": product, "version": match.group(1)}
    return {"product": None, "version": None}


def merge_fingerprint_metadata(*sources: dict[str, Any]) -> dict[str, Any]:
    """Merge local fingerprint evidence without inventing missing values."""
    merged: dict[str, Any] = {}
    for source in sources:
        for key in ("vendor", "product", "version", "cpe", "cpe_prefix"):
            if merged.get(key):
                continue
            value = source.get(key)
            if value:
                merged[key] = value
    if merged.get("product"):
        merged["product"] = normalise_product(merged["product"])
    if merged.get("vendor"):
        merged["vendor"] = normalise_vendor(merged["vendor"])
    if merged.get("cpe"):
        merged["cpe"] = normalise_cpe(merged["cpe"])
    if merged.get("cpe_prefix"):
        merged["cpe_prefix"] = normalise_cpe(merged["cpe_prefix"])
    return merged
