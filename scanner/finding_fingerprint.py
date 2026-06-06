"""Stable finding fingerprinting for duplicate detection."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit


FINGERPRINT_VERSION = "v1"
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE)
_HEX_UUID_RE = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)
_NUMERIC_RE = re.compile(r"^\d+$")

ISSUE_TYPE_ALIASES = {
    "idor_candidate": "idor",
    "access_control_candidate": "access_control",
    "open_redirect_candidate": "open_redirect",
    "open redirect candidate": "open_redirect",
    "reflected_input": "reflected_input",
    "injection_reflection_candidate": "reflected_input",
    "cors_indicator": "cors",
    "directory_listing_indicator": "directory_listing",
    "missing_header": "security_misconfiguration",
    "security header": "security_misconfiguration",
}


def normalise_url_for_fingerprint(url: str) -> dict[str, Any]:
    """Return URL fingerprint components without query values or fragments."""
    raw = str(url or "").strip()
    parsed = urlsplit(raw)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    netloc = host
    if port:
        netloc = f"{host}:{port}"
    path = normalise_path_for_fingerprint(parsed.path or "/")
    parameter_names = normalise_parameter_names([name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)])
    query = "&".join(parameter_names)
    normalised_url = urlunsplit((scheme, netloc, path, query, ""))
    return {
        "normalised_url": normalised_url,
        "scheme": scheme,
        "host": host,
        "port": port,
        "path_normalised": path,
        "parameter_names": parameter_names,
    }


def normalise_path_for_fingerprint(path: str) -> str:
    value = "/" + str(path or "/").strip().split("?", 1)[0].split("#", 1)[0].lstrip("/")
    segments: list[str] = []
    for segment in value.split("/"):
        if not segment:
            continue
        lowered = segment.lower()
        if _UUID_RE.match(lowered) or _HEX_UUID_RE.match(lowered):
            segments.append("{uuid}")
        elif _NUMERIC_RE.match(lowered):
            segments.append("{id}")
        else:
            segments.append(lowered)
    return "/" + "/".join(segments) if segments else "/"


def normalise_parameter_names(params: Any) -> list[str]:
    if params is None:
        return []
    if isinstance(params, str):
        values = [item.strip() for item in params.split(",")]
    else:
        values = []
        for item in params:
            if isinstance(item, dict):
                values.append(str(item.get("name") or item.get("parameter_name") or ""))
            else:
                values.append(str(item))
    return sorted({item.strip().lower() for item in values if item and item.strip()})


def normalise_issue_type(issue_type: Any) -> str:
    raw = str(issue_type or "").strip().lower().replace("-", "_")
    raw = re.sub(r"\s+", "_", raw)
    return ISSUE_TYPE_ALIASES.get(raw, raw)


def build_finding_fingerprint(item: dict[str, Any], item_type: str = "finding") -> dict[str, Any]:
    """Build a stable fingerprint record for a finding-like item."""
    url = str(item.get("affected_url") or item.get("url") or item.get("normalised_url") or item.get("original_url") or "")
    url_parts = normalise_url_for_fingerprint(url) if url else {
        "normalised_url": "",
        "scheme": "",
        "host": str(item.get("host") or item.get("target") or item.get("affected_host") or "").lower(),
        "port": item.get("port") or item.get("affected_port"),
        "path_normalised": normalise_path_for_fingerprint(str(item.get("path") or item.get("path_normalised") or "")),
        "parameter_names": [],
    }
    parameter_names = normalise_parameter_names(
        item.get("parameter_names")
        or item.get("parameters")
        or item.get("parameter_name")
        or item.get("parameter")
        or url_parts.get("parameter_names")
    )
    issue_type = normalise_issue_type(
        item.get("issue_type")
        or item.get("parameter_type")
        or item.get("potential_issue")
        or item.get("endpoint_category")
        or item.get("category")
        or item.get("title")
    )
    host = str(item.get("host") or url_parts.get("host") or item.get("target") or item.get("affected_host") or "").lower()
    port = item.get("port") or item.get("affected_port") or url_parts.get("port")
    data = {
        "version": FINGERPRINT_VERSION,
        "target": _norm(item.get("target") or item.get("affected_host") or host),
        "host": host,
        "path": str(item.get("path_normalised") or url_parts.get("path_normalised") or ""),
        "parameters": parameter_names,
        "issue_type": issue_type,
        "owasp_category": _norm(item.get("owasp_category") or item.get("owasp_id")),
        "source": _norm(item.get("source")),
        "cve": _norm(item.get("cve") or item.get("cve_id")),
        "service": _norm(item.get("service")),
        "port": "" if port is None else str(port),
        "method": _norm(item.get("method") or item.get("method_hint")),
    }
    digest = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {
        "fingerprint_id": f"fp_{uuid.uuid4().hex[:16].translate(str.maketrans('0123456789', 'abcdefghij'))}",
        "fingerprint_version": FINGERPRINT_VERSION,
        "fingerprint_hash": digest,
        "fingerprint_short": digest[:12],
        "target_normalised": data["target"],
        "host": host,
        "path_normalised": data["path"],
        "parameter_names": parameter_names,
        "issue_type": issue_type,
        "owasp_category": data["owasp_category"],
        "source": data["source"],
        "evidence_type": _norm(item.get("evidence_type")),
        "cve": data["cve"],
        "service": data["service"],
        "port": data["port"],
        "method": data["method"],
        "item_type": item_type,
        "item_id": _norm(item.get("id") or item.get("finding_id") or item.get("item_id")),
        "title": _norm(item.get("title") or item.get("finding_title") or item.get("potential_issue") or issue_type),
        "data": data,
        "created_at": now,
    }


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()
