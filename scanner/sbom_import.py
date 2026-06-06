"""Local SBOM import helpers for A03 Software Supply Chain evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scanner.evidence import redact_nested
from scanner.service_fingerprint import normalise_cpe


class SBOMImportError(ValueError):
    """Raised when a local SBOM file cannot be parsed safely."""


def load_sbom(path: str | Path) -> dict[str, Any]:
    sbom_path = Path(path)
    if not sbom_path.exists():
        raise SBOMImportError(f"Local SBOM file was not found: {sbom_path}")
    try:
        data = json.loads(sbom_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SBOMImportError(f"Local SBOM file is not valid JSON: {sbom_path}") from exc
    if not isinstance(data, dict):
        raise SBOMImportError("SBOM must be a JSON object.")
    return redact_nested(data)


def parse_cyclonedx_sbom(data: dict[str, Any]) -> list[dict[str, Any]]:
    if str(data.get("bomFormat") or "").lower() != "cyclonedx":
        return []
    components = []
    for item in data.get("components") or []:
        if not isinstance(item, dict):
            continue
        licenses = []
        for entry in item.get("licenses") or []:
            license_data = entry.get("license") if isinstance(entry, dict) else None
            if isinstance(license_data, dict):
                licenses.append(str(license_data.get("id") or license_data.get("name") or ""))
        components.append(
            {
                "name": str(item.get("name") or "").strip(),
                "version": str(item.get("version") or "").strip(),
                "type": str(item.get("type") or "library"),
                "purl": str(item.get("purl") or ""),
                "cpe": normalise_cpe(item.get("cpe")) or "",
                "license": ", ".join(sorted({license for license in licenses if license})),
                "supplier": _supplier_name(item.get("supplier")),
                "hashes_present": bool(item.get("hashes")),
                "external_references_count": len(item.get("externalReferences") or []),
                "sbom_format": "CycloneDX",
            }
        )
    return normalise_sbom_components(components)


def parse_spdx_sbom(data: dict[str, Any]) -> list[dict[str, Any]]:
    if not str(data.get("spdxVersion") or "").startswith("SPDX"):
        return []
    components = []
    for item in data.get("packages") or []:
        if not isinstance(item, dict):
            continue
        refs = item.get("externalRefs") or []
        purl = _external_ref(refs, "purl")
        cpe = _external_ref(refs, "cpe23Type") or _external_ref(refs, "cpe22Type")
        components.append(
            {
                "name": str(item.get("name") or "").strip(),
                "version": str(item.get("versionInfo") or "").strip(),
                "type": "library",
                "purl": purl,
                "cpe": normalise_cpe(cpe) or "",
                "license": str(item.get("licenseConcluded") or item.get("licenseDeclared") or ""),
                "supplier": str(item.get("supplier") or ""),
                "hashes_present": bool(item.get("checksums")),
                "external_references_count": len(refs),
                "sbom_format": "SPDX",
            }
        )
    return normalise_sbom_components(components)


def normalise_sbom_components(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalised = []
    for item in components or []:
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        normalised.append(
            redact_nested(
                {
                    "name": name,
                    "version": str(item.get("version") or "").strip(),
                    "type": str(item.get("type") or "library"),
                    "purl": str(item.get("purl") or ""),
                    "cpe": normalise_cpe(item.get("cpe")) or "",
                    "license": str(item.get("license") or ""),
                    "supplier": str(item.get("supplier") or ""),
                    "hashes_present": bool(item.get("hashes_present")),
                    "external_references_count": int(item.get("external_references_count") or 0),
                    "sbom_format": str(item.get("sbom_format") or ""),
                }
            )
        )
    return normalised


def parse_sbom(data: dict[str, Any]) -> list[dict[str, Any]]:
    return parse_cyclonedx_sbom(data) or parse_spdx_sbom(data)


def _supplier_name(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("name") or "")
    return str(value or "")


def _external_ref(refs: list[dict[str, Any]], ref_type: str) -> str:
    for ref in refs:
        if str(ref.get("referenceType") or "") == ref_type:
            return str(ref.get("referenceLocator") or "")
    return ""
