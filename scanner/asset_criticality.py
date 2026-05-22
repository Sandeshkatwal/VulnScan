"""Local asset criticality context for VulScan prioritisation."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any


DEFAULT_ASSET_CRITICALITY_PATH = Path("data") / "asset_context" / "sample_asset_criticality.json"
ALLOWED_CRITICALITIES = {"critical", "high", "medium", "low", "unknown"}


def normalise_asset_key(asset: Any) -> str:
    """Return a stable matching key for an asset identifier."""
    value = str(asset or "").strip()
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value.lower()


def normalise_criticality(value: Any) -> tuple[str, str | None]:
    """Return a supported criticality value and an optional warning."""
    criticality = str(value or "").strip().lower()
    if criticality in ALLOWED_CRITICALITIES:
        return criticality, None
    return "unknown", f"Invalid asset criticality '{value}' was treated as unknown."


def load_asset_criticality_context(path: Path | str) -> dict[str, Any]:
    """Load a local asset criticality context without raising user-facing errors."""
    context_path = Path(path)
    warnings: list[str] = []
    context: dict[str, Any] = {
        "context_name": None,
        "context_version": None,
        "description": "",
        "assets": [],
        "asset_index": {},
        "warnings": warnings,
        "loaded": False,
        "path": str(context_path),
    }

    if not context_path.exists():
        warnings.append(f"Asset criticality file was not found: {context_path}. Criticality will default to unknown.")
        return context

    try:
        raw = json.loads(context_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        warnings.append(f"Asset criticality file is not valid JSON: {context_path}. Criticality will default to unknown.")
        return context
    except OSError:
        warnings.append(f"Asset criticality file could not be read: {context_path}. Criticality will default to unknown.")
        return context

    if not isinstance(raw, dict):
        warnings.append("Asset criticality context must be a JSON object. Criticality will default to unknown.")
        return context

    assets = raw.get("assets")
    if assets is None:
        warnings.append("Asset criticality context is missing an assets list. Criticality will default to unknown.")
        assets = []
    if not isinstance(assets, list):
        warnings.append("Asset criticality context assets value must be a list. Criticality will default to unknown.")
        assets = []
    if not assets:
        warnings.append("Asset criticality context contains no asset entries.")

    context.update(
        {
            "context_name": raw.get("context_name"),
            "context_version": raw.get("context_version"),
            "description": raw.get("description") or "",
            "loaded": True,
        }
    )

    asset_index: dict[str, dict[str, Any]] = {}
    normalised_assets: list[dict[str, Any]] = []
    for index, entry in enumerate(assets, start=1):
        if not isinstance(entry, dict):
            warnings.append(f"Asset criticality entry {index} is malformed and was skipped.")
            continue

        asset = str(entry.get("asset") or "").strip()
        asset_key = normalise_asset_key(asset)
        if not asset_key:
            warnings.append(f"Asset criticality entry {index} is missing an asset value and was skipped.")
            continue

        criticality, warning = normalise_criticality(entry.get("criticality"))
        if warning:
            warnings.append(f"{warning} Asset: {asset}.")

        tags = entry.get("tags") or []
        if not isinstance(tags, list):
            warnings.append(f"Asset criticality entry for {asset} has non-list tags; tags were ignored.")
            tags = []
        aliases = entry.get("aliases") or []
        if not isinstance(aliases, list):
            warnings.append(f"Asset criticality entry for {asset} has non-list aliases; aliases were ignored.")
            aliases = []

        normalised_entry = {
            "asset": asset,
            "asset_key": asset_key,
            "criticality": criticality,
            "business_owner": str(entry.get("business_owner") or ""),
            "environment": str(entry.get("environment") or ""),
            "tags": [str(tag) for tag in tags],
            "notes": str(entry.get("notes") or ""),
            "aliases": [str(alias) for alias in aliases if str(alias).strip()],
        }
        normalised_assets.append(normalised_entry)

        keys = [asset_key] + [normalise_asset_key(alias) for alias in normalised_entry["aliases"]]
        for key in [key for key in keys if key]:
            if key in asset_index:
                warnings.append(f"Duplicate asset criticality mapping for '{key}' was ignored after the first entry.")
                continue
            asset_index[key] = normalised_entry

    context["assets"] = normalised_assets
    context["asset_index"] = asset_index
    return context


def resolve_asset_criticality(
    target: str,
    direct_value: str | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve asset criticality from direct CLI input or a loaded context."""
    limitations = [
        "Asset criticality is a local context input and should be reviewed regularly.",
        "Asset criticality does not confirm vulnerability or exploitability.",
    ]
    warnings: list[str] = []
    target_value = str(target or "")

    if direct_value is not None:
        criticality, warning = normalise_criticality(direct_value)
        if warning:
            warnings.append(warning)
        entry = ((context or {}).get("asset_index") or {}).get(normalise_asset_key(target_value)) or {}
        return {
            "enabled": True,
            "target": target_value,
            "criticality": criticality,
            "criticality_source": "direct" if criticality != "unknown" else "default_unknown",
            "business_owner": entry.get("business_owner") or "",
            "environment": entry.get("environment") or "",
            "tags": list(entry.get("tags") or []),
            "notes": entry.get("notes") or "",
            "context_name": (context or {}).get("context_name"),
            "context_version": (context or {}).get("context_version"),
            "limitations": limitations,
            "warnings": warnings,
        }

    asset_index = (context or {}).get("asset_index") or {}
    entry = asset_index.get(normalise_asset_key(target_value))
    if entry:
        return {
            "enabled": True,
            "target": target_value,
            "criticality": entry.get("criticality") or "unknown",
            "criticality_source": "file",
            "business_owner": entry.get("business_owner") or "",
            "environment": entry.get("environment") or "",
            "tags": list(entry.get("tags") or []),
            "notes": entry.get("notes") or "",
            "context_name": (context or {}).get("context_name"),
            "context_version": (context or {}).get("context_version"),
            "limitations": limitations,
            "warnings": warnings,
        }

    return {
        "enabled": True,
        "target": target_value,
        "criticality": "unknown",
        "criticality_source": "default_unknown",
        "business_owner": "",
        "environment": "",
        "tags": [],
        "notes": "",
        "context_name": (context or {}).get("context_name"),
        "context_version": (context or {}).get("context_version"),
        "limitations": limitations,
        "warnings": warnings,
    }


def disabled_asset_context(target: str) -> dict[str, Any]:
    """Return the default asset context when enrichment is disabled."""
    return {
        "enabled": False,
        "target": str(target or ""),
        "criticality": "unknown",
        "criticality_source": "default_unknown",
        "business_owner": "",
        "environment": "",
        "tags": [],
        "notes": "",
        "context_name": None,
        "context_version": None,
        "limitations": ["Asset criticality enrichment was not enabled."],
        "warnings": [],
    }
