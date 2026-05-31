"""API helpers for Finding Fingerprinting and Duplicate Detection."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scanner.database import DB_PATH
from scanner.duplicate_detection import (
    check_duplicate,
    duplicate_summary,
    fingerprint_item,
    get_duplicate_group,
    get_fingerprint,
    list_duplicate_groups,
)


def build_duplicate_item(payload: dict[str, Any]) -> dict[str, Any]:
    """Convert API payload fields into the stable fingerprint input shape."""
    item = dict(payload)
    parameter_names = item.pop("parameter_names", None)
    parameter = item.pop("parameter", None)
    if not parameter_names and parameter:
        parameter_names = [parameter]
    item["parameter_names"] = parameter_names or []
    item.pop("store", None)
    return item


def api_fingerprint(payload: dict[str, Any], db_path: Path | str = DB_PATH) -> dict[str, Any]:
    item = build_duplicate_item(payload)
    store = bool(payload.get("store", False))
    item_type = str(payload.get("item_type") or "candidate")
    return {"fingerprint": fingerprint_item(item, item_type=item_type, db_path=db_path, store=store)}


def api_check_duplicate(payload: dict[str, Any], db_path: Path | str = DB_PATH) -> dict[str, Any]:
    item = build_duplicate_item(payload)
    item_type = str(payload.get("item_type") or "candidate")
    return check_duplicate(item, item_type=item_type, db_path=db_path, store=True)


def api_list_duplicate_groups(db_path: Path | str = DB_PATH) -> dict[str, Any]:
    return {"summary": duplicate_summary(db_path=db_path), "groups": list_duplicate_groups(db_path=db_path)}


def api_get_duplicate_group(group_id: str, db_path: Path | str = DB_PATH) -> dict[str, Any] | None:
    return get_duplicate_group(group_id, db_path=db_path)


def api_get_fingerprint(fingerprint_id: str, db_path: Path | str = DB_PATH) -> dict[str, Any] | None:
    return get_fingerprint(fingerprint_id, db_path=db_path)


def api_duplicate_summary(db_path: Path | str = DB_PATH) -> dict[str, Any]:
    return duplicate_summary(db_path=db_path)
