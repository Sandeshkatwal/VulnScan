"""OWASP Top 10:2025 assessment rules loader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


OWASP_RULES_PATH = Path("data") / "owasp" / "owasp_top10_2025_rules.json"
OWASP_VERSION = "2025"


class OWASPAssessmentRulesError(ValueError):
    """Raised when OWASP assessment rules are missing or invalid."""


def load_owasp_assessment_rules(path: str | Path = OWASP_RULES_PATH) -> dict[str, Any]:
    rules_path = Path(path)
    try:
        payload = json.loads(rules_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise OWASPAssessmentRulesError(f"OWASP assessment rules file was not found: {rules_path}") from exc
    except json.JSONDecodeError as exc:
        raise OWASPAssessmentRulesError(f"OWASP assessment rules file is not valid JSON: {rules_path}") from exc
    categories = payload.get("categories")
    if payload.get("version") != OWASP_VERSION:
        raise OWASPAssessmentRulesError("OWASP assessment rules must use version 2025.")
    if not isinstance(categories, list) or len(categories) != 10:
        raise OWASPAssessmentRulesError("OWASP assessment rules must include exactly ten categories.")
    seen: set[str] = set()
    for category in categories:
        owasp_id = str(category.get("owasp_id") or "")
        if not owasp_id.startswith("A") or ":2025" not in owasp_id:
            raise OWASPAssessmentRulesError("Each OWASP category must include a 2025 owasp_id.")
        if owasp_id in seen:
            raise OWASPAssessmentRulesError(f"Duplicate OWASP category: {owasp_id}")
        seen.add(owasp_id)
    return payload


def categories_by_id(rules: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(category["owasp_id"]): category for category in rules.get("categories", [])}
