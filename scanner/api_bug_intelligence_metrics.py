"""API helpers for local Bug Intelligence metrics."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scanner.bug_intelligence_metrics import build_bug_intelligence_metrics, export_metrics
from scanner.database import DB_PATH


def api_metrics_summary(
    *,
    range_name: str = "all-time",
    start_date: str | None = None,
    end_date: str | None = None,
    program_name: str | None = None,
    db_path: Path | str = DB_PATH,
) -> dict[str, Any]:
    return build_bug_intelligence_metrics(
        range_name=range_name,
        start_date=start_date,
        end_date=end_date,
        program_name=program_name,
        db_path=db_path,
    )


def api_metrics_programs(**kwargs: Any) -> dict[str, Any]:
    metrics = api_metrics_summary(**kwargs)["bug_intelligence_metrics"]
    return {"programs": metrics["top_programs"], "date_range": metrics["date_range"]}


def api_metrics_classes(**kwargs: Any) -> dict[str, Any]:
    metrics = api_metrics_summary(**kwargs)["bug_intelligence_metrics"]
    return {"classes": metrics["top_vulnerability_classes"], "date_range": metrics["date_range"]}


def api_metrics_monthly(**kwargs: Any) -> dict[str, Any]:
    metrics = api_metrics_summary(**kwargs)["bug_intelligence_metrics"]
    return {"monthly_activity": metrics["monthly_activity"], "date_range": metrics["date_range"]}


def api_metrics_outcomes(**kwargs: Any) -> dict[str, Any]:
    metrics = api_metrics_summary(**kwargs)["bug_intelligence_metrics"]
    return {"outcome_distribution": metrics["outcome_distribution"], "date_range": metrics["date_range"]}


def api_metrics_export(format_name: str = "json", **kwargs: Any) -> dict[str, Any] | str:
    exported = export_metrics(format_name=format_name, **kwargs)
    if format_name == "json":
        import json

        return json.loads(exported)
    return exported
