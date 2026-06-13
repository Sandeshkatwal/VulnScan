"""Safe API error response helpers."""

from __future__ import annotations

from typing import Any

from fastapi.responses import JSONResponse


def api_error_payload(message: str, *, detail: str | None = None, status_code: int = 400) -> dict[str, Any]:
    return {
        "error": message,
        "detail": detail or message,
        "status_code": status_code,
        "safe_error": True,
    }


def api_error_response(message: str, *, detail: str | None = None, status_code: int = 400) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=api_error_payload(message, detail=detail, status_code=status_code))
