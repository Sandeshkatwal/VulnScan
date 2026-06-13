"""FastAPI adapters for Version 22.2 pagination helpers."""

from __future__ import annotations

from fastapi import HTTPException

from scanner.pagination import PaginationError, pagination_error_response


def raise_pagination_http_error(exc: PaginationError) -> None:
    raise HTTPException(status_code=400, detail=pagination_error_response(str(exc))) from exc
