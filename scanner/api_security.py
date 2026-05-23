"""API key protection helpers for the local VulScan API."""

from __future__ import annotations

import os
from hmac import compare_digest

from fastapi import Header, HTTPException


API_KEY_ENV_VAR = "VULSCAN_API_KEY"
API_KEY_ERROR_DETAIL = "Invalid or missing API key."
LOCAL_DEVELOPMENT_WARNING = "API key not configured. Protected endpoints are running in local development mode."


def get_configured_api_key() -> str | None:
    """Return the configured local API key, if one has been set."""
    value = os.environ.get(API_KEY_ENV_VAR)
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def get_bearer_token(authorization: str | None) -> str | None:
    """Extract a bearer token from an Authorization header."""
    if not authorization:
        return None
    scheme, separator, token = authorization.partition(" ")
    if separator and scheme.lower() == "bearer" and token.strip():
        return token.strip()
    return None


async def require_api_key(
    x_vulscan_api_key: str | None = Header(default=None, alias="X-VulScan-API-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> None:
    """Require the configured API key for protected endpoints."""
    configured_key = get_configured_api_key()
    if configured_key is None:
        return

    supplied_keys = [x_vulscan_api_key, get_bearer_token(authorization)]
    if any(candidate and compare_digest(candidate.strip(), configured_key) for candidate in supplied_keys):
        return

    raise HTTPException(status_code=401, detail=API_KEY_ERROR_DETAIL)
