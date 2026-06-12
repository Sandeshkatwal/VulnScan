"""Public beta version metadata for VulScan."""

from __future__ import annotations

import platform
import sys
from typing import Any


APP_NAME = "VulScan"
VERSION = "22.0.0-beta"
RELEASE_CHANNEL = "public-beta"
BUILD_STATUS = "stabilisation"
AUTHORISED_USE_ONLY = True


def version_metadata() -> dict[str, Any]:
    """Return safe public version metadata."""
    return {
        "app_name": APP_NAME,
        "scanner": APP_NAME,
        "version": VERSION,
        "api_version": VERSION,
        "release_channel": RELEASE_CHANNEL,
        "build_status": BUILD_STATUS,
        "authorised_use_only": AUTHORISED_USE_ONLY,
        "safety_statement": "Authorised testing only.",
        "python_version": platform.python_version(),
        "python_executable": PathlessExecutable(sys.executable),
        "platform": platform.platform(),
    }


def PathlessExecutable(executable: str) -> str:
    """Return only the executable name to avoid leaking local paths."""
    return executable.replace("\\", "/").split("/")[-1]
