"""Normalised credentialed audit result models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


AUDIT_STATUSES = {"success", "failed", "skipped", "partial"}
CHECK_STATUSES = {"success", "failed", "skipped", "timeout", "partial"}


@dataclass(frozen=True)
class CredentialedAuditError:
    """Safe credentialed audit error metadata."""

    error_code: str
    message: str
    severity: str
    safe_detail: str
    source: str
    check_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CredentialedCheckResult:
    """Normalised result for one credentialed audit check or command."""

    check_id: str
    check_name: str
    source: str
    status: str
    command_name: str = ""
    duration_seconds: float = 0.0
    findings_count: int = 0
    error_code: str | None = None
    error_message: str = ""
    evidence_summary: str = ""
    skipped_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if data["status"] not in CHECK_STATUSES:
            data["status"] = "failed"
        return _drop_none(data)


@dataclass(frozen=True)
class CredentialedAuditResult:
    """Normalised result for a credentialed audit module."""

    source: str
    module_name: str
    status: str
    target: str
    authenticated: bool
    auth_method: str
    username: str
    profile: str
    started_at: str
    ended_at: str
    duration_seconds: float
    checks_planned: int
    checks_completed: int
    checks_failed: int
    checks_skipped: int
    findings: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    errors: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    performance: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if data["status"] not in AUDIT_STATUSES:
            data["status"] = "failed"
        return _drop_none(data)


def build_error(
    *,
    error_code: str | None,
    message: str,
    source: str,
    check_name: str = "",
    severity: str = "error",
    safe_detail: str = "",
) -> dict[str, Any] | None:
    """Build a safe normalised error dictionary."""
    if not error_code and not message:
        return None
    return CredentialedAuditError(
        error_code=str(error_code or "UNKNOWN"),
        message=message,
        severity=severity,
        safe_detail=safe_detail,
        source=source,
        check_name=check_name,
    ).to_dict()


def _drop_none(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item is not None}
