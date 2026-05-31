"""Parameter intelligence for safe endpoint discovery.

This module classifies parameter names only. It does not send requests,
generate payloads, or validate vulnerabilities.
"""

from __future__ import annotations

from typing import Any


SENSITIVE_PARAMETER_NAMES = {
    "token",
    "access_token",
    "refresh_token",
    "password",
    "passwd",
    "secret",
    "api_key",
    "key",
    "session",
    "auth",
    "jwt",
    "code",
}

PARAMETER_TYPES: dict[str, dict[str, Any]] = {
    "redirect": {
        "names": {"redirect", "redirect_uri", "return", "returnurl", "next", "url", "callback", "continue", "destination"},
        "potential_issue": "Open Redirect Candidate",
        "confidence": "Medium",
        "score": 15,
    },
    "idor": {
        "names": {"id", "user_id", "account_id", "order_id", "invoice_id", "customer_id", "profile_id", "uid"},
        "potential_issue": "IDOR Candidate",
        "confidence": "Medium",
        "score": 20,
    },
    "path_traversal": {
        "names": {"file", "filename", "path", "dir", "folder", "template", "page"},
        "potential_issue": "Path Traversal Candidate",
        "confidence": "Medium",
        "score": 20,
    },
    "ssrf": {
        "names": {"url", "uri", "endpoint", "host", "domain", "image", "feed", "webhook"},
        "potential_issue": "SSRF Candidate",
        "confidence": "Medium",
        "score": 20,
    },
    "injection_reflection": {
        "names": {"q", "query", "search", "keyword", "term", "name", "message", "comment"},
        "potential_issue": "Injection or Reflection Candidate",
        "confidence": "Low",
        "score": 10,
    },
    "debug_config": {
        "names": {"debug", "test", "env", "config", "verbose"},
        "potential_issue": "Debug/Configuration Exposure Candidate",
        "confidence": "Medium",
        "score": 15,
    },
    "sensitive_token": {
        "names": SENSITIVE_PARAMETER_NAMES,
        "potential_issue": "Sensitive Token Parameter Observed",
        "confidence": "Medium",
        "score": 20,
    },
}


def is_sensitive_parameter_name(name: str) -> bool:
    return _normalise_name(name) in SENSITIVE_PARAMETER_NAMES


def classify_parameter(name: str) -> dict[str, Any]:
    """Classify a parameter name as a manual-validation candidate."""
    normalised = _normalise_name(name)
    if not normalised:
        return {
            "parameter_type": "unknown",
            "potential_issue": "",
            "confidence": "Low",
            "candidate_score": 0,
            "recommendation": "Review this parameter only if endpoint context suggests it is security relevant.",
            "manual_validation_note": "Parameter candidates are not confirmed vulnerabilities.",
        }
    matches: list[tuple[str, dict[str, Any]]] = []
    for parameter_type, metadata in PARAMETER_TYPES.items():
        if normalised in metadata["names"]:
            matches.append((parameter_type, metadata))
    if not matches:
        return {
            "parameter_type": "unknown",
            "potential_issue": "",
            "confidence": "Low",
            "candidate_score": 0,
            "recommendation": "Review this parameter only if endpoint context suggests it is security relevant.",
            "manual_validation_note": "Parameter candidates are not confirmed vulnerabilities.",
        }
    parameter_type, metadata = sorted(matches, key=lambda item: item[1]["score"], reverse=True)[0]
    return {
        "parameter_type": parameter_type,
        "potential_issue": metadata["potential_issue"],
        "confidence": metadata["confidence"],
        "candidate_score": int(metadata["score"]),
        "recommendation": "Manually validate behaviour within program scope and rules of engagement.",
        "manual_validation_note": "Manual validation required. Parameter candidates are not confirmed vulnerabilities.",
    }


def _normalise_name(name: str) -> str:
    return str(name or "").strip().lower()
