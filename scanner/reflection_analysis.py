"""Safe marker reflection observation for A05 Injection candidate analysis."""

from __future__ import annotations

import re
import secrets
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen


MAX_RESPONSE_BYTES = 256 * 1024
MARKER_PREFIX = "VULSCAN_SAFE_MARKER_"


def generate_safe_marker() -> str:
    return f"{MARKER_PREFIX}{secrets.token_hex(4).upper()}"


def is_safe_marker(marker: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_]+", str(marker or "")))


def build_reflection_url(url: str, parameter_name: str, marker: str) -> str:
    if not is_safe_marker(marker):
        raise ValueError("Safe reflection marker must be alphanumeric with underscores only.")
    parsed = urlsplit(str(url or ""))
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    new_pairs: list[tuple[str, str]] = []
    for name, value in pairs:
        if name == parameter_name:
            new_pairs.append((name, marker))
            replaced = True
        else:
            new_pairs.append((name, value))
    if not replaced:
        raise ValueError("Selected parameter was not present in the URL query string.")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(new_pairs, doseq=True), parsed.fragment))


def classify_reflection_context(snippet: str, marker: str) -> str:
    text = str(snippet or "")
    if marker not in text:
        return "unknown"
    lower = text.lower()
    marker_index = text.find(marker)
    before = text[max(0, marker_index - 80):marker_index]
    after = text[marker_index + len(marker):marker_index + len(marker) + 80]
    window = f"{before}{marker}{after}"
    if re.search(r"<script\b|</script>|(?:var|let|const|function|location)\s*[.=]", lower):
        return "script_like"
    if re.search(r"href\s*=|src\s*=|action\s*=|location\s*=|url\s*\(", window, re.IGNORECASE):
        return "url_like"
    if re.search(r"[\{\[,]\s*\"?[A-Za-z0-9_.-]+\"?\s*:\s*\"?" + re.escape(marker), window) or re.search(re.escape(marker) + r"\"?\s*[,}\]]", window):
        return "json_like"
    if re.search(r"[A-Za-z_:.-]+\s*=\s*['\"]?[^<>]{0,80}" + re.escape(marker), window):
        return "attribute_like"
    if "<" in before[-30:] or ">" in after[:30]:
        return "html_text"
    return "html_text"


def redact_reflection_snippet(snippet: str) -> str:
    value = str(snippet or "")
    replacements = [
        (r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]"),
        (r"(?i)(password|passwd|pwd|token|api[_-]?key|secret|session[_-]?id|sid)\s*[:=]\s*['\"]?[^'\"\s;&<]+", r"\1=[REDACTED]"),
        (r"(?i)(cookie:\s*)[^;\r\n<\s]+", r"\1[REDACTED]"),
        (r"(?i)(set-cookie:\s*)[^;\r\n<]+", r"\1[REDACTED]"),
    ]
    for pattern, replacement in replacements:
        value = re.sub(pattern, replacement, value)
    return value[:600]


def snippet_around_marker(body: str, marker: str, radius: int = 180) -> str:
    index = str(body or "").find(marker)
    if index < 0:
        return ""
    start = max(0, index - radius)
    end = min(len(body), index + len(marker) + radius)
    return redact_reflection_snippet(body[start:end])


def observe_safe_reflection(
    url: str,
    parameter_name: str,
    timeout: int = 5,
    request_delay: float = 1.0,
    opener: Any | None = None,
) -> dict[str, Any]:
    parsed = urlsplit(str(url or ""))
    if parsed.scheme not in {"http", "https"} or not parsed.query:
        return _observation(url, parameter_name, "", False, "unknown", "", "skipped", "Only HTTP(S) GET URLs with query parameters are eligible.")
    marker = generate_safe_marker()
    reflection_url = build_reflection_url(url, parameter_name, marker)
    if request_delay > 0:
        time.sleep(float(request_delay))
    request = Request(reflection_url, method="GET", headers={"User-Agent": "VulScan-safe-reflection/20.5"})
    try:
        response = opener(request, timeout=timeout) if opener else urlopen(request, timeout=timeout)
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    except Exception as exc:
        return _observation(url, parameter_name, marker, False, "unknown", "", "error", f"Safe reflection request failed: {exc}")
    body = raw[:MAX_RESPONSE_BYTES].decode("utf-8", errors="replace")
    reflected = marker in body
    snippet = snippet_around_marker(body, marker) if reflected else ""
    context = classify_reflection_context(snippet, marker) if reflected else "unknown"
    return _observation(url, parameter_name, marker, reflected, context, snippet, "observed", "Harmless marker observation completed.")


def _observation(url: str, parameter_name: str, marker: str, reflected: bool, context: str, snippet: str, status: str, note: str) -> dict[str, Any]:
    return {
        "url": url,
        "parameter": parameter_name,
        "marker": marker,
        "marker_is_safe": is_safe_marker(marker) if marker else True,
        "marker_reflected": reflected,
        "reflection_context": context,
        "redacted_snippet": snippet,
        "status": status,
        "note": note,
        "full_body_stored": False,
    }
