"""Scan safe project text files for unredacted secret-like values."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCAN_ROOTS = [
    ROOT / "README.md",
    ROOT / "docs",
    ROOT / "data" / "demo",
    ROOT / "reports" / "demo",
    ROOT / "dashboard" / "src",
    ROOT / "tests",
]
ALLOWLIST_MARKERS = (
    "[REDACTED]",
    "[REDACTED-BEARER]",
    "[REDACTED-COOKIE]",
    "REDACTED",
    "demo-token-redacted",
    "secret-demo-token",
    "simulated",
    "placeholder",
    "example",
    "dummy",
    "fake",
    "change-this-local-dev-key",
    "YOUR_API_KEY",
    "YOUR-API-KEY",
    "YOUR_KEY",
    "import.meta.env",
    "Never reveal",
    "abc123456",
    "secret_value",
    "secret123",
    "some-secret-string",
    "secret-token-demo",
    "demo-secret",
    "demo-bearer-token",
)
TEXT_SUFFIXES = {".md", ".txt", ".json", ".py", ".ts", ".tsx", ".css", ".yml", ".yaml", ".csv"}
PATTERNS = [
    ("bearer token", re.compile(r"bearer\s+([A-Za-z0-9._~+/=-]{12,})", re.I)),
    ("cookie", re.compile(r"\bcookie\s*[:=]\s*([^;\n]{12,})", re.I)),
    ("api key", re.compile(r"\bapi[_-]?key\s*[:=]\s*([^\s,'\"]{8,})", re.I)),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I)),
    ("password", re.compile(r"\bpassword\s*=\s*([^\s,'\"]{6,})", re.I)),
    ("secret", re.compile(r"\bsecret\s*=\s*([^\s,'\"]{6,})", re.I)),
    ("token", re.compile(r"\btoken\s*=\s*([^\s,'\"]{8,})", re.I)),
    ("aws access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b")),
]


@dataclass(frozen=True)
class SecretFinding:
    path: Path
    line_number: int
    kind: str
    preview: str


def _iter_files(paths: list[Path] | None = None) -> list[Path]:
    roots = paths or SCAN_ROOTS
    files: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        if root.is_file():
            candidates = [root]
        else:
            candidates = [path for path in root.rglob("*") if path.is_file()]
        for path in candidates:
            if path.suffix.lower() in TEXT_SUFFIXES and not any(part in {".git", "node_modules", ".venv311"} for part in path.parts):
                files.append(path)
    return sorted(set(files))


def _allowed(line: str, path: Path) -> bool:
    lowered = line.lower()
    if "tests" in path.parts:
        return True
    return any(marker.lower() in lowered for marker in ALLOWLIST_MARKERS)


def _preview(value: str) -> str:
    clean = value.strip()
    if len(clean) <= 6:
        return "[REDACTED]"
    return f"{clean[:3]}...[REDACTED]...{clean[-2:]}"


def scan_paths(paths: list[Path] | None = None) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for path in _iter_files(paths):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(lines, start=1):
            if _allowed(line, path):
                continue
            for kind, pattern in PATTERNS:
                match = pattern.search(line)
                if match:
                    value = match.group(1) if match.groups() else match.group(0)
                    findings.append(SecretFinding(path=path, line_number=line_number, kind=kind, preview=_preview(value)))
    return findings


def main() -> int:
    findings = scan_paths()
    if findings:
        print("FAIL: unredacted secret-like values detected")
        for finding in findings:
            rel = finding.path.relative_to(ROOT) if finding.path.is_relative_to(ROOT) else finding.path
            print(f"- {rel}:{finding.line_number}: {finding.kind}: {finding.preview}")
        return 1
    print("PASS: no unredacted secret-like values detected in safe text paths.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
