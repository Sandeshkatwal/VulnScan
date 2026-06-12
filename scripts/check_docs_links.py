"""Basic local Markdown link checker for VulScan docs."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def is_external(target: str) -> bool:
    return target.startswith(("http://", "https://", "mailto:", "#"))


def main() -> int:
    failures: list[str] = []
    for path in [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md")), ROOT / "dashboard" / "README.md"]:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for match in LINK_RE.finditer(text):
            target = match.group(1).split("#", 1)[0].strip()
            if not target or is_external(target):
                continue
            candidate = (path.parent / unquote(target)).resolve()
            try:
                candidate.relative_to(ROOT)
            except ValueError:
                failures.append(f"{path.relative_to(ROOT)} links outside repo: {target}")
                continue
            if not candidate.exists():
                failures.append(f"{path.relative_to(ROOT)} missing link: {target}")
    if failures:
        print("FAIL: documentation link check failed")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("PASS: local Markdown links resolved.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

