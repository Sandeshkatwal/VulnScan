"""Collect local beta issue notes into a safe summary file."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "reports" / "beta_issues" / "beta_issue_summary.json"
SOURCES = [ROOT / "docs" / "beta", ROOT / "docs" / "issues"]


def collect_beta_issues() -> dict[str, object]:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    documents = []
    for source in SOURCES:
        if not source.exists():
            continue
        for path in sorted(source.rglob("*.md")):
            documents.append(str(path.relative_to(ROOT)))
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "release": "22.1.0-beta",
        "focus": "Beta Feedback and Resolved Issues",
        "documents_reviewed": documents,
        "issue_sources": ["local documentation", "GitHub issue templates"],
        "secrets_included": False,
    }
    OUTPUT.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    summary = collect_beta_issues()
    print(f"Collected {len(summary['documents_reviewed'])} beta documentation files.")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
