"""Generate VulScan 22.0.0-beta release notes."""

from __future__ import annotations

import sys
from pathlib import Path

from scanner.version import BUILD_STATUS, RELEASE_CHANNEL, VERSION


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "reports" / "diagnostics" / "release_notes_22_0_0_beta.md"


def build_release_notes() -> str:
    return f"""# VulScan {VERSION}

Release channel: {RELEASE_CHANNEL}
Build status: {BUILD_STATUS}

## Summary

VulScan 22.0.0-beta is a Public Beta Stabilisation and Issue Cleanup release for authorised local testing, OWASP-focused assessment planning, evidence management, reporting, and portfolio demonstration workflows.

## Stabilisation Changes

- Added version metadata, health checks, safe diagnostics, command verification, dependency review, and public beta readiness checks.
- Added Public Beta notes, Known Limitations, Verification Matrix, Beta Testing Guide, issue templates, and pull request checklist.
- Improved dashboard beta status, API connection feedback, diagnostics display, and known limitation visibility.

## Verification Commands

- `python -m pytest`
- `python -m scanner.main version`
- `python -m scanner.main health`
- `python -m scanner.main diagnostics --json`
- `python scripts/check_no_secrets.py`
- `python scripts/check_demo_safety.py`
- `python scripts/verify_release.py`
- `python scripts/public_beta_check.py`
- `cd dashboard && npm run build`

## Known Limitations

See `docs/beta/KNOWN_LIMITATIONS.md`. Findings are indicators or candidates unless manually validated. VulScan is not a replacement for professional manual penetration testing.

## Safety Statement

VulScan is for authorised testing only. Public Beta workflows avoid exploit code, credential attacks, automatic auth bypass testing, and destructive state-changing workflow execution.

## Next Roadmap

- Continue Regression Testing from beta feedback.
- Improve documentation and issue triage.
- Expand safe local labs and optional integrations only after beta reliability work is complete.
"""


def main() -> int:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(build_release_notes(), encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
