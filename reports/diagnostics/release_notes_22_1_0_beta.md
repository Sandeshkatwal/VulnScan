# VulScan 22.1.0-beta

Release channel: public-beta
Build status: bug-fix-sprint

## Summary

VulScan 22.1.0-beta is a Bug Fix Sprint and Regression Test Hardening release for authorised local testing, OWASP-focused assessment planning, evidence management, reporting, and portfolio demonstration workflows.

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
