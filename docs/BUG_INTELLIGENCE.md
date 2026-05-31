# Bug Intelligence

This page is the professional terminology entry point for the authorised vulnerability discovery workflow.

The implementation keeps legacy command flags, API routes, JSON keys, and folders such as `--bug-bounty-scope`, `/bug-bounty/...`, and `data/bug_bounty/` for backward compatibility. User-facing documentation and dashboard navigation use Bug Intelligence, Program Scope, Recon Intelligence, Security Finding Reports, and Submission and Retest Tracking.

Version 18.6 adds local Submission and Retest Tracking for Security Finding Reports. It records workflow status, duplicate or accepted outcomes, payment notes, follow-up dates, evidence references, timeline events, and retest status. It does not submit reports externally and does not store platform credentials or API tokens.

Version 18.7 adds the Bug Intelligence Workflow dashboard. It connects Program Scope, Recon Intelligence, Endpoint Intelligence, OWASP Indicator Mapping, Safe Validation, Evidence Capture, Security Finding Reports, Submission, and Retest into one progress view.

The readiness score is workflow completeness only. It is not a severity rating, proof of exploitability, or a guarantee that a report is valid. The workflow supports responsible disclosure, bug bounty, and internal security testing without exploitation or automatic submission.

See [BUG_BOUNTY.md](BUG_BOUNTY.md) for the full workflow guide.
