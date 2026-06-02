# Bug Intelligence

This page is the professional terminology entry point for the authorised vulnerability discovery workflow.

For the release-ready portfolio flow, see [BUG_INTELLIGENCE_WORKFLOW.md](BUG_INTELLIGENCE_WORKFLOW.md), [COMMAND_REFERENCE.md](COMMAND_REFERENCE.md), and [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md).

The implementation keeps legacy command flags, API routes, JSON keys, and folders such as `--bug-bounty-scope`, `/bug-bounty/...`, and `data/bug_bounty/` for backward compatibility. User-facing documentation and dashboard navigation use Bug Intelligence, Program Scope, Recon Intelligence, Security Finding Reports, and Submission and Retest Tracking.

Version 19.0 hardens the Bug Intelligence chapter for release. Prefer `scope list`, `scope check`, `--scope-file`, `data/programs/`, `data/recon/`, `data/endpoints/`, and `data/validation/`. Legacy `bug-bounty` command flags, routes, JSON keys, and directories remain compatibility aliases and may be removed later.

Version 18.6 adds local Submission and Retest Tracking for Security Finding Reports. It records workflow status, duplicate or accepted outcomes, payment notes, follow-up dates, evidence references, timeline events, and retest status. It does not submit reports externally and does not store platform credentials or API tokens.

Version 18.7 adds the Bug Intelligence Workflow dashboard. It connects Program Scope, Recon Intelligence, Endpoint Intelligence, OWASP Indicator Mapping, Safe Validation, Evidence Capture, Security Finding Reports, Submission, and Retest into one progress view.

Version 18.8 adds Finding Fingerprinting and Duplicate Detection. It creates stable metadata-only fingerprints and local duplicate indicators across findings, candidates, evidence, reports, submissions, and retests. Parameter values and secrets are not used.

Version 18.9 adds local Personal Performance Metrics for progress, quality, duplicates, acceptance rate, reporting productivity, retest outcomes, bounty totals, Program Performance, vulnerability classes, monthly activity, and outcome distribution. Metrics are calculated from local VulScan data only and do not access external platforms, browser sessions, credentials, cookies, API keys, or tokens.

The readiness score is workflow completeness only. It is not a severity rating, proof of exploitability, or a guarantee that a report is valid. The workflow supports responsible disclosure, bug bounty, and internal security testing without exploitation or automatic submission.

See [BUG_INTELLIGENCE_METRICS.md](BUG_INTELLIGENCE_METRICS.md) for metrics formulas, CLI examples, API examples, dashboard usage, and privacy notes.

See [BUG_INTELLIGENCE_WORKFLOW.md](BUG_INTELLIGENCE_WORKFLOW.md) and [COMMAND_REFERENCE.md](COMMAND_REFERENCE.md) for the release-hardened workflow and command set.

See [BUG_BOUNTY.md](BUG_BOUNTY.md) for the full workflow guide.
