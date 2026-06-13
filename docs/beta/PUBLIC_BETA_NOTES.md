# VulScan 22.0.0-beta

## Version 22.2.0-beta

Version 22.2.0-beta focuses on Performance Review and Large Dataset Handling. It adds shared Pagination helpers, Response Size Control for large list endpoints, Large Demo Dataset scripts, Performance Baseline output, diagnostics performance metadata, and dashboard components for Lazy Loading and paginated rendering.

## Summary

VulScan 22.0.0-beta is a Public Beta Stabilisation and Issue Cleanup release for authorised security assessment, OWASP-focused assessment planning, evidence management, reporting, and portfolio demonstration workflows.

## Main Capabilities

- Discovery Engine, Passive Web DAST, Vulnerability Intelligence, and Prioritisation.
- OWASP assessment modules and report/dashboard workflows.
- Authenticated assessment planning with boundary controls and manual validation records.
- Evidence Vault, redaction checks, Professional Finding Builder, and Report Composer.
- Portfolio Demo Mode with simulated redacted data only.

## What Changed in 22.0

- Added version metadata, health checks, safe diagnostics, and Public Beta readiness checks.
- Added command verification, dependency review, no-secrets scanning, and release note generation.
- Added Known Limitations, Verification Matrix, Beta Testing Guide, issue triage guidance, issue templates, and a pull request checklist.
- Improved dashboard beta status, API connection feedback, diagnostics visibility, and known limitations messaging.

## Safety Model

VulScan is for authorised testing only. Public Beta workflows avoid exploit code, credential attacks, automatic auth bypass testing, and destructive state-changing workflow execution. Many findings are indicators or candidates and require manual validation.

## Known Limitations

See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

## Verification Commands

```powershell
.\.venv311\Scripts\python.exe -m pytest
.\.venv311\Scripts\python.exe -m scanner.main version
.\.venv311\Scripts\python.exe -m scanner.main health
.\.venv311\Scripts\python.exe -m scanner.main diagnostics --json
.\.venv311\Scripts\python.exe scripts\check_no_secrets.py
.\.venv311\Scripts\python.exe scripts\check_demo_safety.py
.\.venv311\Scripts\python.exe scripts\verify_release.py
.\.venv311\Scripts\python.exe scripts\public_beta_check.py
cd dashboard
npm run build
```

## GitHub Demo Workflow

Use issue templates to report bugs, documentation problems, or safe feature requests. Do not include secrets, real tokens, cookies, passwords, private keys, or private customer data in issues, screenshots, logs, reports, or demo material.

## Roadmap After Beta

- Continue Regression Testing and Issue Cleanup from Public Beta feedback.
- Improve documentation clarity and command coverage.
- Expand safe local examples and optional integrations after reliability work is complete.

## 22.1 Bug Fix Sprint

Version 22.1.0-beta focuses on Bug Fix Sprint work, Regression Test Hardening, Stability, Reliability, Edge Case Handling, API Error Handling, Dashboard Resilience, Resolved Issues, Beta Feedback, and Safe Regression Testing.
