# Resolved Issues 22.1

VulScan 22.1.0-beta is a Bug Fix Sprint and Regression Test Hardening release.

## Resolved Issues

- Added regression coverage for CLI edge cases, API Error Handling, report export safety, demo reliability, and security redaction.
- Added shared friendly error helpers for missing files, invalid JSON, unsafe paths, and user-facing CLI messages.
- Added safe API error helper responses for validation and generic API errors.
- Added sample data verification and report export verification scripts.
- Added dashboard resilience components for API errors, fallback states, retry actions, and build/regression status.
- Added local Beta Feedback issue collection and regression summary artifacts.

## Verification

Run:

```powershell
.\.venv311\Scripts\python.exe -m pytest tests\regression
.\.venv311\Scripts\python.exe scripts\verify_sample_data.py
.\.venv311\Scripts\python.exe scripts\check_report_exports.py
.\.venv311\Scripts\python.exe scripts\run_regression_suite.py
```

## Safety Notes

No exploit code, attack payloads, credential attacks, automatic auth bypass testing, or state-changing workflow execution were added. Safe Regression Testing uses local sample data and simulated demo data only.
