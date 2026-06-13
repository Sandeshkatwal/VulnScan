# Regression Testing

Version 22.1.0-beta adds focused Regression Test Hardening for Public Beta Stability and Reliability.

## Test Areas

- CLI regressions: missing files, invalid JSON, unsafe paths, command availability, and friendly errors.
- API regressions: structured errors, missing resources, unsafe downloads, redaction, health, and version stability.
- Report regressions: Markdown, HTML, JSON, candidate wording, and unsafe evidence export blocking.
- Demo regressions: simulated data only, safe statements, and API-independent dataset loading.
- Security regressions: redaction, path traversal blocking, `.gitignore` safety, and auth profile secret handling.

## Commands

```powershell
.\.venv311\Scripts\python.exe -m pytest tests\regression
.\.venv311\Scripts\python.exe scripts\run_regression_suite.py
.\.venv311\Scripts\python.exe scripts\verify_sample_data.py
.\.venv311\Scripts\python.exe scripts\check_report_exports.py
```
