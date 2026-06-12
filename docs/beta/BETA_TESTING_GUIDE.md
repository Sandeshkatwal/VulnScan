# Beta Testing Guide

## Setup Environment

Use Windows 11, Python 3.11, and the dashboard Node/npm versions already configured in the project. Install Python dependencies into `.venv311` and dashboard dependencies with `npm ci`.

## Run Backend Tests

```powershell
.\.venv311\Scripts\python.exe -m pytest
```

## Run Dashboard Build

```powershell
cd dashboard
npm run build
```

## Run Demo Mode

```powershell
.\.venv311\Scripts\python.exe -m scanner.main demo status
.\.venv311\Scripts\python.exe -m scanner.main demo generate --json
.\.venv311\Scripts\python.exe -m scanner.main demo report --markdown --html --json
.\.venv311\Scripts\python.exe -m scanner.main demo walkthrough
```

## Run Evidence Redaction Check

```powershell
.\.venv311\Scripts\python.exe -m scanner.main evidence redact-check --text "Authorization: Bearer secret-demo-token"
```

## Compose Demo Report

```powershell
.\.venv311\Scripts\python.exe -m scanner.main reports compose --title "VulScan OWASP Assessment Report" --target http://127.0.0.1:8000 --findings-file data\findings\sample_finding.json --markdown --html --json
```

## Check Dashboard Pages

Start the API and dashboard locally, then check Dashboard Home, Portfolio Demo Mode, Evidence Vault, Report Composer, OWASP Report, Settings, and About. Confirm loading, empty, offline, and demo mode states remain readable.

## Record Issues

Use the GitHub issue templates. Include commands, expected behaviour, actual behaviour, and safe redacted logs or screenshots only.

## What Not To Test

Do not test against systems without permission. Do not include real secrets. Do not perform credential attacks, automatic auth bypass testing, brute force, exploit attempts, or destructive state-changing workflow execution.

## Safe Local Testing Reminder

Prefer localhost-only testing and simulated demo data during Public Beta verification.
