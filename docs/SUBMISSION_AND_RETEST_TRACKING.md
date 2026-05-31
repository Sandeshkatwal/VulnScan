# Submission and Retest Tracking

VulScan provides local workflow tracking for Security Finding Reports. It does not submit reports to external platforms, does not integrate platform API tokens, and does not store platform credentials.

## What It Tracks

- submission status from draft through closed
- duplicate, informative, accepted, resolved, and paid outcomes
- submitted and accepted severity
- bounty/payment notes by currency
- next follow-up date
- evidence and report references
- timeline events
- retest status and retest result

## Safety Model

Submission and retest tracking is workflow/status tracking only. Retests are manual by default and can link to existing evidence or Safe Validation output that the user explicitly runs. VulScan does not modify targets, submit forms, or contact external submission platforms.

Notes are redacted before storage. Do not enter platform passwords, API keys, session cookies, tokens, private keys, or other secrets.

## CLI

```powershell
.\.venv311\Scripts\python.exe -m scanner.main submission create --report-id REPORT_ID --program-name "Demo Program" --platform "manual" --status draft
.\.venv311\Scripts\python.exe -m scanner.main submission list
.\.venv311\Scripts\python.exe -m scanner.main submission update-status --submission-id SUBMISSION_ID --status submitted --note "Submitted through platform."
.\.venv311\Scripts\python.exe -m scanner.main retest create --submission-id SUBMISSION_ID --status retest_required --note "Retest requested."
.\.venv311\Scripts\python.exe -m scanner.main retest update --retest-id RETEST_ID --status retest_passed --result issue_no_longer_reproducible --note "Manual retest passed."
```

## API

- `GET /submissions`
- `POST /submissions`
- `GET /submissions/{submission_id}`
- `PUT /submissions/{submission_id}`
- `POST /submissions/{submission_id}/status`
- `POST /submissions/{submission_id}/notes`
- `GET /submissions/{submission_id}/timeline`
- `GET /submissions/summary`
- `GET /retests`
- `POST /retests`
- `GET /retests/{retest_id}`
- `PUT /retests/{retest_id}`

API key protection applies when configured.

## Dashboard

Open **Bug Intelligence -> Submission Tracker** to review summary cards, create a tracking record, update status, inspect timeline events, and manage retest checklist state.

This workflow can support bug bounty, responsible disclosure, and internal vulnerability management.
