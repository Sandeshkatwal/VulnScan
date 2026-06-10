# Duplicate Detection and Finding Fingerprinting

Version 18.8 adds metadata-only Finding Fingerprinting and Duplicate Detection for the Bug Intelligence workflow.

Version 18.9 includes duplicate counts and duplicate rates in local Bug Intelligence Metrics and Program Performance. These are local workflow indicators only and do not predict how an external platform will classify a submission.

The feature helps identify repeat findings across endpoint candidates, parameter candidates, evidence records, Security Finding Reports, submissions, and retests. It does not submit to external platforms and does not decide whether a third-party platform will mark a report as duplicate.

## Fingerprint Fields

Fingerprints use stable metadata only:

- normalised target, host, and path
- sorted parameter names
- issue type
- OWASP indicator category when available
- source, CVE, service, port, and method when available

Fingerprints do not include timestamps, report IDs, random IDs, response bodies, volatile evidence snippets, parameter values, or secrets.

## Normalisation

- Query parameter values are removed.
- Query parameter names are sorted.
- Numeric path identifiers become `{id}`.
- UUID-looking path segments become `{uuid}`.
- Issue type names are normalised, for example `idor_candidate` becomes `idor`.

## Duplicate Status

- `exact_duplicate`: same fingerprint hash.
- `likely_duplicate`: same host, normalised path, issue type, and overlapping parameter names.
- `related`: same host and issue type with related source or OWASP category.
- `unique`: no matching local fingerprint was found.

All statuses are local indicators. Manual review is required.

## CLI

```powershell
.\.venv311\Scripts\python.exe -m scanner.main duplicates fingerprint --url "http://127.0.0.1:8000/account?id=123" --issue-type idor_candidate --parameter id
.\.venv311\Scripts\python.exe -m scanner.main duplicates check --url "http://127.0.0.1:8000/account?id=456" --issue-type idor_candidate --parameter id
.\.venv311\Scripts\python.exe -m scanner.main duplicates groups
```

## API

- `POST /duplicates/fingerprint`
- `POST /duplicates/check`
- `GET /duplicates/groups`
- `GET /duplicates/groups/{group_id}`
- `GET /duplicates/fingerprints/{fingerprint_id}`

API key protection applies when configured. Requests accept parameter names only, not parameter values or platform credentials.

## Dashboard

The Duplicate Detection view under Bug Intelligence provides summary cards, a fingerprint checker, duplicate result panel, duplicate groups, and group detail. It is tracking and review support only.

## Safety Notes

VulScan does not perform exploitation, payload generation, external platform submission, or secret retention for duplicate detection. This workflow supports authorised security testing, responsible disclosure, internal testing, and bug bounty workflows.
