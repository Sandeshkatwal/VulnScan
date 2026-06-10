# Evidence Vault

Version 21.6 adds an Evidence Vault with Redaction Quality Controls for safe evidence documentation and Report Evidence Linking.

The Evidence Vault stores Redacted Evidence summaries only. It must not store raw passwords, session cookies, bearer tokens, API keys, private keys, full sensitive response bodies, or other authentication material.

## Evidence Item Model

An Evidence Item records an evidence ID, title, evidence type, source module, related target, related URL or host, OWASP categories, linked findings, linked test plans, linked Replay Plans, linked Business Logic Review plans, submissions, severity context, confidence, evidence strength, redaction status, Secret Detection status, Evidence Quality Score, safe summaries, attachment metadata, timeline events, notes, and limitations.

## Redaction Model

Secret Detection checks text for Authorization bearer headers, Basic auth, Cookie and Set-Cookie headers, session IDs, CSRF tokens, API keys, access tokens, refresh tokens, ID tokens, JWT-like strings, AWS access keys, private key blocks, password fields, secret fields, long random strings, and credential-like pairs.

Redaction replaces sensitive values with markers such as `[REDACTED-BEARER]`, `[REDACTED-BASIC]`, `[REDACTED-COOKIE]`, `[REDACTED-SESSION]`, `[REDACTED-CSRF]`, `[REDACTED-API-KEY]`, `[REDACTED-TOKEN]`, `[REDACTED-JWT]`, `[REDACTED-PRIVATE-KEY]`, `[REDACTED-PASSWORD]`, and `[REDACTED-SECRET]`.

## Evidence Quality Score

Evidence Quality Score is evidence quality, not vulnerability severity. Labels are Excellent Evidence, Good Evidence, Needs Improvement, Weak Evidence, and Blocked.

## Evidence Timeline

Each Evidence Item can include a Chain-of-Custody Style Timeline with created, redacted, reviewed, linked, exported, export blocked, retest added, note added, and archived events. VulScan does not present this as a formal legal custody assertion.

## Linking And Export

Evidence can link to findings, OWASP categories, Access Control Manual Test Planner records, Replay Plans, Business Logic Review plans, reports, submissions, and retests. Export Safety Check blocks export when redaction failed, Secret Detection failed, safe summary is missing, or secret-like patterns remain.

Exports are written to `reports/evidence_vault/exports` as JSON or Markdown and include Redacted Evidence only.

## Attachment Metadata

Version 21.6 supports attachment metadata only. It does not accept arbitrary file paths, does not copy screenshots from authenticated pages, and does not read binary images for Secret Detection.

## CLI Examples

```powershell
.\.venv311\Scripts\python.exe -m scanner.main evidence list
.\.venv311\Scripts\python.exe -m scanner.main evidence show --evidence-id demo-evidence-001
.\.venv311\Scripts\python.exe -m scanner.main evidence add --title "Manual A01 observation" --type manual_observation --summary "Access denied for standard_user as expected" --owasp A01:2025 --json
.\.venv311\Scripts\python.exe -m scanner.main evidence redact-check --text "Authorization: Bearer secret-demo-token"
.\.venv311\Scripts\python.exe -m scanner.main evidence quality --evidence-id demo-evidence-001
.\.venv311\Scripts\python.exe -m scanner.main evidence timeline --evidence-id demo-evidence-001
.\.venv311\Scripts\python.exe -m scanner.main evidence link --evidence-id demo-evidence-001 --finding-id finding-001
.\.venv311\Scripts\python.exe -m scanner.main evidence export --evidence-id demo-evidence-001 --markdown --json
```

## API Examples

- `GET /evidence`
- `GET /evidence/{evidence_id}`
- `POST /evidence`
- `POST /evidence/redact-check`
- `POST /evidence/{evidence_id}/quality`
- `GET /evidence/{evidence_id}/timeline`
- `POST /evidence/{evidence_id}/link`
- `POST /evidence/export`

API key protection applies when configured. API responses return Redacted Evidence only.

## Dashboard Usage

Open Evidence Vault in the dashboard to review evidence summary cards, Evidence Item table, safe detail, Redaction Check panel, Evidence Quality panel, Evidence Timeline, Evidence Linking, and Export Safety panel.

## Limitations And Future Work

Evidence Vault records improve report readiness and redaction confidence but do not prove impact. Future work can add reviewed attachment ingestion, safer screenshot reference workflows, richer report-link backfills, and encrypted local storage.
