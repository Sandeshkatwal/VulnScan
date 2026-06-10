# Safe Authenticated Parameter Replay Planner

Version 21.4 adds a Safe Authenticated Parameter Replay Planner for authorised manual validation planning.

Replay Plans convert discovered endpoints, parameter names, authenticated crawl metadata, OWASP A01/A05/A07 candidates, and role mapping context into Redacted Request Templates and Parameter Review Plans. They are documentation and workflow records only.

## What Is Not Automated

VulScan does not replay requests, mutate parameters, submit forms, send payloads, perform automatic authorization testing, perform automatic privilege changes, compare live accounts automatically, or access unauthorised data.

Use Authorised Test Accounts Only. Store Redacted Auth Context only. Do not store raw passwords, raw cookies, bearer tokens, Authorization header values, CSRF values, nonce values, or session tokens.

## Replay Plans

A Replay Plan records:

- affected endpoint and normalised URL
- parameter name, location, and type
- related OWASP categories
- role label and Expected Behaviour
- manual steps
- Redacted Request Template reference
- Observed Behaviour, evidence checklist, validation status, and Retest Workflow status

Supported replay intents include object ownership review, tenant boundary review, role permission review, reflection context review, auth session review, redirect callback review, export/download review, input validation review, and manual review.

## Redacted Request Templates

Redacted Request Templates retain method, URL template, header names, cookie names, query parameter names, path parameter placeholders, form field names, and JSON body schema only.

Values are replaced with `{ORIGINAL_VALUE_REDACTED}` and `{TEST_VALUE_APPROVED_MANUAL_ONLY}`. POST, PUT, PATCH, and DELETE templates are marked state-changing and blocked by default. Destructive endpoints are blocked by default.

## Evidence And Retest

The evidence checklist tracks authorisation scope, role label, parameter name, redaction, Expected Behaviour, Observed Behaviour, status code if safe, redacted response summary, secrets exclusion, third-party data exclusion, Retest Workflow status, and recommendation.

Observed Behaviour records store redacted summaries only. Evidence file paths must stay under `reports/parameter_replay/evidence`.

## Report-Ready Templates

Report templates use candidate wording unless Observed Behaviour is manually recorded as `unexpectedly_allowed` or `reflected_with_context_risk`. Issue wording is never inferred from a candidate alone.

## CLI Examples

```powershell
.\.venv311\Scripts\python.exe -m scanner.main replay-plans list --plans-file data\parameter_replay\sample_replay_plan.json
.\.venv311\Scripts\python.exe -m scanner.main replay-plans create --endpoint "http://127.0.0.1:8000/users/123?user_id=123" --parameter user_id --intent object_ownership_review --role standard_user --json --html
.\.venv311\Scripts\python.exe -m scanner.main replay-plans generate --parameters-file reports\latest_parameter_results.json --endpoints-file data\endpoints\sample_urls.txt --json --html
.\.venv311\Scripts\python.exe -m scanner.main replay-plans template --plan-id demo-replay-001 --plans-file data\parameter_replay\sample_replay_plan.json
.\.venv311\Scripts\python.exe -m scanner.main replay-plans observe --plan-id demo-replay-001 --observed-result denied_as_expected --status-code 403 --summary "Access denied for standard_user as expected" --json
.\.venv311\Scripts\python.exe -m scanner.main replay-plans report --plan-id demo-replay-001 --plans-file data\parameter_replay\sample_replay_plan.json --markdown
.\.venv311\Scripts\python.exe -m scanner.main replay-plans retest --plan-id demo-replay-001 --status passed --notes "Parameter access remains denied after remediation" --json
```

## API Examples

- `POST /replay-plans/create`
- `POST /replay-plans/generate`
- `GET /replay-plans/{plan_id}`
- `POST /replay-plans/observe`
- `POST /replay-plans/retest`
- `POST /replay-plans/report-template`

API key protection applies when configured. Endpoints do not make live requests and reject credential-like role fields.

## Dashboard Usage

Open the dashboard and select Authenticated Assessment, then Parameter Replay Planner. The view shows the safety notice, Replay Plan summary, table, Redacted Request Template, Expected vs Observed Behaviour, Evidence Checklist, Retest Workflow, and report template generation.

There is no send request, replay now, payload input, credential field, raw token display, or raw cookie display.

## Limitations And Future Work

Replay Plans are planning records and do not prove impact. Manual validation must stay within assessment scope and programme rules. Future work can add richer importers for authenticated crawl and role mapping exports while preserving the No Automatic Replay safety model.
