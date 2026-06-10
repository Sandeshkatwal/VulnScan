# Business Logic Review Workflow Assistant

Version 21.5 adds a Business Logic Review Workflow Assistant for manual workflow review and documentation only.

Manual Validation Required. Authorised Test Data Only. No Automatic Workflow Execution.

The assistant identifies workflow candidates from existing endpoints, parameters, authenticated crawl results, role mapping data, Replay Plans, and OWASP evidence. It creates Workflow Review Plans, State Transition Review maps, Abuse Case Checklists, Expected Behaviour and Observed Behaviour records, Retest Workflow records, and report-ready templates.

VulScan does not execute checkout, payment, approval, coupon, rate-limit, account lifecycle, import/export, webhook, or other state-changing workflows automatically. It does not trigger payments, refunds, transfers, subscriptions, purchases, real approvals, or real rejections.

Workflow candidates include checkout/payment, refund/transfer, approval/rejection, account lifecycle, password reset, subscription plans, coupon/discount, quota/rate/limit, import/export, file upload processing, role/permission changes, multi-step processes, notification/webhook, and custom workflows.

State Transition Review maps document from-state, to-state, action, allowed roles, disallowed roles, endpoint, expected control, manual validation status, and notes.

Abuse Case Checklists cover skipped workflow steps, repeated one-time actions, client-controlled price or discount fields, lower-role actions, tenant/user boundary review, stale links or tokens, callbacks/events, import/export boundaries, server-side controls, and audit logging.

Observation records store redacted summaries only. Evidence paths must stay under `reports/business_logic/evidence`.

Report templates use candidate wording unless manual Observed Behaviour is recorded as `unexpected_success` or `control_missing`.

## CLI Examples

```powershell
.\.venv311\Scripts\python.exe -m scanner.main business-logic list --plans-file data\business_logic\sample_workflow_plan.json
.\.venv311\Scripts\python.exe -m scanner.main business-logic detect --endpoints-file data\endpoints\sample_urls.txt --json --html
.\.venv311\Scripts\python.exe -m scanner.main business-logic create --workflow checkout_payment --endpoint "http://127.0.0.1:8000/checkout" --role standard_user --json --html
.\.venv311\Scripts\python.exe -m scanner.main business-logic generate --endpoints-file data\endpoints\sample_urls.txt --roles-file data\roles\sample_roles.json --json --html
.\.venv311\Scripts\python.exe -m scanner.main business-logic state-map --workflow approval_rejection --json
.\.venv311\Scripts\python.exe -m scanner.main business-logic checklist --workflow checkout_payment --json
.\.venv311\Scripts\python.exe -m scanner.main business-logic observe --plan-id demo-workflow-001 --observed-result behaved_as_expected --summary "Workflow behaved as expected using approved test data" --json
.\.venv311\Scripts\python.exe -m scanner.main business-logic report --plan-id demo-workflow-001 --plans-file data\business_logic\sample_workflow_plan.json --markdown
.\.venv311\Scripts\python.exe -m scanner.main business-logic retest --plan-id demo-workflow-001 --status passed --notes "Workflow control still enforced after remediation" --json
```

## API Examples

- `POST /business-logic/detect`
- `POST /business-logic/create`
- `POST /business-logic/generate`
- `POST /business-logic/state-map`
- `POST /business-logic/checklist`
- `POST /business-logic/observe`
- `POST /business-logic/retest`
- `POST /business-logic/report-template`

API key protection applies when configured. Endpoints do not make live requests and reject credential-like role fields.

## Dashboard Usage

Open the dashboard and select Business Logic Review. There is no run workflow, test payment, approve now, credential, token, or cookie display control.

## Limitations And Future Work

Business Logic Review plans document manual review scope and do not prove impact. Future work can add richer imports from authenticated crawl and role mapping exports while preserving the No Automatic Workflow Execution model.

## Evidence Vault Integration

Version 21.6 Evidence Vault can link Business Logic Review observations and Workflow Review Plans to Redacted Evidence, Evidence Quality Score, Evidence Timeline, and Export Safety Check records.
