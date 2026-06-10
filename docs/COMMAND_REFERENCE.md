# Command Reference

These commands use the preferred Bug Intelligence terminology. Legacy aliases remain available for compatibility.

## Backend

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1
```

## API

```powershell
.\.venv311\Scripts\python.exe -m scanner.main api
```

## Dashboard

```powershell
cd dashboard
npm run dev
```

## Program Scope

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scope list
.\.venv311\Scripts\python.exe -m scanner.main scope check --target 127.0.0.1 --scope-file data\programs\sample_program_scope.json
```

Legacy aliases:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main program-scope
.\.venv311\Scripts\python.exe -m scanner.main scope check --target 127.0.0.1 --bug-bounty-scope data\bug_bounty\sample_program_scope.json
```

Alias retained for compatibility. Prefer the new Bug Intelligence terminology.

## Recon Intelligence

```powershell
.\.venv311\Scripts\python.exe -m scanner.main recon --targets-file data\recon\sample_targets.txt --scope-file data\programs\sample_program_scope.json --enforce-scope
```

Legacy `--bug-bounty-scope` remains supported.

## Endpoint and Parameter Intelligence

```powershell
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --scope-file data\programs\sample_program_scope.json --enforce-scope
```

## Safe Validation

```powershell
.\.venv311\Scripts\python.exe -m scanner.main validate --targets-file data\validation\sample_validation_targets.json --scope-file data\programs\sample_program_scope.json --enforce-scope
```

## A08 Software/Data Integrity

```powershell
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --a08-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --a08-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main validate --targets-file data\validation\sample_validation_targets.json --a08-checks --owasp-assess --json --html
```

A08 checks are passive integrity indicators only. No uploads, form submissions, webhook triggers, update calls, or bypass tests are performed.

## Evidence Capture

```powershell
.\.venv311\Scripts\python.exe -m scanner.main evidence list
```

## Security Finding Reports

```powershell
.\.venv311\Scripts\python.exe -m scanner.main security-report list
```

Legacy alias:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main bug-report list
```

## Submission and Retest Tracker

```powershell
.\.venv311\Scripts\python.exe -m scanner.main submission list
.\.venv311\Scripts\python.exe -m scanner.main retest list
```

## Duplicate Detection

```powershell
.\.venv311\Scripts\python.exe -m scanner.main duplicates groups
```

## Performance Metrics

```powershell
.\.venv311\Scripts\python.exe -m scanner.main metrics summary
.\.venv311\Scripts\python.exe -m scanner.main metrics summary --range last-30-days
.\.venv311\Scripts\python.exe -m scanner.main metrics programs
.\.venv311\Scripts\python.exe -m scanner.main metrics classes
.\.venv311\Scripts\python.exe -m scanner.main metrics export --format json
```

## API and Dashboard

```powershell
.\.venv311\Scripts\python.exe -m scanner.main api
cd dashboard
npm run dev
```

The API binds to localhost by default. Do not expose it remotely unless you explicitly understand and accept the risk for an authorised local-network environment.
## OWASP Assessment Engine

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --vuln-intel --prioritise --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main validate --targets-file data\validation\sample_validation_targets.json --owasp-assess --json --html
```

`--owasp-assess` builds report-ready OWASP Evidence, Category Results, Coverage, and Manual Validation Required sections from existing evidence only.

## A04 Cryptographic Failures

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --a04-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --a04-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main validate --targets-file data\validation\sample_validation_targets.json --a04-checks --owasp-assess --json --html
```

`--a04-checks` adds safe A04 Cryptographic Failures evidence for transport security indicators, HSTS, cookie security evidence, sensitive data over cleartext indicators, mixed content indicators, and TLS metadata.

## A07 Authentication Failures

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --a07-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --a07-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main validate --targets-file data\validation\sample_validation_targets.json --a07-checks --owasp-assess --json --html
```

`--a07-checks` adds safe A07 Authentication Failures evidence for authentication indicators, session management indicators, login workflow evidence, password reset workflow evidence, cookie/session evidence, rate-limit header indicators, and manual validation needs.

## A10 Mishandling of Exceptional Conditions

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --a10-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --a10-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main validate --targets-file data\validation\sample_validation_targets.json --a10-checks --owasp-assess --json --html
```

`--a10-checks` adds safe A10 Mishandling of Exceptional Conditions evidence for error-handling indicators, exception exposure evidence, verbose error evidence, framework debug indicators, status code patterns, sensitive error content, and fail-safe review required notes. It does not force errors or send payloads.
## A05 Injection

```powershell
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --a05-checks --owasp-assess --json --html
```

```powershell
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --a05-checks --safe-reflection --max-reflection-checks 10 --owasp-assess --json --html
```

`--safe-reflection` uses harmless GET markers only. A05 output is candidate/indicator-based and requires manual validation.
## A01 Broken Access Control

`--a01-checks` enables safe candidate discovery and manual validation planning for A01 Broken Access Control. It is available for `endpoints`, `web-scan`, and `validate`.

The option does not perform automatic role comparison, account-to-account requests, credential attack workflows, elevated-access action workflows, or state-changing requests.
## Version 20.7 A03 Commands

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --a03-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --a03-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --vuln-intel --a03-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main sbom analyse --sbom-file data\sbom\sample_cyclonedx_sbom.json --a03-checks --owasp-assess --json --html
```

`--a03-checks` classifies available component/header/endpoint/SBOM/vulnerability-intelligence evidence. It does not perform dependency confusion testing, external registry fetching, malicious package testing, package takeover simulation, or exploit validation.
# Version 20.9 OWASP Assessment Report

Generate the unified OWASP Assessment Markdown report with `--owasp-report` after `--owasp-assess`:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --a01-checks --a02-checks --a03-checks --a04-checks --a05-checks --a07-checks --a08-checks --a10-checks --owasp-assess --owasp-report --json --html
```

# Version 21.0 Authenticated Web Assessment Foundation

```powershell
.\.venv311\Scripts\python.exe -m scanner.main auth profiles
.\.venv311\Scripts\python.exe -m scanner.main auth show --profile-file data\auth_profiles\sample_session_profile.redacted.json
.\.venv311\Scripts\python.exe -m scanner.main auth validate --profile-file data\auth_profiles\sample_session_profile.redacted.json
.\.venv311\Scripts\python.exe -m scanner.main auth check-url --profile-file data\auth_profiles\sample_session_profile.redacted.json --url http://127.0.0.1:8000/dashboard
```

## Authenticated Crawl

```powershell
.\.venv311\Scripts\python.exe -m scanner.main authenticated-crawl --url http://127.0.0.1:8000/dashboard --auth-profile data\auth_profiles\sample_session_profile.redacted.json --max-pages 30 --max-depth 2 --request-delay 1.0 --json --html

.\.venv311\Scripts\python.exe -m scanner.main authenticated-crawl --url http://127.0.0.1:8000/dashboard --auth-profile data\auth_profiles\sample_session_profile.redacted.json --dry-run --json --html
```

Authenticated Crawl is GET-only, enforces Session Boundary Controls, blocks destructive-looking paths, records Session Expiry Indicators, and stores Redacted Authenticated Evidence only.

## Version 21.2 Role Commands

```powershell
.\.venv311\Scripts\python.exe -m scanner.main roles list --roles-file data\roles\sample_roles.json
.\.venv311\Scripts\python.exe -m scanner.main roles show --roles-file data\roles\sample_roles.json --role standard_user
.\.venv311\Scripts\python.exe -m scanner.main roles matrix --matrix-file data\roles\sample_permission_matrix.json
.\.venv311\Scripts\python.exe -m scanner.main roles map-endpoints --roles-file data\roles\sample_roles.json --matrix-file data\roles\sample_permission_matrix.json --endpoints-file data\endpoints\sample_urls.txt --json --html
.\.venv311\Scripts\python.exe -m scanner.main roles plan --role standard_user --endpoint "http://127.0.0.1:8000/admin/users" --expected denied
```

Role commands perform Role and Permission Mapping, Access-Control Matrix summaries, endpoint action inference, and Manual Validation Required planning only. They do not perform live requests or automatic permission testing.
## Version 21.3 Access Test Commands

```powershell
.\.venv311\Scripts\python.exe -m scanner.main access-tests list --plans-file data\access_control_tests\sample_a01_test_plan.json
.\.venv311\Scripts\python.exe -m scanner.main access-tests create --role standard_user --endpoint "http://127.0.0.1:8000/admin/users" --expected denied --test-type vertical_access_control_review --json --html
.\.venv311\Scripts\python.exe -m scanner.main access-tests show --plan-id demo-plan-001 --plans-file data\access_control_tests\sample_a01_test_plan.json
.\.venv311\Scripts\python.exe -m scanner.main access-tests observe --plan-id demo-plan-001 --observed-result denied_as_expected --status-code 403 --summary "Access denied for standard_user as expected" --json
.\.venv311\Scripts\python.exe -m scanner.main access-tests report --plan-id demo-plan-001 --plans-file data\access_control_tests\sample_a01_test_plan.json --markdown
.\.venv311\Scripts\python.exe -m scanner.main access-tests retest --plan-id demo-plan-001 --status passed --notes "Access remains denied after remediation" --json
```

## Safe Authenticated Parameter Replay Planner

```powershell
.\.venv311\Scripts\python.exe -m scanner.main replay-plans list --plans-file data\parameter_replay\sample_replay_plan.json
.\.venv311\Scripts\python.exe -m scanner.main replay-plans create --endpoint "http://127.0.0.1:8000/users/123?user_id=123" --parameter user_id --intent object_ownership_review --role standard_user --json --html
.\.venv311\Scripts\python.exe -m scanner.main replay-plans generate --parameters-file reports\latest_parameter_results.json --endpoints-file data\endpoints\sample_urls.txt --json --html
.\.venv311\Scripts\python.exe -m scanner.main replay-plans template --plan-id demo-replay-001 --plans-file data\parameter_replay\sample_replay_plan.json
.\.venv311\Scripts\python.exe -m scanner.main replay-plans observe --plan-id demo-replay-001 --observed-result denied_as_expected --status-code 403 --summary "Access denied for standard_user as expected" --json
.\.venv311\Scripts\python.exe -m scanner.main replay-plans report --plan-id demo-replay-001 --plans-file data\parameter_replay\sample_replay_plan.json --markdown
.\.venv311\Scripts\python.exe -m scanner.main replay-plans retest --plan-id demo-replay-001 --status passed --notes "Parameter access remains denied after remediation" --json
```

## Business Logic Review

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

Access test commands create, update, and read local Access Control Manual Test Planner records only.

## Evidence Vault

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
