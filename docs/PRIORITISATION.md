# VulScan Prioritisation

Version 14.7 adds local asset criticality to the prioritisation engine.

Version 14.8 adds fix-first dashboard reporting for prioritised findings.

Prioritisation uses existing local scan evidence plus local business context. It does not perform exploitation, live attack checks, brute forcing, credential attacks, destructive payloads, or live CVE, EPSS, or exploit-data fetching.

## Asset Criticality

Allowed values:

- `critical`
- `high`
- `medium`
- `low`
- `unknown`

Asset criticality can be provided directly:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target production-web --prioritise --use-asset-criticality --asset-criticality critical
```

Or loaded from a local JSON file:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --prioritise --use-asset-criticality --asset-criticality-file data\asset_context\sample_asset_criticality.json
```

Direct CLI criticality overrides file mapping for the current target. Missing files, invalid JSON, malformed entries, duplicate entries, and invalid criticality values produce friendly warnings and continue with `unknown` where needed.

## JSON Format

The sample file is `data\asset_context\sample_asset_criticality.json`. Each entry can include:

- `asset`
- `criticality`
- `business_owner`
- `environment`
- `tags`
- `notes`
- optional `aliases`

Do not store secrets in asset context files.

## Scoring

Asset criticality adjusts prioritisation score:

- `critical`: add 20
- `high`: add 12
- `medium`: add 6
- `low`: add 0
- `unknown`: add 0

Pure informational findings are capped at `Monitor` unless other strong local signals justify a higher priority. Asset criticality alone must not turn an informational finding into `Fix First`.

## Outputs

Reports include:

- top-level `asset_context`
- `prioritisation_summary`
- `prioritised_findings`
- asset criticality, environment, business owner, and tags on prioritised findings

Asset criticality is business context, not proof of a vulnerability or exploitability. Review and maintain the context regularly.

## Fix-First Dashboard

Version 14.8 generates a dashboard when `--prioritise` is used. `--fix-first-dashboard` can also be supplied explicitly and enables prioritisation automatically if needed.

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --prioritise --fix-first-dashboard
```

The dashboard is reporting-only. It uses existing `prioritised_findings` and does not run new scans, live vulnerability checks, exploitation checks, brute forcing, credential attacks, or internet data fetching.

Dashboard outputs include:

- `fix_first_dashboard`
- `priority_distribution`
- `top_fix_first_findings`
- `remediation_action_plan`
- `executive_summary`

The remediation action plan groups findings into immediate, planned, monitoring, and informational actions. SLA hints are generic examples and should be customised to local remediation policy, asset criticality, exposure, and change windows. Human validation is still required before remediation decisions.
