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
