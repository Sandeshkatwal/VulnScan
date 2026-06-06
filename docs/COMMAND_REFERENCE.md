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

The option does not perform auth bypass automation, cross-account testing, credential attacks, privilege escalation attempts, or state-changing requests.
## Version 20.7 A03 Commands

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --a03-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --a03-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --vuln-intel --a03-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main sbom analyse --sbom-file data\sbom\sample_cyclonedx_sbom.json --a03-checks --owasp-assess --json --html
```

`--a03-checks` classifies available component/header/endpoint/SBOM/vulnerability-intelligence evidence. It does not perform dependency confusion testing, external registry fetching, malicious package testing, package takeover simulation, or exploit validation.
