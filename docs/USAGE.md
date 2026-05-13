# VulScan Usage

VulScan is for authorised defensive vulnerability assessment only.

## TCP Port Scan

From the project root in PowerShell, activate the virtual environment first:

```powershell
.\.venv311\Scripts\Activate.ps1
```

Then run:

```powershell
python -m scanner.main scan --target 127.0.0.1
```

Or use the included helper script:

```powershell
.\run_scan.ps1
```

The Version 10 scanner performs TCP connect checks against a fixed default list of common ports and identifies likely services from a safe static port mapping:

```text
21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443
```

Only open ports are shown by default. Each open result includes the host, resolved IP address, TCP port, protocol, service, status, confidence, evidence, and a defensive recommendation. For example, an open `445/tcp` result is identified as `smb`.

## Findings

VulScan reports include a standard top-level `findings` section. Findings include sequential IDs, severity, category, affected host/port/URL, service, evidence, confidence, impact, recommendation, verification, limitation, source, risk score, risk label, fix priority, and creation time.

Open ports remain in `open_ports` for asset inventory. Open services also create informational service exposure findings.

## Risk Scoring

Risk scores are heuristic and range from 0 to 100. They combine severity, confidence, finding source, and exposure context such as sensitive ports or clear-text services.

Risk scores help with triage, but they are not a final statement of business risk. A human reviewer should validate context, asset criticality, exposure, compensating controls, and operational impact before prioritising remediation.

## Scan History

Use `--save-db` to store scan results in the local SQLite database at `data\vulscan.db`:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --save-db
```

View previous scans for a target:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main history --target 127.0.0.1
```

Limit the number of history rows shown:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main history --target 127.0.0.1 --limit 5
```

The history command shows the database path, target, number of scans shown, scan summaries, and latest-scan severity and risk-label counts. If the database does not exist or a target has no saved scans, VulScan prints a friendly message.

The database is local to your workstation and should not be committed to Git. It supports future scan diffing, remediation tracking, and trend reporting.

## HTTP Security Header Audit

HTTP auditing is optional and runs only when `--http-audit` is provided. It only targets detected web services on `80`, `443`, `8080`, and `8443`, and sends a normal HTTP GET request to `/`.

```powershell
python -m scanner.main scan --target example.com --http-audit
```

To include HTTP findings in both JSON and HTML reports:

```powershell
python -m scanner.main scan --target example.com --http-audit --json --html
```

The HTTP audit checks for common missing security headers, basic information disclosure headers, and basic cookie flags when `Set-Cookie` is present.

## TLS Certificate Audit

TLS auditing is optional and runs only when `--tls-audit` is provided. It only targets detected HTTPS services on `443` and `8443`, and performs a normal TLS handshake to inspect certificate information.

```powershell
python -m scanner.main scan --target example.com --tls-audit
```

To include TLS findings in both JSON and HTML reports:

```powershell
python -m scanner.main scan --target example.com --tls-audit --json --html
```

The TLS audit checks certificate validation status, hostname mismatch where possible, certificate expiry, certificates expiring within 30 days, subject, issuer, and validity dates. It does not test weak ciphers, perform downgrade testing, or run aggressive TLS probing.

## Windows Example

```powershell
python -m scanner.main scan --target 127.0.0.1
```

To save a JSON report in the `reports` folder:

```powershell
python -m scanner.main scan --target 127.0.0.1 --json
```

To save an HTML report in the `reports` folder:

```powershell
python -m scanner.main scan --target 127.0.0.1 --html
```

To save both JSON and HTML reports:

```powershell
python -m scanner.main scan --target 127.0.0.1 --json --html
```

Equivalent explicit virtual environment commands:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --json --html
.\.venv311\Scripts\python.exe -m scanner.main scan --target example.com --http-audit --tls-audit --json --html
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main history --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main history --target 127.0.0.1 --limit 5
```

To run HTTP auditing and save reports:

```powershell
python -m scanner.main scan --target example.com --http-audit --json --html
```

To run TLS auditing and save reports:

```powershell
python -m scanner.main scan --target example.com --tls-audit --json --html
```

Example output includes a table with:

```text
Port  Protocol  Service  Status  Evidence  Recommendation
```

When `--json` is used, VulScan also prints the saved report path:

```text
JSON report saved: reports\127.0.0.1_2026-05-12_231500.json
```

When `--html` is used, VulScan also prints the saved report path:

```text
HTML report saved: reports\127.0.0.1_2026-05-13_231500.html
```

## Installing Dependencies

After activating `.venv311`, install the project requirements from PowerShell:

```powershell
python -m pip install -r requirements.txt
```

## Running Tests Later

When tests are added, run them from the project root with:

```powershell
python -m pytest
```

## Safety Boundaries

Do not use VulScan against systems you do not own or do not have explicit permission to test. VulScan does not perform SYN scanning, UDP scanning, stealth scanning, crawling, fuzzing, brute forcing, credential attacks, exploitation, payload attacks, firewall bypassing, cipher probing, protocol downgrade testing, or destructive actions.
