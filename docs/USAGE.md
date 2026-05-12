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

The Version 4 scanner performs TCP connect checks against a fixed default list of common ports and identifies likely services from a safe static port mapping:

```text
21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443
```

Only open ports are shown by default. Each open result includes the host, resolved IP address, TCP port, protocol, service, status, confidence, evidence, and a defensive recommendation. For example, an open `445/tcp` result is identified as `smb`.

## Windows Example

```powershell
python -m scanner.main scan --target 127.0.0.1
```

To save a JSON report in the `reports` folder:

```powershell
python -m scanner.main scan --target 127.0.0.1 --json
```

Example output includes a table with:

```text
Port  Protocol  Service  Status  Evidence  Recommendation
```

When `--json` is used, VulScan also prints the saved report path:

```text
JSON report saved: reports\127.0.0.1_2026-05-12_231500.json
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

Do not use VulScan against systems you do not own or do not have explicit permission to test. VulScan does not perform SYN scanning, UDP scanning, stealth scanning, brute forcing, credential attacks, exploitation, payload attacks, firewall bypassing, or destructive actions.
